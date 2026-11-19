//! HTTPS termination belongs to the engine, so native adapters cannot hide
//! redirects, methods, credentials, or private-network requests inside CONNECT.
use base64::Engine as _;
use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use omd_domain::HostGrant;
use omd_network::Network;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};
use tokio_util::sync::CancellationToken;
use url::Url;

type Body = UnsyncBoxBody<Bytes, io::Error>;
#[derive(Debug, thiserror::Error)]
#[error("The native helper policy broker is unavailable")]
pub struct Error;
struct Context {
    network: Network,
    grants: Vec<HostGrant>,
    session: Option<omd_credentials::Session>,
    sign_in: bool,
    helper_origin: Option<String>,
    issuer: Issuer<'static, KeyPair>,
    leaf_key: KeyPair,
    authorization: String,
    cancel: CancellationToken,
    response_limit: u64,
    limit_reached: Arc<AtomicBool>,
    ca_der: rustls::pki_types::CertificateDer<'static>,
}
pub struct Broker {
    pub port: u16,
    upstream_port: Option<u16>,
    /// Chromium trusts this one ephemeral TLS key, never arbitrary certificates.
    pub spki: String,
    /// Only supplied to the confined helper, never installed as a system trust root.
    pub ca_pem: String,
    pub username: String,
    cancel: CancellationToken,
    limit_reached: Arc<AtomicBool>,
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Broker {
    pub async fn start(
        network: Network,
        grants: Vec<HostGrant>,
        session: Option<omd_credentials::Session>,
        sign_in: bool,
        response_limit: u64,
    ) -> Result<Self, Error> {
        Self::start_mode(network, grants, session, sign_in, None, response_limit).await
    }
    /// A media extractor may derive an authorization header from its cookie jar.
    /// Accept it only at the initial, credential-approved HTTPS origin. Cookies
    /// always come from the vault's original domain/path policy instead.
    pub async fn start_media(
        network: Network,
        grants: Vec<HostGrant>,
        session: Option<omd_credentials::Session>,
        source: &Url,
        response_limit: u64,
    ) -> Result<Self, Error> {
        let origin = session.as_ref().and_then(|_| {
            grants
                .iter()
                .any(|grant| grant.credential && omd_network::validate_url(source, grant).is_ok())
                .then(|| source.origin().ascii_serialization())
        });
        Self::start_mode(network, grants, session, false, origin, response_limit).await
    }
    async fn start_mode(
        network: Network,
        grants: Vec<HostGrant>,
        session: Option<omd_credentials::Session>,
        sign_in: bool,
        helper_origin: Option<String>,
        response_limit: u64,
    ) -> Result<Self, Error> {
        if response_limit == 0 || response_limit > 1024 * 1024 * 1024 * 1024 {
            return Err(Error);
        }
        let key = KeyPair::generate().map_err(|_| Error)?;
        let mut params =
            CertificateParams::new(vec!["omd-helper-broker.invalid".into()]).map_err(|_| Error)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "OMD ephemeral helper CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = params.self_signed(&key).map_err(|_| Error)?;
        let issuer = Issuer::new(params, key);
        let leaf_key = KeyPair::generate().map_err(|_| Error)?;
        let spki = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(leaf_key.subject_public_key_info()));
        // Key material is random for each invocation; its hash is an independent
        // local proxy capability and is never sent to a remote source.
        let username = omd_domain::digest(&leaf_key.serialize_der());
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:"))
        );
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| Error)?;
        let port = listener.local_addr().map_err(|_| Error)?.port();
        let cancel = CancellationToken::new();
        let limit_reached = Arc::new(AtomicBool::new(false));
        let context = Arc::new(Context {
            network,
            grants,
            session,
            sign_in,
            helper_origin,
            issuer,
            leaf_key,
            authorization,
            cancel: cancel.clone(),
            response_limit,
            limit_reached: limit_reached.clone(),
            ca_der: ca.der().clone(),
        });
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(16));
            loop {
                let permit = tokio::select! {_=task_cancel.cancelled()=>break,p=permits.clone().acquire_owned()=>match p{Ok(p)=>p,Err(_)=>break}};
                let socket = tokio::select! {_=task_cancel.cancelled()=>break,value=listener.accept()=>match value{Ok((socket,_))=>socket,Err(_)=>break}};
                let context = context.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    tokio::select! {_=context.cancel.cancelled()=>{},_=connection(socket,context.clone())=>{}}
                });
            }
        });
        Ok(Self {
            port,
            upstream_port: None,
            spki,
            ca_pem: ca.pem(),
            username,
            cancel,
            limit_reached,
        })
    }
    /// Native Windows helpers reach a peer inside their no-network-capability
    /// AppContainer. Its private pipe forwards to the original policy listener.
    #[allow(unused_mut)]
    pub fn native(mut self) -> Result<Self, Error> {
        #[cfg(windows)]
        {
            let reserve = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .map_err(|_| Error)?;
            self.upstream_port = Some(self.port);
            self.port = reserve.local_addr().map_err(|_| Error)?.port();
            // Losing this reservation can only prevent launch, never grant access
            // to the process that wins it: cross-container loopback stays denied.
        }
        Ok(self)
    }
    pub fn isolation_upstream(&self) -> Option<u16> {
        self.upstream_port
    }
    pub fn proxy_url(&self) -> String {
        format!("http://{}:@127.0.0.1:{}", self.username, self.port)
    }
    /// True once a response was cut because delivering more would exceed the
    /// response limit. The helper saw a failed transfer, so a caller can report
    /// a budget refusal instead of a generic tool failure.
    pub fn response_limit_reached(&self) -> bool {
        self.limit_reached.load(Ordering::Acquire)
    }
}
async fn connection(mut socket: TcpStream, context: Arc<Context>) -> Result<(), Error> {
    let authority = tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            if bytes.len() >= 16384 {
                return Err(Error);
            }
            bytes.push(socket.read_u8().await.map_err(|_| Error)?);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Error)?;
        let authority = match connect_authority(text, &context) {
            Ok(authority) => authority,
            Err(ConnectError::Authentication) => {
                // Chromium waits for a proxy challenge before sending its
                // credentials. A closed socket looks like an upstream failure.
                socket.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"OMD\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.map_err(|_| Error)?;
                return Err(Error);
            }
            Err(ConnectError::Denied) => return Err(Error),
        };
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|_| Error)?;
        Ok::<_, Error>(authority)
    })
    .await
    .map_err(|_| Error)??;
    let mut params = CertificateParams::new(vec![authority.clone()]).map_err(|_| Error)?;
    params.use_authority_key_identifier_extension = true;
    let certificate = params
        .signed_by(&context.leaf_key, &context.issuer)
        .map_err(|_| Error)?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error)?
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone(), context.ca_der.clone()],
        PrivatePkcs8KeyDer::from(context.leaf_key.serialize_der()).into(),
    )
    .map_err(|_| Error)?;
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TlsAcceptor::from(Arc::new(config)).accept(socket),
    )
    .await
    .map_err(|_| Error)?
    .map_err(|_| Error)?;
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .max_headers(128)
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15));
    builder
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| {
                let context = context.clone();
                let authority = authority.clone();
                async move {
                    Ok::<_, Infallible>(
                        forward(request, &authority, context)
                            .await
                            .unwrap_or_else(|_| denied()),
                    )
                }
            }),
        )
        .await
        .map_err(|_| Error)
}
enum ConnectError {
    Authentication,
    Denied,
}
fn connect_authority(text: &str, context: &Context) -> Result<String, ConnectError> {
    let mut lines = text.split("\r\n");
    let words: Vec<_> = lines
        .next()
        .ok_or(ConnectError::Denied)?
        .split(' ')
        .collect();
    if words.len() != 3 || words[0] != "CONNECT" || words[2] != "HTTP/1.1" {
        return Err(ConnectError::Denied);
    }
    let url = Url::parse(&format!("https://{}/", words[1])).map_err(|_| ConnectError::Denied)?;
    if url.path() != "/"
        || url.query().is_some()
        || !context
            .grants
            .iter()
            .any(|grant| omd_network::validate_url(&url, grant).is_ok())
    {
        return Err(ConnectError::Denied);
    }
    let mut authenticated = false;
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(ConnectError::Denied)?;
        if name.eq_ignore_ascii_case("proxy-authorization") {
            if authenticated || value.trim() != context.authorization {
                return Err(ConnectError::Authentication);
            }
            authenticated = true;
        }
    }
    if !authenticated {
        return Err(ConnectError::Authentication);
    }
    Ok(url.host_str().ok_or(ConnectError::Denied)?.to_owned())
}
async fn forward(
    request: Request<Incoming>,
    authority: &str,
    context: Arc<Context>,
) -> Result<Response<Body>, Error> {
    if request.method() == hyper::Method::CONNECT
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
    {
        return Err(Error);
    }
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or(Error)?;
    if host != authority && host != format!("{authority}:443") {
        return Err(Error);
    }
    let url = Url::parse(&format!("https://{authority}{}", request.uri())).map_err(|_| Error)?;
    let grant = context
        .grants
        .iter()
        .find(|g| {
            g.methods.iter().any(|m| m == request.method().as_str())
                && omd_network::validate_url(&url, g).is_ok()
        })
        .ok_or(Error)?;
    let mut headers = BTreeMap::new();
    let helper_auth =
        context.helper_origin.as_deref() == Some(url.origin().ascii_serialization().as_str());
    for (name, value) in request.headers() {
        // Some browser stacks reuse proxy credentials for an origin's HTTP
        // authentication challenge. Never forward the local broker capability.
        if name == hyper::header::PROXY_AUTHORIZATION
            || (name == hyper::header::AUTHORIZATION
                && value.as_bytes() == context.authorization.as_bytes())
        {
            return Err(Error);
        }
        if !context.sign_in && matches!(name.as_str(), "cookie" | "x-api-key" | "x-auth-token") {
            continue;
        }
        headers.insert(
            name.to_string(),
            value.to_str().map_err(|_| Error)?.to_owned(),
        );
    }
    let method = request.method().to_string();
    let bytes = tokio::time::timeout(
        Duration::from_secs(30),
        Limited::new(request.into_body(), 1024 * 1024).collect(),
    )
    .await
    .map_err(|_| Error)?
    .map_err(|_| Error)?
    .to_bytes();
    let body = String::from_utf8(bytes.to_vec()).map_err(|_| Error)?;
    let upstream = context
        .network
        .open_native(
            &omd_network::Request {
                url: url.into(),
                permission: grant.id.clone(),
                method,
                headers,
                body,
            },
            std::slice::from_ref(grant),
            context.session.as_ref(),
            &context.cancel,
            context.sign_in || helper_auth,
        )
        .await
        .map_err(|_| Error)?;
    // The limit bounds the bytes delivered to the helper, not the length a
    // source declares. Media extractors identify large direct media from its
    // headers or a short prefix and then close the response, so refusing on
    // Content-Length would reject them without saving any transfer. A body
    // that would exceed the limit is cut below; the forwarded length (or the
    // missing final chunk) makes that a failed transfer, never a short success.
    let mut response = Response::builder().status(upstream.status());
    for (name, value) in upstream.headers() {
        if matches!(
            name.as_str(),
            "connection"
                | "proxy-authenticate"
                | "transfer-encoding"
                | "upgrade"
                | "te"
                | "trailer"
                | "keep-alive"
        ) {
            continue;
        }
        if name.as_str() == "set-cookie" && !grant.credential {
            continue;
        }
        response = response.header(name, value);
    }
    let stream = stream::try_unfold(
        (upstream, 0u64, context),
        |(mut upstream, total, context)| async move {
            let chunk = tokio::select! {_=context.cancel.cancelled()=>return Err(io::Error::other("helper canceled")),chunk=upstream.chunk()=>chunk.map_err(|_|io::Error::other("source transfer failed"))?};
            match chunk {
                None => Ok(None),
                Some(bytes) => {
                    let total = total.saturating_add(bytes.len() as u64);
                    if total > context.response_limit {
                        context.limit_reached.store(true, Ordering::Release);
                        return Err(io::Error::other("response limit"));
                    }
                    context
                        .network
                        .bandwidth
                        .consume(bytes.len(), &context.cancel)
                        .await
                        .map_err(|_| io::Error::other("transfer canceled"))?;
                    Ok(Some((Frame::data(bytes), (upstream, total, context))))
                }
            }
        },
    );
    response
        .body(StreamBody::new(stream).boxed_unsync())
        .map_err(|_| Error)
}
fn denied() -> Response<Body> {
    Response::builder()
        .status(502)
        .body(
            Full::new(Bytes::from_static(
                b"OMD denied or could not complete this source request",
            ))
            .map_err(|e: Infallible| match e {})
            .boxed_unsync(),
        )
        .expect("constant response")
}
