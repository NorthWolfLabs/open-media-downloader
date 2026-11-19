use omd_domain::HostGrant;
use omd_helper_broker::Broker;
use omd_network::Network;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn grants(host: &str) -> Vec<HostGrant> {
    vec![HostGrant {
        request_intervals: Default::default(),
        id: "source".into(),
        hosts: vec![host.into()],
        methods: vec!["GET".into()],
        credential: false,
    }]
}
#[tokio::test]
async fn proxy_requires_capability_and_enforces_private_dns_and_methods_inside_tls() {
    let broker = Broker::start(Network::new(0), grants("localhost"), None, false, 8192)
        .await
        .unwrap();
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", broker.port))
        .await
        .unwrap();
    socket
        .write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required\r\n"));
    assert!(!String::from_utf8_lossy(&response).contains(&broker.username));
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(broker.proxy_url()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(broker.ca_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    for method in [reqwest::Method::GET, reqwest::Method::POST] {
        let response = client
            .request(method, "https://localhost/")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 502);
        assert!(!response.text().await.unwrap().contains(&broker.username));
    }
    assert!(
        client
            .get("https://undeclared.example/")
            .send()
            .await
            .is_err()
    );
}
#[tokio::test]
#[ignore = "bounded live external HTTPS smoke"]
async fn live_https_is_verified_and_retrieved_only_by_engine() {
    let broker = Broker::start(
        Network::new(0),
        grants("example.com"),
        None,
        false,
        1024 * 1024,
    )
    .await
    .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(broker.proxy_url()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(broker.ca_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let response = client.get("https://example.com/").send().await.unwrap();
    assert!(response.status().is_success());
    assert!(response.text().await.unwrap().contains("Example Domain"));
}

#[tokio::test]
async fn media_derived_authorization_is_origin_bound_and_proxy_capability_never_leaks() {
    use base64::Engine as _;
    use std::sync::{Arc, Mutex};
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    let network = Network::new(0).with_native_fixture(move |url, _, headers, _| {
        seen.lock()
            .unwrap()
            .push((url.to_string(), headers.clone()));
        Ok(http::Response::builder().body(Vec::new()).unwrap())
    });
    let mut grants = grants("source.example");
    grants[0].hosts.push("other.example".into());
    grants[0].credential = true;
    let session = omd_credentials::Session {
        expires_at: None,
        origins: vec![],
        headers: vec![],
        cookies: vec![omd_credentials::Cookie {
            name: "session".into(),
            value: "VAULT_SECRET".into(),
            domain: "source.example".into(),
            path: "/account".into(),
            host_only: true,
            expires_at: None,
            secure: true,
            http_only: true,
            same_site: None,
        }],
    };
    let broker = Broker::start_media(
        network,
        grants,
        Some(session),
        &url::Url::parse("https://source.example/account").unwrap(),
        8192,
    )
    .await
    .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(broker.proxy_url()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(broker.ca_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    for path in [
        "https://source.example/account/items",
        "https://source.example/public",
        "https://other.example/account",
    ] {
        assert_eq!(
            client
                .get(path)
                .header("authorization", "SAPISIDHASH DERIVED")
                .header("cookie", "session=HELPER_WRONG_SCOPE")
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let local = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:", broker.username))
    );
    for header in ["authorization", "proxy-authorization"] {
        assert_eq!(
            client
                .get("https://source.example/account")
                .header(header, &local)
                .send()
                .await
                .unwrap()
                .status(),
            502
        );
    }
    let seen = calls.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].1["authorization"], "SAPISIDHASH DERIVED");
    assert_eq!(seen[0].1["cookie"], "session=VAULT_SECRET");
    assert_eq!(seen[1].1["authorization"], "SAPISIDHASH DERIVED");
    assert!(!seen[1].1.contains_key("cookie"));
    assert!(!seen[2].1.contains_key("authorization"));
    assert!(!seen[2].1.contains_key("cookie"));
}

/// Generates a large body on demand and counts what the broker pulls, so a
/// fixture can declare hundreds of MiB without allocating or sending them.
struct LazyBody {
    remaining: u64,
    sent: u64,
    declared: bool,
    pulled: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
const CHUNK: u64 = 16 * 1024;
impl hyper::body::Body for LazyBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, Self::Error>>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let n = self.remaining.min(CHUNK);
        let mut chunk = vec![0u8; n as usize];
        if self.sent == 0 {
            chunk[..3].copy_from_slice(b"ID3");
        }
        self.remaining -= n;
        self.sent += n;
        self.pulled
            .fetch_add(n, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk.into()))))
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        // Like a real upstream, a declared Content-Length is the exact size.
        if self.declared {
            hyper::body::SizeHint::with_exact(self.remaining)
        } else {
            hyper::body::SizeHint::default()
        }
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}
fn media_response(
    length: u64,
    declared: bool,
    pulled: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> http::Response<reqwest::Body> {
    let mut builder = http::Response::builder().header("Content-Type", "audio/mpeg");
    if declared {
        builder = builder.header("Content-Length", length.to_string());
    }
    builder
        .body(reqwest::Body::wrap(LazyBody {
            remaining: length,
            sent: 0,
            declared,
            pulled,
        }))
        .unwrap()
}
fn helper_client(broker: &Broker) -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(broker.proxy_url()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(broker.ca_pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}
async fn read_to_end(response: &mut reqwest::Response) -> (u64, reqwest::Result<()>) {
    let mut received = 0;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => received += chunk.len() as u64,
            Ok(None) => return (received, Ok(())),
            Err(error) => return (received, Err(error)),
        }
    }
}

#[tokio::test]
async fn declared_large_media_is_identified_from_headers_and_a_prefix_within_the_budget() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };
    const LIMIT: u64 = 16 * 1024 * 1024;
    const DECLARED: u64 = 256 * 1024 * 1024;
    let pulled = Arc::new(AtomicU64::new(0));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (counter, seen) = (pulled.clone(), calls.clone());
    let network = Network::new(0).with_transfer_fixture(move |url, _, _| {
        seen.lock().unwrap().push(url.to_string());
        Ok(match url.host_str() {
            Some("traffic.fixture.test") => http::Response::builder()
                .status(302)
                .header(
                    "Location",
                    if url.path() == "/elsewhere.mp3" {
                        "https://ungranted.fixture.test/episode.mp3"
                    } else {
                        "https://cdn.fixture.test/episode.mp3"
                    },
                )
                .body(reqwest::Body::from(Vec::new()))
                .unwrap(),
            _ => media_response(DECLARED, true, counter.clone()),
        })
    });
    let mut grants = grants("traffic.fixture.test");
    grants[0].hosts.push("cdn.fixture.test".into());
    let source = url::Url::parse("https://traffic.fixture.test/episode.mp3").unwrap();
    let broker = Broker::start_media(network, grants, None, &source, LIMIT)
        .await
        .unwrap();
    let client = helper_client(&broker);
    let mut response = client.get(source.clone()).send().await.unwrap();
    // The redirect is followed through the broker to the granted media host.
    assert_eq!(response.status(), 200);
    assert_eq!(response.url().host_str(), Some("cdn.fixture.test"));
    assert_eq!(response.headers()["content-type"], "audio/mpeg");
    assert_eq!(response.content_length(), Some(DECLARED));
    // A generic extractor sniffs at most a short prefix, then closes.
    let mut prefix = Vec::new();
    while prefix.len() < 512 {
        prefix.extend_from_slice(&response.chunk().await.unwrap().unwrap());
    }
    assert!(prefix.starts_with(b"ID3"));
    drop(response);
    drop(client);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let total = pulled.load(Ordering::SeqCst);
    assert!(
        total < LIMIT,
        "the broker pulled {total} bytes for a response the helper closed"
    );
    assert!(!broker.response_limit_reached());
    // A redirect to a host outside the grant still fails at CONNECT.
    assert!(
        helper_client(&broker)
            .get("https://traffic.fixture.test/elsewhere.mp3")
            .send()
            .await
            .is_err()
    );
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|url| url.contains("ungranted"))
    );
}

#[tokio::test]
async fn reading_past_the_budget_is_cut_reported_and_never_ends_cleanly() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    const LIMIT: u64 = 1024 * 1024;
    for declared in [true, false] {
        let pulled = Arc::new(AtomicU64::new(0));
        let counter = pulled.clone();
        let network = Network::new(0).with_transfer_fixture(move |_, _, _| {
            Ok(media_response(64 * 1024 * 1024, declared, counter.clone()))
        });
        let source = url::Url::parse("https://cdn.fixture.test/episode.mp3").unwrap();
        let broker = Broker::start_media(network, grants("cdn.fixture.test"), None, &source, LIMIT)
            .await
            .unwrap();
        let mut response = helper_client(&broker).get(source).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let (received, outcome) = read_to_end(&mut response).await;
        assert!(
            outcome.is_err(),
            "a cut body must fail, not end as a short success (declared length: {declared})"
        );
        assert!(
            received <= LIMIT,
            "{received} bytes delivered past the limit"
        );
        assert!(pulled.load(Ordering::SeqCst) <= LIMIT + CHUNK);
        assert!(broker.response_limit_reached());
    }
}

#[tokio::test]
async fn bodies_up_to_the_budget_are_delivered_completely() {
    use std::sync::{Arc, atomic::AtomicU64};
    const LIMIT: u64 = 1024 * 1024;
    let network = Network::new(0).with_transfer_fixture(move |_, _, _| {
        Ok(media_response(LIMIT, true, Arc::new(AtomicU64::new(0))))
    });
    let source = url::Url::parse("https://cdn.fixture.test/episode.mp3").unwrap();
    let broker = Broker::start_media(network, grants("cdn.fixture.test"), None, &source, LIMIT)
        .await
        .unwrap();
    let mut response = helper_client(&broker).get(source).send().await.unwrap();
    let (received, outcome) = read_to_end(&mut response).await;
    assert!(outcome.is_ok());
    assert_eq!(received, LIMIT);
    assert!(!broker.response_limit_reached());
}

#[tokio::test]
async fn dropping_the_broker_stops_an_in_flight_large_transfer() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    let pulled = Arc::new(AtomicU64::new(0));
    let counter = pulled.clone();
    let network = Network::new(0).with_transfer_fixture(move |_, _, _| {
        Ok(media_response(
            4 * 1024 * 1024 * 1024,
            true,
            counter.clone(),
        ))
    });
    let source = url::Url::parse("https://cdn.fixture.test/episode.mp3").unwrap();
    let broker = Broker::start_media(
        network,
        grants("cdn.fixture.test"),
        None,
        &source,
        1024 * 1024 * 1024 * 1024,
    )
    .await
    .unwrap();
    let mut response = helper_client(&broker).get(source).send().await.unwrap();
    let mut received = 0;
    while received < 1024 * 1024 {
        received += response.chunk().await.unwrap().unwrap().len();
    }
    drop(broker);
    let (_, outcome) = tokio::time::timeout(Duration::from_secs(10), read_to_end(&mut response))
        .await
        .expect("canceling the broker ends the transfer promptly");
    assert!(outcome.is_err());
    let after = pulled.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(pulled.load(Ordering::SeqCst), after);
    assert!(after < 64 * 1024 * 1024);
}
