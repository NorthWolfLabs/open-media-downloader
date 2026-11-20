//! This client deliberately has no dependency on any engine crate or database.
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Attach to an OMD v2 acquisition service")]
struct Args {
    /// Source account profile used for discovery, preparation and subscriptions.
    #[arg(long, global = true)]
    account: Option<String>,
    #[arg(long)]
    instance: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Tools {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    ToolStatus,
    InstallTools {
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long, default_value = "Media tools")]
        label: String,
        #[arg(long)]
        approve: Option<String>,
    },
    Tool {
        id: String,
        #[arg(long,value_parser=["activate","remove","retry-cleanup"])]
        action: Option<String>,
        #[arg(long)]
        approve: Option<String>,
    },
    Notifications {
        #[arg(long,action=clap::ArgAction::Set)]
        enabled: Option<bool>,
    },
    TestNotification,
    NotificationHistory {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Notification {
        id: String,
        #[arg(value_parser=["retry","dismiss"])]
        action: String,
    },
    /// Review removal, then repeat with the returned digest to approve it.
    RemoveSource {
        provider: String,
        #[arg(long)]
        approve: Option<String>,
    },
    SourceRemovals {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    SourceRemoval {
        id: String,
        #[arg(long)]
        retry: bool,
    },
    SourceRemovalEntries {
        id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    /// Check all currently recorded acquisitions on a destination without changing files.
    CheckDestination {
        destination: String,
    },
    DestinationChecks {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    DestinationCheck {
        id: String,
        #[arg(long,value_parser=["pause","resume","retry","cancel"])]
        action: Option<String>,
    },
    DestinationCheckFiles {
        id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Status,
    /// Read metadata overrides, or replace them with a JSON document from stdin.
    Metadata {
        #[arg(value_parser=["collection","release"])]
        kind: String,
        provider: String,
        id: String,
        #[arg(long)]
        write: bool,
    },
    /// Read output naming templates, or replace them with JSON from stdin.
    Naming {
        #[arg(long)]
        write: bool,
    },
    Credentials {
        provider: String,
    },
    /// Sign in to a source in a native window that the engine opens on its
    /// desktop session. The account is saved when sign-in completes.
    SignIn {
        provider: String,
        profile: String,
        #[arg(long, default_value = "Account")]
        label: String,
    },
    /// Read a session JSON document from stdin; secret values never go in arguments.
    SetCredentials {
        provider: String,
        profile: String,
        label: String,
    },
    RevokeCredentials {
        provider: String,
        profile: String,
    },
    /// Create an inspect/removal operation. Destructive modes require a separate start after preview.
    ManageFiles {
        job: String,
        #[arg(value_parser=["reconcile","remove_files","forget_history","remove_files_and_history"])]
        mode: String,
    },
    FileOperations {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    FileOperation {
        id: String,
        #[arg(long,value_parser=["start","retry","cancel"])]
        action: Option<String>,
    },
    FileOperationEntries {
        id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Relocate {
        destination: String,
        target: PathBuf,
    },
    Relocations {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Relocation {
        id: String,
        #[arg(long,value_parser=["start","retry","cancel"])]
        action: Option<String>,
    },
    RelocationFiles {
        id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    ReconnectDestination {
        id: String,
        path: PathBuf,
    },
    Sources {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Subscriptions {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Inbox {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Follow {
        provider: String,
        id: String,
        destination: String,
        #[arg(long)]
        automatic: bool,
        #[arg(long)]
        include_existing: bool,
        #[arg(long, default_value = "60")]
        interval_minutes: u32,
    },
    /// Start a durable full-collection scan. Inspect its returned selection ID.
    Snapshot {
        provider: String,
        id: String,
    },
    Selections {
        #[arg(long)]
        cursor: Option<String>,
    },
    Selection {
        id: String,
        #[arg(long, value_parser=["retry","cancel"])]
        action: Option<String>,
    },
    SnapshotReleases {
        id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    PrepareSnapshot {
        id: String,
        destination: String,
        #[arg(long, default_value = "en")]
        language: String,
        #[arg(long, default_value = "cbz")]
        recipe: String,
    },
    Preview {
        id: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    DownloadMissing {
        provider: String,
        id: String,
        destination: String,
        #[arg(long, default_value = "en")]
        language: String,
        #[arg(long, default_value = "cbz")]
        recipe: String,
    },
    Install {
        package: PathBuf,
        #[arg(long)]
        approve: Option<String>,
    },
    Search {
        provider: String,
        query: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    Collection {
        provider: String,
        id: String,
    },
    Releases {
        provider: String,
        id: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    Destinations {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    AddDestination {
        label: String,
        path: PathBuf,
    },
    Prepare {
        #[arg(long)]
        new_version: bool,
        provider: String,
        id: String,
        destination: String,
        #[arg(long, default_value = "cbz")]
        recipe: String,
    },
    Download {
        preparation: String,
        #[arg(long)]
        key: Option<String>,
    },
    Groups {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    #[command(name = "group-action")]
    ControlGroup {
        id: String,
        #[arg(value_parser=["pause","cancel","resume","retry"])]
        action: String,
    },
    GroupJobs {
        id: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "")]
        query: String,
    },
    Jobs {
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    Files {
        job: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    Pause {
        job: String,
    },
    Resume {
        job: String,
    },
    Cancel {
        job: String,
    },
    Retry {
        job: String,
    },
}
fn segment(value: &str) -> String {
    let mut url = reqwest::Url::parse("http://localhost/").expect("static URL");
    url.path_segments_mut()
        .expect("HTTP path")
        .clear()
        .push(value);
    url.path().trim_start_matches('/').to_owned()
}
fn list_path(path: &str, query: &str, cursor: Option<&str>) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("q", query);
    if let Some(cursor) = cursor {
        params.append_pair("cursor", cursor);
    }
    format!("{path}?{}", params.finish())
}
#[derive(Deserialize)]
struct Instance {
    endpoint: String,
    token: String,
    admin_token: String,
}
struct Client {
    account: Option<String>,
    http: reqwest::Client,
    instance: Instance,
}
impl Client {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        mut body: Option<Value>,
        admin: bool,
        key: Option<String>,
    ) -> anyhow::Result<Value> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.instance.endpoint))
            .bearer_auth(if admin {
                &self.instance.admin_token
            } else {
                &self.instance.token
            });
        if let Some(account) = &self.account
            && (path == "/v2/preparations"
                || path.ends_with("/invoke")
                || path == "/v2/subscriptions"
                || path == "/v2/snapshots")
            && let Some(Value::Object(body)) = &mut body
        {
            body.insert("credential_profile".into(), json!(account));
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        let response = request.send().await?;
        let status = response.status();
        let value: Value = response.json().await?;
        anyhow::ensure!(
            status.is_success(),
            "{}: {}",
            value["code"].as_str().unwrap_or("request_failed"),
            value["message"]
                .as_str()
                .unwrap_or("The engine rejected this request.")
        );
        Ok(value)
    }
    async fn operation(
        &self,
        provider: &str,
        operation: &str,
        id: Option<String>,
        query: Option<String>,
        cursor: Option<String>,
    ) -> anyhow::Result<Value> {
        self.call(reqwest::Method::POST,&format!("/v2/sources/{provider}/invoke"),Some(json!({"operation":operation,"reference":id.map(|id|json!({"provider":provider,"id":id})),"query":query,"url":null,"cursor":cursor,"page_size":100,"policy":{}})),false,None).await
    }
}
async fn json_stdin() -> anyhow::Result<Value> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    tokio::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await?;
    anyhow::ensure!(
        bytes.len() <= 1024 * 1024,
        "The JSON document exceeds 1 MiB"
    );
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Supply a valid JSON document on stdin"))
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let instance: Instance = serde_json::from_slice(&tokio::fs::read(&args.instance).await?)?;
    let endpoint = reqwest::Url::parse(&instance.endpoint)?;
    anyhow::ensure!(
        endpoint.scheme() == "http" && endpoint.host_str() == Some("127.0.0.1"),
        "The instance endpoint must be local loopback."
    );
    let client = Client {
        account: args.account,
        http: reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(300))
            .build()?,
        instance,
    };
    use reqwest::Method as M;
    // A command can submit downloads and leave; ask the engine to finish them
    // before it stops. Earlier engines ignore the option.
    let lease = client
        .call(
            M::POST,
            "/v2/clients?finish_downloads=true",
            None,
            false,
            None,
        )
        .await?;
    let id = lease["id"].as_str().unwrap().to_owned();
    // Independent heartbeats keep long preparations attached without engine internals.
    let beat_http = client.http.clone();
    let beat_endpoint = client.instance.endpoint.clone();
    let beat_token = client.instance.token.clone();
    let beat_id = id.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let _ = beat_http
                .post(format!("{beat_endpoint}/v2/clients/{beat_id}"))
                .bearer_auth(&beat_token)
                .send()
                .await;
        }
    });
    let result=match args.command{
        Action::Tools{cursor,query}=>client.call(M::GET,&format!("/v2/tools?q={}&cursor={}",segment(&query),segment(cursor.as_deref().unwrap_or(""))),None,false,None).await,
        Action::ToolStatus=>client.call(M::GET,"/v2/tools/status",None,false,None).await,
        Action::InstallTools{manifest,label,approve}=>client.call(M::POST,"/v2/tools/install",Some(json!({"manifest_path":manifest,"label":label,"approve_digest":approve})),true,None).await,
        Action::Tool{id,action,approve}=>match action {
            Some(action)=>client.call(M::POST,&format!("/v2/tools/{}/{}",segment(&id),action),if action=="remove"{Some(json!({"approve_digest":approve}))}else{None},true,None).await,
            None=>client.call(M::GET,&format!("/v2/tools/{}",segment(&id)),None,false,None).await,
        },
 Action::Notifications{enabled}=>client.call(if enabled.is_some(){M::PUT}else{M::GET},"/v2/notifications",enabled.map(|enabled|json!({"enabled":enabled})),false,None).await,
 Action::TestNotification=>client.call(M::POST,"/v2/notifications/test",None,false,None).await,
 Action::NotificationHistory{cursor,query}=>client.call(M::GET,&list_path("/v2/notifications/history",&query,cursor.as_deref()),None,false,None).await,
 Action::Notification{id,action}=>client.call(M::POST,&format!("/v2/notifications/history/{}/{action}",segment(&id)),None,false,None).await,
        Action::RemoveSource{provider,approve}=>client.call(M::POST,&format!("/v2/sources/{}/remove",segment(&provider)),Some(json!({"approve_digest":approve})),true,None).await,
        Action::SourceRemovals{cursor,query}=>client.call(M::GET,&list_path("/v2/source-removals",&query,cursor.as_deref()),None,false,None).await,
        Action::SourceRemoval{id,retry}=>client.call(if retry{M::POST}else{M::GET},&format!("/v2/source-removals/{}{}",segment(&id),if retry{"/retry"}else{""}),None,retry,None).await,
        Action::SourceRemovalEntries{id,cursor,query}=>client.call(M::GET,&list_path(&format!("/v2/source-removals/{}/entries",segment(&id)),&query,cursor.as_deref()),None,false,None).await,
        Action::Credentials{provider}=>client.call(M::GET,&format!("/v2/sources/{provider}/credentials"),None,false,None).await,
        Action::Metadata{kind,provider,id,write}=>{
            if write{client.call(M::PUT,&format!("/v2/metadata/{kind}"),Some(json!({"reference":{"provider":provider,"id":id},"overrides":json_stdin().await?})),false,None).await}
            else{let query={let mut url=reqwest::Url::parse("http://localhost/")?;url.query_pairs_mut().append_pair("source_id",&id);url.query().unwrap_or("").to_owned()};client.call(M::GET,&format!("/v2/metadata/{kind}/{provider}?{query}"),None,false,None).await}
        },
        Action::Naming{write}=>client.call(if write{M::PUT}else{M::GET},"/v2/naming",if write{Some(json_stdin().await?)}else{None},false,None).await,
        Action::SetCredentials{provider,profile,label}=>{
            use tokio::io::AsyncReadExt;
            let mut bytes=Vec::new();tokio::io::stdin().take(1024*1024+1).read_to_end(&mut bytes).await?;
            anyhow::ensure!(bytes.len()<=1024*1024,"The session exceeds the credential size limit");
            let session:Value=serde_json::from_slice(&bytes).map_err(|_|anyhow::anyhow!("Supply a valid session JSON document on stdin"))?;
            client.call(M::PUT,&format!("/v2/sources/{provider}/credentials/{profile}"),Some(json!({"label":label,"session":session})),false,None).await
        },
        Action::SignIn{provider,profile,label}=>sign_in(&client,&id,&provider,&profile,&label).await,
        Action::RevokeCredentials{provider,profile}=>client.call(M::DELETE,&format!("/v2/sources/{provider}/credentials/{profile}"),None,false,None).await,
        Action::ManageFiles{job,mode}=>client.call(M::POST,&format!("/v2/jobs/{job}/file-operations"),Some(json!({"mode":mode})),false,None).await,
        Action::FileOperations{cursor,query}=>client.call(M::GET,&list_path("/v2/file-operations",&query,cursor.as_deref()),None,false,None).await,
        Action::FileOperation{id,action}=>client.call(if action.is_some(){M::POST}else{M::GET},&format!("/v2/file-operations/{id}{}",action.map(|a|format!("/{a}")).unwrap_or_default()),None,false,None).await,
        Action::FileOperationEntries{id,cursor,query}=>client.call(M::GET,&list_path(&format!("/v2/file-operations/{id}/files"),&query,cursor.as_deref()),None,false,None).await,
        Action::CheckDestination{destination}=>client.call(M::POST,&format!("/v2/destinations/{destination}/check"),None,false,None).await,
        Action::DestinationChecks{cursor,query}=>client.call(M::GET,&list_path("/v2/destination-checks",&query,cursor.as_deref()),None,false,None).await,
        Action::DestinationCheck{id,action}=>client.call(if action.is_some(){M::POST}else{M::GET},&format!("/v2/destination-checks/{id}{}",action.map(|a|format!("/{a}")).unwrap_or_default()),None,false,None).await,
        Action::DestinationCheckFiles{id,cursor,query}=>client.call(M::GET,&list_path(&format!("/v2/destination-checks/{id}/files"),&query,cursor.as_deref()),None,false,None).await,
        Action::Relocate{destination,target}=>client.call(M::POST,&format!("/v2/destinations/{destination}/relocate"),Some(json!({"target_root":target})),false,None).await,
        Action::Relocations{cursor,query}=>client.call(M::GET,&list_path("/v2/relocations",&query,cursor.as_deref()),None,false,None).await,
        Action::Relocation{id,action}=>client.call(if action.is_some(){M::POST}else{M::GET},&format!("/v2/relocations/{id}{}",action.map(|a|format!("/{a}")).unwrap_or_default()),None,false,None).await,
        Action::RelocationFiles{id,cursor,query}=>client.call(M::GET,&list_path(&format!("/v2/relocations/{id}/files"),&query,cursor.as_deref()),None,false,None).await,
        Action::ReconnectDestination{id,path}=>client.call(M::POST,&format!("/v2/destinations/{id}/reconnect"),Some(json!({"root":path})),false,None).await,
        Action::Status=>client.call(M::GET,"/v2/service",None,false,None).await,
        Action::Sources{cursor,query}=>client.call(M::GET,&list_path("/v2/sources",&query,cursor.as_deref()),None,false,None).await,
        Action::Subscriptions{cursor,query}=>client.call(M::GET,&list_path("/v2/subscriptions",&query,cursor.as_deref()),None,false,None).await,
        Action::Inbox{cursor,query}=>client.call(M::GET,&list_path("/v2/inbox",&query,cursor.as_deref()),None,false,None).await,
        Action::Follow{provider,id,destination,automatic,include_existing,interval_minutes}=>client.call(M::POST,"/v2/subscriptions",Some(json!({"target":{"provider":provider,"id":id},"destination_id":destination,"policy":{},"action":if automatic{"download"}else{"notify"},"recipe":"cbz","include_existing":include_existing,"interval_minutes":interval_minutes,"credential_profile":null})),false,None).await,
        Action::Snapshot{provider,id}=>client.call(M::POST,"/v2/snapshots",Some(json!({"reference":{"provider":provider,"id":id}})),false,None).await,
        Action::Selections{cursor}=>client.call(M::GET,&list_path("/v2/selections","",cursor.as_deref()),None,false,None).await,
        Action::Selection{id,action}=>client.call(if action.is_some(){M::POST}else{M::GET},&format!("/v2/selections/{id}{}",action.map(|a|format!("/{a}")).unwrap_or_default()),None,false,None).await,
        Action::SnapshotReleases{id,cursor,query}=>client.call(M::GET,&list_path(&format!("/v2/snapshots/{id}/releases"),&query,cursor.as_deref()),None,false,None).await,
        Action::PrepareSnapshot{id,destination,language,recipe}=>client.call(M::POST,"/v2/batches",Some(json!({"snapshot_id":id,"destination_id":destination,"recipe":recipe,"policy":{"languages":if language.is_empty(){vec![]}else{vec![language]}}})),false,None).await,
        Action::Preview{id,cursor}=>client.call(M::GET,&list_path(&format!("/v2/batches/{id}/items"),"",cursor.as_deref()),None,false,None).await,
        Action::DownloadMissing{provider,id,destination,language,recipe}=>download_missing(&client,&provider,&id,&destination,&language,&recipe).await,
        Action::Install{package,approve}=>client.call(M::POST,"/v2/sources/install",Some(json!({"package_path":std::fs::canonicalize(package)?,"approve_digest":approve})),true,None).await,
        Action::Search{provider,query,cursor}=>client.operation(&provider,"search",None,Some(query),cursor).await,
        Action::Collection{provider,id}=>client.operation(&provider,"collection",Some(id),None,None).await,
        Action::Releases{provider,id,cursor}=>client.operation(&provider,"releases",Some(id),None,cursor).await,
        Action::Destinations{cursor,query}=>client.call(M::GET,&list_path("/v2/destinations",&query,cursor.as_deref()),None,false,None).await,
        Action::AddDestination{label,path}=>client.call(M::POST,"/v2/destinations",Some(json!({"label":label,"root":path})),false,None).await,
        Action::Prepare{provider,id,destination,recipe,new_version}=>client.call(M::POST,"/v2/preparations",Some(json!({"releases":[{"provider":provider,"id":id}],"destination_id":destination,"recipe":recipe,"policy":{},"duplicate_behavior":if new_version{"new_version"}else{"skip_satisfied"}})),false,None).await,
        Action::Download{preparation,key}=>client.call(M::POST,"/v2/jobs",Some(json!({"preparation_id":preparation})),false,Some(key.unwrap_or_else(||uuid::Uuid::new_v4().to_string()))).await,
        Action::ControlGroup{id,action}=>client.call(M::POST,&format!("/v2/groups/{}/{action}",segment(&id)),None,false,None).await,
        Action::Groups{cursor,query}=>client.call(M::GET,&list_path("/v2/groups",&query,cursor.as_deref()),None,false,None).await,
        Action::GroupJobs{id,cursor,query}=>client.call(M::GET,&list_path(&format!("/v2/groups/{id}/jobs"),&query,cursor.as_deref()),None,false,None).await,
        Action::Jobs{query,cursor}=>{let mut url=reqwest::Url::parse("http://localhost/v2/jobs")?;url.query_pairs_mut().append_pair("q",&query);if let Some(cursor)=cursor{url.query_pairs_mut().append_pair("cursor",&cursor);}client.call(M::GET,&format!("{}?{}",url.path(),url.query().unwrap_or("")),None,false,None).await},
        Action::Files{job,cursor}=>client.call(M::GET,&list_path(&format!("/v2/jobs/{job}/files"),"",cursor.as_deref()),None,false,None).await,
        Action::Pause{job}=>client.call(M::POST,&format!("/v2/jobs/{job}/pause"),None,false,None).await,
        Action::Resume{job}=>client.call(M::POST,&format!("/v2/jobs/{job}/resume"),None,false,None).await,
        Action::Cancel{job}=>client.call(M::POST,&format!("/v2/jobs/{job}/cancel"),None,false,None).await,
        Action::Retry{job}=>client.call(M::POST,&format!("/v2/jobs/{job}/retry"),None,false,None).await,
    };
    heartbeat.abort();
    let _ = client
        .call(M::DELETE, &format!("/v2/clients/{id}"), None, false, None)
        .await;
    println!("{}", serde_json::to_string_pretty(&result?)?);
    Ok(())
}

async fn sign_in(
    client: &Client,
    lease: &str,
    provider: &str,
    profile: &str,
    label: &str,
) -> anyhow::Result<Value> {
    use reqwest::Method as M;
    let session = client
        .call(
            M::POST,
            &format!("/v2/sources/{}/sign-ins", segment(provider)),
            Some(json!({"client":lease,"profile":profile,"label":label,"window":"native"})),
            false,
            None,
        )
        .await?;
    let id = segment(
        session["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("The engine did not return a sign-in session."))?,
    );
    let owner = json!({ "client": lease });
    eprintln!(
        "Finish signing in in the window that opened. OMD saves the account when sign-in completes. Close the window or press Ctrl-C to cancel."
    );
    let finished = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let status = client
                .call(
                    M::POST,
                    &format!("/v2/sign-ins/{id}/status"),
                    Some(owner.clone()),
                    false,
                    None,
                )
                .await?;
            if status["ready"] == true {
                return client
                    .call(
                        M::POST,
                        &format!("/v2/sign-ins/{id}/complete"),
                        Some(owner.clone()),
                        false,
                        None,
                    )
                    .await;
            }
        }
    };
    tokio::select! {
        result = finished => result,
        _ = tokio::signal::ctrl_c() => {
            let _ = client
                .call(M::POST, &format!("/v2/sign-ins/{id}/close"), Some(owner.clone()), false, None)
                .await;
            anyhow::bail!("Sign-in canceled.")
        }
    }
}
async fn download_missing(
    client: &Client,
    provider: &str,
    id: &str,
    destination: &str,
    language: &str,
    recipe: &str,
) -> anyhow::Result<Value> {
    let snapshot = client
        .call(
            reqwest::Method::POST,
            "/v2/snapshots",
            Some(json!({"reference":{"provider":provider,"id":id}})),
            false,
            None,
        )
        .await?;
    let snapshot = wait_selection(client, snapshot).await?;
    let batch=client.call(reqwest::Method::POST,"/v2/batches",Some(json!({"snapshot_id":snapshot["id"],"destination_id":destination,"recipe":recipe,"policy":{"languages":if language.is_empty(){vec![]}else{vec![language]}}})),false,None).await?;
    let batch = wait_selection(client, batch).await?;
    client
        .call(
            reqwest::Method::POST,
            "/v2/jobs",
            Some(json!({"preparation_id":batch["id"]})),
            false,
            Some(format!("cli:{}", batch["id"].as_str().unwrap())),
        )
        .await
}
async fn wait_selection(client: &Client, mut task: Value) -> anyhow::Result<Value> {
    let id = task["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing task identity"))?
        .to_owned();
    eprintln!("Durable preparation: {id}. Use selection {id} to inspect it after reconnecting.");
    loop {
        match task["state"].as_str() {
            Some("ready") => return Ok(task),
            Some("working") => {}
            _ => anyhow::bail!(
                "Preparation {id}: {}. {}",
                task["state"].as_str().unwrap_or("invalid state"),
                task["issue"]["message"]
                    .as_str()
                    .unwrap_or("Inspect this selection before retrying.")
            ),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        task = client
            .call(
                reqwest::Method::GET,
                &format!("/v2/selections/{id}"),
                None,
                false,
                None,
            )
            .await?;
    }
}
