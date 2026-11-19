//! Test-only native extractor. Exercises the real process confinement, TLS
//! broker, redirects and credential transport without contacting a real account.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--check-work") {
        let path = args.get(2).ok_or("missing work path")?;
        let result = omd_files::Root::open(std::path::Path::new(path));
        println!(
            "{}",
            match result {
                Ok(_) => serde_json::json!({"root_open":true}),
                Err(error) =>
                    serde_json::json!({"root_open":false,"code":error.raw_os_error(),"kind":format!("{:?}",error.kind()),"message":error.to_string()}),
            }
        );
        return Ok(());
    }
    // Core passes only generic tool options. A site extraction strategy here
    // would be a core/plugin boundary failure, so the fixture refuses it.
    if args.iter().any(|a| a.starts_with("--extractor-args")) {
        eprintln!("ERROR: fixture refused an extractor-specific option");
        std::process::exit(2);
    }
    let option = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
    };
    let proxy = option("--proxy").ok_or("missing proxy")?;
    let url = args.last().ok_or("missing URL")?;
    // Like an authenticated extractor, read the explicit config from stdin and
    // derive request authorization from its in-memory cookie jar. The derived
    // value proves the jar arrived without carrying the cookie itself.
    let mut derived = None;
    if option("--config-locations").map(String::as_str) == Some("-") {
        let mut config = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut config)?;
        for line in config.lines() {
            let cookie = line
                .strip_prefix("--add-header 'Cookie: ")
                .and_then(|rest| rest.strip_suffix('\''))
                .ok_or("unexpected stdin config")?
                .replace("'\"'\"'", "'");
            let origin = url::Url::parse(url)?.origin().ascii_serialization();
            derived = Some(format!(
                "FixtureHash {}",
                omd_domain::digest(format!("{origin} {cookie}").as_bytes())
            ));
        }
    }
    let ca = std::fs::read(std::env::var("SSL_CERT_FILE")?)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(proxy)?)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut request = client.get(url);
    if let Some(derived) = derived {
        request = request.header(reqwest::header::AUTHORIZATION, derived);
    }
    let mut response = request.send().await?.error_for_status()?;
    // Like yt-dlp's generic extractor, identify direct media from the response
    // headers, or from a short prefix of an untyped body, and never read the
    // rest of a large file during metadata extraction.
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let typed = content_type
        .split_once('/')
        .filter(|(kind, _)| matches!(*kind, "audio" | "video"));
    let direct = if typed.is_some() {
        true
    } else if content_type.starts_with("application/octet-stream") {
        let mut prefix = Vec::new();
        while prefix.len() < 512 {
            match response.chunk().await? {
                Some(chunk) => prefix.extend_from_slice(&chunk),
                None => break,
            }
        }
        !prefix.trim_ascii_start().starts_with(b"<")
    } else {
        false
    };
    if direct {
        let name = url
            .rsplit('/')
            .next()
            .unwrap_or("media")
            .split(['?', '#'])
            .next()
            .unwrap_or("media");
        let (id, ext) = name.rsplit_once('.').unwrap_or((name, "unknown_video"));
        let (kind, subtype) = typed.unwrap_or(("video", "unknown"));
        println!(
            "{}",
            serde_json::json!({
                "id": id,
                "title": id,
                "extractor": "generic",
                "direct": true,
                "format_id": subtype.split(';').next().unwrap_or("unknown").trim(),
                "ext": ext,
                "vcodec": if kind == "audio" { Some("none") } else { None },
            })
        );
        return Ok(());
    }
    let mut value: serde_json::Value = response.json().await?;
    // Like yt-dlp, return only the requested 1-based, inclusive entry window.
    let number = |name: &str| option(name).and_then(|v| v.parse::<usize>().ok());
    if let (Some(start), Some(end)) = (number("--playlist-start"), number("--playlist-end"))
        && let Some(entries) = value
            .get_mut("entries")
            .and_then(serde_json::Value::as_array_mut)
    {
        let window = entries
            .iter()
            .skip(start.saturating_sub(1))
            .take((end + 1).saturating_sub(start))
            .cloned()
            .collect();
        *entries = window;
    }
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
