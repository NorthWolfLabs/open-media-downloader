//! Bounded, unauthenticated development probe for the pinned media adapter.
//!
//! Usage: probe <yt-dlp executable> <media page URL> <granted host>...
//! Core names no site; pass the page and the hosts its extractor needs, as a
//! plugin's host grant would.
#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let usage = "usage: probe <yt-dlp executable> <media page URL> <granted host>...";
    let executable = std::path::PathBuf::from(args.next().expect(usage));
    let url = args.next().expect(usage);
    let hosts: Vec<String> = args.collect();
    assert!(!hosts.is_empty(), "{usage}");
    let work = tempfile::tempdir().unwrap();
    let grant = omd_domain::HostGrant {
        request_intervals: Default::default(),
        id: "media".into(),
        hosts,
        methods: vec!["GET".into(), "POST".into()],
        credential: false,
    };
    let broker = omd_helper_broker::Broker::start(
        omd_network::Network::new(0),
        vec![grant],
        None,
        false,
        32 * 1024 * 1024,
    )
    .await
    .unwrap();
    let cert = work.path().join("ca.pem");
    std::fs::write(&cert, &broker.ca_pem).unwrap();
    let policy = omd_isolation::Policy {
        executable,
        readable: vec![],
        executables: vec![],
        work: work.path().into(),
        broker_port: Some(broker.port),
        broker_upstream_port: None,
        interactive: false,
    };
    let args = vec![
        "--ignore-config",
        "--no-plugin-dirs",
        "--no-cache-dir",
        "--skip-download",
        "--dump-single-json",
        "--no-js-runtimes",
        "--socket-timeout",
        "10",
        "--retries",
        "0",
        "--compat-options",
        "no-certifi",
        "--proxy",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([broker.proxy_url(), "--".into(), url])
    .collect::<Vec<_>>();
    let captured = omd_isolation::capture(
        &policy,
        &args,
        vec![],
        &std::collections::BTreeMap::from([(
            "SSL_CERT_FILE".into(),
            cert.to_string_lossy().into_owned(),
        )]),
        32 * 1024 * 1024,
        std::time::Duration::from_secs(60),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    println!(
        "success={} output_bytes={} diagnostic={}",
        captured.success,
        captured.stdout.len(),
        String::from_utf8_lossy(&captured.stderr).replace(&broker.username, "[proxy credential]")
    );
}
