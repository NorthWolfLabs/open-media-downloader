//! Bounded live extraction through the verified managed tools, the confined
//! helper and the engine HTTPS broker. Core names no site: the operator supplies
//! the page and the hosts its extractor needs, as a plugin's host grant would.
//!
//! OMD_TEST_MEDIA_TOOLS: a verified tools-v2.json (relative paths resolve
//! against its folder). OMD_TEST_LIVE_MEDIA_URL: a public media page.
//! OMD_TEST_LIVE_MEDIA_HOSTS: comma-separated granted hosts (wildcards allowed).
//! OMD_TEST_LIVE_MEDIA_ID (optional): the item id the extractor must report.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
#[tokio::test]
#[ignore = "live extraction; requires OMD_TEST_MEDIA_TOOLS, OMD_TEST_LIVE_MEDIA_URL and OMD_TEST_LIVE_MEDIA_HOSTS"]
async fn live_metadata_uses_confined_tool_and_engine_https_broker() {
    let required = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| panic!("Set {name} for this live extraction"))
    };
    let manifest = std::path::PathBuf::from(required("OMD_TEST_MEDIA_TOOLS"));
    let mut tools: omd_media::Tools =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    let base = manifest.parent().unwrap();
    let absolute = |tool: &mut omd_media::Tool| {
        if tool.path.is_relative() {
            tool.path = base.join(&tool.path);
        }
    };
    absolute(&mut tools.yt_dlp);
    for tool in [&mut tools.ffmpeg, &mut tools.ffprobe, &mut tools.node] {
        tool.as_mut().map(absolute);
    }
    let url = required("OMD_TEST_LIVE_MEDIA_URL");
    let hosts: Vec<String> = required("OMD_TEST_LIVE_MEDIA_HOSTS")
        .split(',')
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .collect();
    let work = tempfile::tempdir().unwrap();
    let media = omd_media::Media {
        revoked: tokio_util::sync::CancellationToken::new(),
        tools,
        network: omd_network::Network::new(0),
        work_root: work.path().into(),
    };
    let grant = omd_domain::HostGrant {
        request_intervals: Default::default(),
        id: "media".into(),
        hosts,
        methods: vec!["GET".into(), "POST".into()],
        credential: false,
    };
    let result = media
        .inspect(
            &omd_media::Inspect {
                url,
                cursor: None,
                page_size: 10,
            },
            "fixture-source",
            &[grant],
            None,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
    assert!(result.is_ok(), "{:?}", result.err());
    let value = result.unwrap();
    if let Ok(id) = std::env::var("OMD_TEST_LIVE_MEDIA_ID") {
        assert_eq!(value["id"], id);
    }
    // Only the projection reaches a component: no formats or transport.
    assert!(value.get("formats").is_none());
    assert!(value.get("http_headers").is_none());
    assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
}
