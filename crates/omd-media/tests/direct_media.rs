#![cfg(all(
    feature = "fixture-tests",
    any(target_os = "macos", target_os = "linux", windows)
))]
//! Long public direct media (podcast episodes are often 50-200 MiB) through
//! the real helper confinement and broker. Preparation reads only metadata, so
//! the extraction budget must bound bytes delivered, not the declared size.
use omd_domain::{HostGrant, Recipe, ResolvedRelease, SelectionPolicy};
use omd_media::{Inspect, Media, Preparation, Tool, Tools};
use omd_network::Network;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;
/// The fixed extraction budget in `Media::extract`.
const EXTRACTION_BUDGET: u64 = 32 * MIB;

/// A plain loopback origin standing in for a public CDN. It declares `length`
/// bytes and writes them in 16 KiB pieces under real TCP backpressure,
/// counting what it could hand to the engine.
async fn origin(length: u64, content_type: &'static str) -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let sent = Arc::new(AtomicU64::new(0));
    let counter = sent.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let Ok(byte) = socket.read_u8().await else {
                        return;
                    };
                    request.push(byte);
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                );
                if socket.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let mut chunk = vec![0u8; 16 * 1024];
                chunk[..3].copy_from_slice(b"ID3");
                let mut remaining = length;
                while remaining > 0 {
                    let n = remaining.min(chunk.len() as u64) as usize;
                    if socket.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    counter.fetch_add(n as u64, Ordering::SeqCst);
                    remaining -= n as u64;
                    chunk[..3].fill(0);
                }
            });
        }
    });
    (address, sent)
}
/// The publisher's tracking host redirects to the CDN, like podcast feeds do.
/// Both are granted; the CDN response is streamed from the loopback origin.
fn network(origin: std::net::SocketAddr) -> Network {
    let handle = tokio::runtime::Handle::current();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    Network::new(0).with_transfer_fixture(move |url, _, _| match url.host_str() {
        Some("traffic.fixture.test") => Ok(http::Response::builder()
            .status(302)
            .header(
                "Location",
                format!("https://cdn.fixture.test{}", url.path()),
            )
            .body(reqwest::Body::from(Vec::new()))
            .unwrap()),
        Some("cdn.fixture.test") => {
            let response = tokio::task::block_in_place(|| {
                handle.block_on(client.get(format!("http://{origin}{}", url.path())).send())
            })
            .unwrap();
            // Keeps the origin's exact Content-Length, as a real response does.
            Ok(http::Response::from(response))
        }
        _ => Err(omd_network::NetworkError::Denied),
    })
}
fn grants() -> Vec<HostGrant> {
    vec![HostGrant {
        request_intervals: Default::default(),
        id: "media".into(),
        hosts: vec!["traffic.fixture.test".into(), "cdn.fixture.test".into()],
        methods: vec!["GET".into()],
        credential: false,
    }]
}
fn media(network: Network, work: &std::path::Path) -> Media {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_omd-media-probe"));
    let tool = Tool {
        sha256: omd_domain::digest(&std::fs::read(&path).unwrap()),
        path,
        version: "test-only".into(),
    };
    Media {
        revoked: CancellationToken::new(),
        tools: Tools {
            yt_dlp: tool.clone(),
            node: None,
            ffmpeg: Some(tool.clone()),
            ffprobe: Some(tool),
        },
        network,
        work_root: work.into(),
    }
}
fn resolved(url: &str) -> ResolvedRelease {
    serde_json::from_value(serde_json::json!({
        "release": {
            "reference": {"provider": "fixture-source", "id": "episode-1"},
            "collection": {"provider": "fixture-source", "id": "show"},
            "title": "A long episode",
            "canonical_url": "https://traffic.fixture.test/episode-1",
            "chapter": null, "volume": null, "language": "en", "group": null,
            "published_at": null, "revision": null,
            "availability": "available", "unavailable_reason": null, "position": 1
        },
        "collection": {
            "reference": {"provider": "fixture-source", "id": "show"},
            "title": "Show", "kind": "playlist",
            "canonical_url": "https://traffic.fixture.test/show",
            "description": null, "artwork_url": null
        },
        "resources": [{
            "id": "audio", "position": 0, "role": "media", "media_type": "audio/mpeg",
            "expected_size": null, "expected_sha256": null,
            "locator": {"kind": "media", "url": url, "permission": "media", "credential_profile": null}
        }],
        "expires_at": null
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_direct_media_prepares_from_its_headers_within_the_extraction_budget() {
    for (content_type, format_id) in [
        ("audio/mpeg", "mpeg"),
        // Untyped bodies are identified from a short prefix.
        ("application/octet-stream", "unknown"),
    ] {
        let (address, sent) = origin(128 * MIB, content_type).await;
        let temp = tempfile::tempdir().unwrap();
        let plan = media(network(address), temp.path())
            .prepare(
                Preparation {
                    resolved: resolved("https://traffic.fixture.test/episode-1.mp3"),
                    recipe: Recipe::Mp3,
                    policy: SelectionPolicy::default(),
                    provider_digest: "fixture".into(),
                    credential_profile: None,
                },
                &grants(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_or_else(|p| panic!("{content_type}: {} {}", p.code, p.message));
        let selection = plan.media.expect("media selection");
        assert_eq!(selection.format_ids, [format_id]);
        assert_eq!(plan.outputs[0].relative_path, "media.mp3");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let sent = sent.load(Ordering::SeqCst);
        assert!(
            sent < EXTRACTION_BUDGET,
            "{content_type}: preparing metadata transferred {sent} bytes"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_helper_reading_past_the_extraction_budget_gets_a_budget_refusal() {
    let (address, sent) = origin(64 * MIB, "application/json").await;
    let temp = tempfile::tempdir().unwrap();
    let problem = media(network(address), temp.path())
        .inspect(
            &Inspect {
                url: "https://traffic.fixture.test/listing.json".into(),
                cursor: None,
                page_size: 1,
            },
            "fixture-source",
            &grants(),
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(problem.code, "media_budget", "{}", problem.message);
    // Cut at the budget; only socket buffers beyond it, never the whole body.
    let sent = sent.load(Ordering::SeqCst);
    assert!(sent < 48 * MIB, "{sent} bytes transferred past the budget");
}
