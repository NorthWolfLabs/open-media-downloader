use omd_domain::digest;
use omd_media::{Tool, Tools};
use omd_store::Store;
use omd_tools::*;
use std::path::Path;
fn fixture(root: &Path, version: &str) -> Tools {
    std::fs::create_dir_all(root).unwrap();
    let tool = |name: &str| {
        let bytes = format!("{name}-{version}");
        let path = root.join(name);
        std::fs::write(&path, &bytes).unwrap();
        Tool {
            path,
            sha256: digest(bytes.as_bytes()),
            version: version.into(),
        }
    };
    Tools {
        yt_dlp: tool("yt_dlp"),
        node: Some(tool("node")),
        ffmpeg: Some(tool("ffmpeg")),
        ffprobe: Some(tool("ffprobe")),
    }
}

#[tokio::test]
async fn installation_reuses_verified_prefixes_after_each_copy_boundary() {
    for boundary in 0..=8 {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let tools = fixture(&root.path().join("input"), "interrupted");
        let reviewed = review(&tools).await.unwrap();
        let stage = root
            .path()
            .join("managed-tools")
            .join(format!(".install-{}", reviewed.digest));
        std::fs::create_dir_all(&stage).unwrap();
        for (index, name) in ["yt_dlp", "node", "ffmpeg", "ffprobe"].iter().enumerate() {
            let bytes = std::fs::read(root.path().join("input").join(name)).unwrap();
            if boundary > index * 2 {
                let count = if boundary == index * 2 + 1 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                };
                let path = stage.join(format!("{name}{}", if cfg!(windows) { ".exe" } else { "" }));
                std::fs::write(path, &bytes[..count]).unwrap();
            }
        }
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        let installed = install(&store, root.path(), &tools, &reviewed.digest, "Recovered")
            .await
            .unwrap();
        assert_eq!(installed.state, "installed");
        assert!(!stage.exists());
        assert_eq!(
            review(&paths(root.path(), &reviewed).unwrap())
                .await
                .unwrap()
                .digest,
            reviewed.digest
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths(root.path(), &reviewed).unwrap().yt_dlp.path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o500);
        }
    }
}

#[tokio::test]
async fn installation_preserves_changed_and_additional_staging_files() {
    for extra in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let tools = fixture(&root.path().join("input"), "one");
        let reviewed = review(&tools).await.unwrap();
        let stage = root
            .path()
            .join("managed-tools")
            .join(format!(".install-{}", reviewed.digest));
        std::fs::create_dir_all(&stage).unwrap();
        let path = stage.join(if extra {
            "user-note"
        } else if cfg!(windows) {
            "yt_dlp.exe"
        } else {
            "yt_dlp"
        });
        std::fs::write(&path, "keep this unrelated content").unwrap();
        let failure = install(&store, root.path(), &tools, &reviewed.digest, "Tools")
            .await
            .err()
            .unwrap();
        assert_eq!(failure.code, "tool_staging_conflict");
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "keep this unrelated content"
        );
        assert!(
            !root
                .path()
                .join("managed-tools")
                .join(&reviewed.digest)
                .exists()
        );
    }
}
#[tokio::test]
async fn reviewed_updates_preserve_previous_bytes_and_activation_survives_restart() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("db");
    let store = Store::open(&db).await.unwrap();
    let tools = fixture(&root.path().join("input"), "one");
    let a = review(&tools).await.unwrap();
    assert!(
        install(&store, root.path(), &tools, "wrong", "First")
            .await
            .is_err()
    );
    let installed = install(&store, root.path(), &tools, &a.digest, "First")
        .await
        .unwrap();
    assert!(!installed.active);
    activate(&store, root.path(), &a.digest).await.unwrap();
    let new = fixture(&root.path().join("new"), "two");
    let b = review(&new).await.unwrap();
    install(&store, root.path(), &new, &b.digest, "Second")
        .await
        .unwrap();
    activate(&store, root.path(), &b.digest).await.unwrap();
    assert_eq!(
        review(&paths(root.path(), &a).unwrap())
            .await
            .unwrap()
            .digest,
        a.digest
    );
    activate(&store, root.path(), &a.digest).await.unwrap();
    store.pool.close().await;
    let store = Store::open(&db).await.unwrap();
    assert!(get(&store, &a.digest).await.unwrap().active);
    let repeated = install(&store, root.path(), &tools, &a.digest, "First")
        .await
        .unwrap();
    assert!(repeated.active);
    assert_eq!(repeated.installed_at, installed.installed_at);
    std::fs::write(&tools.yt_dlp.path, "changed after review").unwrap();
    assert!(
        install(&store, root.path(), &tools, &a.digest, "First")
            .await
            .is_err()
    );
}
#[tokio::test]
async fn removal_replays_quarantine_gaps_and_preserves_replacement_and_additional_files() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("db");
    let store = Store::open(&db).await.unwrap();
    let tools = fixture(&root.path().join("input"), "one");
    let review = review(&tools).await.unwrap();
    install(&store, root.path(), &tools, &review.digest, "Tools")
        .await
        .unwrap();
    activate(&store, root.path(), &review.digest).await.unwrap();
    begin_removal(&store, &review.digest).await.unwrap();
    assert!(!get(&store, &review.digest).await.unwrap().active);
    assert!(activate(&store, root.path(), &review.digest).await.is_err());
    let folder = root.path().join("managed-tools").join(&review.digest);
    let exe = if cfg!(windows) {
        "yt_dlp.exe"
    } else {
        "yt_dlp"
    };
    std::fs::rename(folder.join(exe), folder.join(".removing-yt_dlp")).unwrap();
    std::fs::write(folder.join(exe), "new unrelated original-path replacement").unwrap();
    std::fs::write(folder.join("sentinel"), "keep").unwrap();
    store.pool.close().await;
    let store = Store::open(&db).await.unwrap();
    let result = cleanup(&store, root.path(), &review.digest).await.unwrap();
    assert_eq!(result.state, "retained");
    assert_eq!(
        std::fs::read_to_string(folder.join(exe)).unwrap(),
        "new unrelated original-path replacement"
    );
    assert_eq!(
        std::fs::read_to_string(folder.join("sentinel")).unwrap(),
        "keep"
    );
    assert_eq!(
        cleanup(&store, root.path(), &review.digest)
            .await
            .unwrap()
            .state,
        "retained"
    );
    std::fs::remove_file(folder.join(exe)).unwrap();
    std::fs::remove_file(folder.join("sentinel")).unwrap();
    assert_eq!(
        cleanup(&store, root.path(), &review.digest)
            .await
            .unwrap()
            .state,
        "removed"
    );
    install(&store, root.path(), &tools, &review.digest, "Tools")
        .await
        .unwrap();
    assert_eq!(
        cleanup(&store, root.path(), &review.digest)
            .await
            .unwrap()
            .state,
        "installed"
    );
    assert_eq!(
        self::review(&paths(root.path(), &review).unwrap())
            .await
            .unwrap()
            .digest,
        review.digest
    );
}
#[tokio::test]
async fn managed_tool_history_pages_more_than_two_hundred_exact_sets() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(&root.path().join("db")).await.unwrap();
    for n in 0..251 {
        let tools = fixture(&root.path().join("input"), &n.to_string());
        let r = review(&tools).await.unwrap();
        install(&store, root.path(), &tools, &r.digest, "Reference")
            .await
            .unwrap();
    }
    let first = list(&store, "reference", None, 200).await.unwrap();
    assert_eq!(first.items.len(), 200);
    let rest = list(&store, "reference", first.next_cursor.as_deref(), 200)
        .await
        .unwrap();
    assert_eq!(rest.items.len(), 51);
    assert!(rest.next_cursor.is_none());
    assert!(
        list(&store, "not present", None, 200)
            .await
            .unwrap()
            .items
            .is_empty()
    );
}
