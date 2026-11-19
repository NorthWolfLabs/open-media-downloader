use omd_browser::{FileIdentity, Kit, packages::*};
use omd_domain::digest;
use omd_store::Store;
use std::{collections::BTreeMap, path::Path};
fn fixture(root: &Path, version: &str) -> Kit {
    std::fs::create_dir_all(root.join("content/resources")).unwrap();
    let mut files = BTreeMap::new();
    for name in ["browser", "adapter.mjs", "resources/fixture.pak"] {
        let bytes = format!("{name}-{version}");
        std::fs::write(root.join("content").join(name), &bytes).unwrap();
        files.insert(
            name.into(),
            FileIdentity {
                bytes: bytes.len() as u64,
                sha256: digest(bytes.as_bytes()),
            },
        );
    }
    std::fs::write(root.join("node"), "fixture-node").unwrap();
    Kit {
        root: root.join("content"),
        version: version.into(),
        node: omd_media::Tool {
            path: root.join("node"),
            sha256: digest(b"fixture-node"),
            version: "fixture".into(),
        },
        browser: "browser".into(),
        adapter: "adapter.mjs".into(),
        files,
    }
}
#[cfg(unix)]
#[tokio::test]
async fn many_locale_folders_fit_gui_file_descriptor_budget() {
    const CHILD: &str = "OMD_BROWSER_DESCRIPTOR_TEST";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new("/bin/sh")
            .args(["-c", "ulimit -n 256; exec \"$1\" --exact many_locale_folders_fit_gui_file_descriptor_budget --nocapture", "omd-browser-test"])
            .arg(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut kit = fixture(&root.path().join("input"), "many-locales");
    for i in 0..400 {
        let name = format!("resources/locale-{i}/messages.pak");
        std::fs::create_dir_all(kit.root.join(&name).parent().unwrap()).unwrap();
        std::fs::write(kit.root.join(&name), b"locale").unwrap();
        kit.files.insert(
            name,
            FileIdentity {
                bytes: 6,
                sha256: digest(b"locale"),
            },
        );
    }
    let helper = "Browser.app/Contents/MacOS/Browser Helper";
    std::fs::create_dir_all(kit.root.join(helper).parent().unwrap()).unwrap();
    std::fs::write(kit.root.join(helper), b"helper").unwrap();
    kit.files.insert(
        helper.into(),
        FileIdentity {
            bytes: 6,
            sha256: digest(b"helper"),
        },
    );
    let reviewed = review(&kit).await.unwrap();
    let store = Store::open(&root.path().join("db")).await.unwrap();
    install(&store, root.path(), &kit, &reviewed.digest, "Browser")
        .await
        .unwrap();
    activate(&store, root.path(), &reviewed.digest)
        .await
        .unwrap();
    paths(root.path(), &reviewed)
        .unwrap()
        .verify()
        .await
        .unwrap();
    use std::os::unix::fs::PermissionsExt;
    let helper = paths(root.path(), &reviewed).unwrap().root.join(helper);
    assert_eq!(
        std::fs::metadata(&helper).unwrap().permissions().mode() & 0o777,
        0o500
    );
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o400)).unwrap();
    install(&store, root.path(), &kit, &reviewed.digest, "Browser")
        .await
        .unwrap();
    assert_eq!(
        std::fs::metadata(&helper).unwrap().permissions().mode() & 0o777,
        0o500
    );
}
#[tokio::test]
async fn copied_inventory_activation_rollback_removal_and_reinstall_approval() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(&root.path().join("db")).await.unwrap();
    let one = fixture(&root.path().join("one"), "one");
    let first = review(&one).await.unwrap();
    let two = fixture(&root.path().join("two"), "two");
    let second = review(&two).await.unwrap();
    for (kit, review) in [(&one, &first), (&two, &second)] {
        assert!(
            install(&store, root.path(), kit, "unapproved", "Browser")
                .await
                .is_err()
        );
        install(&store, root.path(), kit, &review.digest, "Browser")
            .await
            .unwrap();
    }
    activate(&store, root.path(), &first.digest).await.unwrap();
    activate(&store, root.path(), &second.digest).await.unwrap();
    activate(&store, root.path(), &first.digest).await.unwrap();
    assert!(get(&store, &first.digest).await.unwrap().active);
    let second = get(&store, &second.digest).await.unwrap();
    begin_removal(&store, &second.digest, &second.approval_digest)
        .await
        .unwrap();
    assert_eq!(
        cleanup(&store, root.path(), &second.digest)
            .await
            .unwrap()
            .state,
        "removed"
    );
    let reinstated = install(&store, root.path(), &two, &second.digest, "Again")
        .await
        .unwrap();
    assert_ne!(reinstated.approval_digest, second.approval_digest);
    assert!(
        begin_removal(&store, &second.digest, &second.approval_digest)
            .await
            .is_err()
    );
    let page = list(&store, "Browser", None, 1).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        list(&store, "Browser", page.next_cursor.as_deref(), 1)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    paths(root.path(), &first).unwrap().verify().await.unwrap();
}
#[tokio::test]
async fn installation_recovers_nested_partial_and_completed_copies() {
    for boundary in 0..=8 {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let kit = fixture(&root.path().join("input"), "recovery");
        let reviewed = review(&kit).await.unwrap();
        let stage = root
            .path()
            .join("managed-browsers")
            .join(format!(".install-{}", reviewed.digest));
        std::fs::create_dir_all(stage.join("content/resources")).unwrap();
        let files = [
            ("content/adapter.mjs", kit.root.join("adapter.mjs")),
            ("content/browser", kit.root.join("browser")),
            (
                "content/resources/fixture.pak",
                kit.root.join("resources/fixture.pak"),
            ),
            (
                if cfg!(windows) { "node.exe" } else { "node" },
                kit.node.path.clone(),
            ),
        ];
        for (index, (name, input)) in files.iter().enumerate() {
            if boundary > index * 2 {
                let bytes = std::fs::read(input).unwrap();
                let count = if boundary == index * 2 + 1 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                };
                std::fs::write(stage.join(name), &bytes[..count]).unwrap();
            }
        }
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        install(&store, root.path(), &kit, &reviewed.digest, "Recovered")
            .await
            .unwrap();
        paths(root.path(), &reviewed)
            .unwrap()
            .verify()
            .await
            .unwrap();
        assert!(!stage.exists());
    }
}
#[tokio::test]
async fn changed_files_are_preserved_during_installation_and_removal() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(&root.path().join("db")).await.unwrap();
    let kit = fixture(&root.path().join("input"), "preservation");
    let review = review(&kit).await.unwrap();
    let stage = root
        .path()
        .join("managed-browsers")
        .join(format!(".install-{}", review.digest));
    std::fs::create_dir_all(stage.join("content")).unwrap();
    std::fs::write(stage.join("content/browser"), "user content").unwrap();
    assert!(
        install(&store, root.path(), &kit, &review.digest, "Browser")
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(stage.join("content/browser")).unwrap(),
        "user content"
    );
    std::fs::rename(
        stage.join("content/browser"),
        root.path().join("preserved-note"),
    )
    .unwrap();
    let installed = install(&store, root.path(), &kit, &review.digest, "Browser")
        .await
        .unwrap();
    let browser = paths(root.path(), &review).unwrap().root.join("browser");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&browser, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&browser, "user content").unwrap();
    begin_removal(&store, &review.digest, &installed.approval_digest)
        .await
        .unwrap();
    assert_eq!(
        cleanup(&store, root.path(), &review.digest)
            .await
            .unwrap()
            .state,
        "retained"
    );
    assert_eq!(std::fs::read_to_string(&browser).unwrap(), "user content");
    std::fs::rename(&browser, root.path().join("second-preserved-note")).unwrap();
    assert_eq!(
        cleanup(&store, root.path(), &review.digest)
            .await
            .unwrap()
            .state,
        "removed"
    );
}
