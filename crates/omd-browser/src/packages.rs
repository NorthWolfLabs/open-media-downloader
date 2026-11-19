//! Immutable browser inventories and recoverable installation/removal. Callers
//! serialize mutations and stop sessions before removing their executable bytes.
use super::{FileIdentity, Kit, Result, integrity, issue};
use omd_domain::{Page, Problem, digest};
use omd_files::Root;
use omd_store::{Store, now};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "BrowserPackageReview")]
pub struct Review {
    pub digest: String,
    pub platform: String,
    pub version: String,
    pub node_version: String,
    pub node: FileIdentity,
    pub browser: String,
    pub adapter: String,
    pub files: BTreeMap<String, FileIdentity>,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "BrowserPackage")]
pub struct Installed {
    pub digest: String,
    pub label: String,
    pub review: Review,
    pub state: String,
    pub active: bool,
    pub installed_at: String,
    pub updated_at: String,
    pub approval_digest: String,
    pub issue: Option<Problem>,
}
fn storage(_: impl std::fmt::Display) -> Problem {
    issue(
        "browser_storage",
        "The browser package operation could not finish. Check available storage and retry.",
        "retry",
    )
}
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(review: &Review) -> Result<String> {
    Ok(digest(
        &serde_json::to_vec(&(
            &review.platform,
            &review.version,
            &review.node_version,
            &review.node,
            &review.browser,
            &review.adapter,
            &review.files,
        ))
        .map_err(storage)?,
    ))
}
pub async fn read_manifest(path: &Path) -> Result<Kit> {
    if !path.is_absolute() {
        return Err(integrity());
    }
    let parent = Root::open(path.parent().ok_or_else(integrity)?).map_err(storage)?;
    let file = parent
        .read_file(
            path.file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(integrity)?,
        )
        .map_err(storage)?;
    let mut bytes = vec![];
    file.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(integrity());
    }
    let mut kit: Kit = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    if kit.root.is_relative() {
        kit.root = path.parent().unwrap().join(kit.root);
    }
    if kit.node.path.is_relative() {
        kit.node.path = path.parent().unwrap().join(kit.node.path);
    }
    Ok(kit)
}
pub async fn review(kit: &Kit) -> Result<Review> {
    if [&kit.version, &kit.node.version]
        .iter()
        .any(|v| v.is_empty() || v.len() > 100 || v.chars().any(char::is_control))
    {
        return Err(integrity());
    }
    kit.verify().await?;
    let mut review = Review {
        digest: String::new(),
        platform: platform(),
        version: kit.version.clone(),
        node_version: kit.node.version.clone(),
        node: FileIdentity {
            bytes: std::fs::metadata(&kit.node.path).map_err(storage)?.len(),
            sha256: kit.node.sha256.clone(),
        },
        browser: kit.browser.clone(),
        adapter: kit.adapter.clone(),
        files: kit.files.clone(),
    };
    review.digest = identity(&review)?;
    Ok(review)
}
fn root(profile: &Path) -> Result<Root> {
    let profile = Root::open(profile).map_err(storage)?;
    match profile.directory("managed-browsers") {
        Ok(root) => Ok(root),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => profile
            .create_directory("managed-browsers", true)
            .map_err(storage),
        Err(e) => Err(storage(e)),
    }
}
pub fn paths(profile: &Path, review: &Review) -> Result<Kit> {
    if !valid_digest(&review.digest)
        || review.platform != platform()
        || identity(review)? != review.digest
    {
        return Err(integrity());
    }
    // Native confinement uses canonical paths; adapter argv must match them
    // even when a fixture or caller supplied macOS's /var alias.
    let profile = profile.canonicalize().map_err(storage)?;
    Ok(Kit {
        root: profile
            .join("managed-browsers")
            .join(&review.digest)
            .join("content"),
        version: review.version.clone(),
        node: omd_media::Tool {
            path: profile
                .join("managed-browsers")
                .join(&review.digest)
                .join(if cfg!(windows) { "node.exe" } else { "node" }),
            version: review.node_version.clone(),
            sha256: review.node.sha256.clone(),
        },
        browser: review.browser.clone(),
        adapter: review.adapter.clone(),
        files: review.files.clone(),
    })
}
const SELECT: &str = "SELECT p.*,COALESCE(p.digest=a.digest,0) AS active FROM browser_packages p LEFT JOIN browser_package_active a ON a.singleton=1";
fn decode(row: sqlx::sqlite::SqliteRow) -> Result<Installed> {
    Ok(Installed {
        approval_digest: digest(
            &serde_json::to_vec(&(
                row.get::<String, _>("digest"),
                row.get::<i64, _>("revision"),
            ))
            .map_err(storage)?,
        ),
        digest: row.get("digest"),
        label: row.get("label"),
        review: serde_json::from_str(row.get("review_json")).map_err(storage)?,
        state: row.get("state"),
        active: row.get("active"),
        installed_at: row.get("installed_at"),
        updated_at: row.get("updated_at"),
        issue: row
            .get::<Option<String>, _>("issue_json")
            .map(|v| serde_json::from_str(&v))
            .transpose()
            .map_err(storage)?,
    })
}
pub async fn get(store: &Store, id: &str) -> Result<Installed> {
    if !valid_digest(id) {
        return Err(integrity());
    }
    decode(
        sqlx::query(&format!("{SELECT} WHERE p.digest=?"))
            .bind(id)
            .fetch_optional(&store.pool)
            .await
            .map_err(storage)?
            .ok_or_else(integrity)?,
    )
}
pub async fn list(
    store: &Store,
    query: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<Page<Installed>> {
    if limit == 0 || limit > 200 || query.len() > 200 || cursor.is_some_and(|v| !valid_digest(v)) {
        return Err(integrity());
    }
    let rows = sqlx::query(&format!("{SELECT} WHERE p.digest>? AND (instr(lower(p.label),lower(?))>0 OR instr(lower(p.review_json),lower(?))>0) ORDER BY p.digest LIMIT ?")).bind(cursor.unwrap_or("")).bind(query).bind(query).bind(limit+1).fetch_all(&store.pool).await.map_err(storage)?;
    let mut items = rows.into_iter().map(decode).collect::<Result<Vec<_>>>()?;
    let next_cursor = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|v| v.digest.clone())
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}
fn inventory(review: &Review) -> BTreeMap<String, FileIdentity> {
    std::iter::once((
        if cfg!(windows) { "node.exe" } else { "node" }.into(),
        review.node.clone(),
    ))
    .chain(
        review
            .files
            .iter()
            .map(|(name, identity)| (format!("content/{name}"), identity.clone())),
    )
    .collect()
}
fn parents(files: &BTreeMap<String, FileIdentity>) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for name in files.keys() {
        let mut parent = Path::new(name).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            result.insert(path.to_string_lossy().into_owned());
            parent = path.parent();
        }
    }
    result
}
fn check_entries(root: &Root, files: &BTreeMap<String, FileIdentity>) -> Result<()> {
    let directories = parents(files);
    let mut pending = vec![String::new()];
    while let Some(prefix) = pending.pop() {
        let directory = if prefix.is_empty() {
            root.try_clone()
        } else {
            root.directory(prefix.trim_end_matches('/'))
        }
        .map_err(storage)?;
        for entry in directory.entries().map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let name = format!("{prefix}{}", entry.name);
            if entry.directory {
                if !directories.contains(&name) {
                    return Err(integrity());
                }
                pending.push(format!("{name}/"));
            } else if !files.contains_key(&name) {
                return Err(integrity());
            }
        }
    }
    Ok(())
}
fn copy_file(
    mut source: std::fs::File,
    target: &Root,
    name: &str,
    expected: &FileIdentity,
    executable: bool,
) -> Result<()> {
    let offset = match target.read_file(name) {
        Ok(mut existing) => {
            let length = existing.metadata().map_err(storage)?.len();
            if length > expected.bytes {
                return Err(integrity());
            }
            let mut actual = [0u8; 65536];
            let mut original = [0u8; 65536];
            let mut remaining = length;
            while remaining > 0 {
                let count = remaining.min(actual.len() as u64) as usize;
                existing.read_exact(&mut actual[..count]).map_err(storage)?;
                source.read_exact(&mut original[..count]).map_err(storage)?;
                if actual[..count] != original[..count] {
                    return Err(integrity());
                }
                remaining -= count as u64;
            }
            length
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(storage(e)),
    };
    if offset < expected.bytes {
        let mut file = target.open_resume(name).map_err(storage)?;
        if file.metadata().map_err(storage)?.len() != offset {
            return Err(integrity());
        }
        // Compare the actual write descriptor again, after the pathname reopen.
        source.seek(SeekFrom::Start(0)).map_err(storage)?;
        let mut actual = [0u8; 65536];
        let mut original = [0u8; 65536];
        let mut remaining = offset;
        while remaining > 0 {
            let count = remaining.min(actual.len() as u64) as usize;
            file.read_exact(&mut actual[..count]).map_err(storage)?;
            source.read_exact(&mut original[..count]).map_err(storage)?;
            if actual[..count] != original[..count] {
                return Err(integrity());
            }
            remaining -= count as u64;
        }
        let mut remaining = expected.bytes - offset;
        while remaining > 0 {
            let count = remaining.min(original.len() as u64) as usize;
            source.read_exact(&mut original[..count]).map_err(storage)?;
            file.write_all(&original[..count]).map_err(storage)?;
            remaining -= count as u64;
        }
        file.sync_all().map_err(storage)?;
    } else if expected.bytes == 0 && target.read_file(name).is_err() {
        target.write_new(name, &[]).map_err(storage)?;
    }
    if target.hash(name).map_err(storage)? != (expected.bytes, expected.sha256.clone()) {
        return Err(integrity());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = target.read_file(name).map_err(storage)?;
        file.set_permissions(std::fs::Permissions::from_mode(if executable {
            0o500
        } else {
            0o400
        }))
        .map_err(storage)?;
        file.sync_all().map_err(storage)?;
    }
    #[cfg(not(unix))]
    {
        let _ = executable;
    }
    Ok(())
}
pub async fn install(
    store: &Store,
    profile: &Path,
    kit: &Kit,
    approve: &str,
    label: &str,
) -> Result<Installed> {
    let review = review(kit).await?;
    if approve != review.digest
        || label.trim().is_empty()
        || label.len() > 120
        || label.chars().any(char::is_control)
    {
        return Err(integrity());
    }
    let directory = root(profile)?;
    if directory.directory(&review.digest).is_err() {
        let stage = format!(".install-{}", review.digest);
        let staging = match directory.directory(&stage) {
            Ok(folder) => folder,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                directory.create_directory(&stage, true).map_err(storage)?
            }
            Err(e) => return Err(storage(e)),
        };
        let files = inventory(&review);
        check_entries(&staging, &files)?;
        for parent in parents(&files) {
            match staging.directory(&parent) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    staging.create_directory(&parent, true).map_err(storage)?;
                }
                Err(e) => return Err(storage(e)),
            }
        }
        let source = Root::open(&kit.root).map_err(storage)?;
        let node_parent =
            Root::open(kit.node.path.parent().ok_or_else(integrity)?).map_err(storage)?;
        for (name, expected) in &files {
            let (file, executable) = if let Some(relative) = name.strip_prefix("content/") {
                (
                    source.read_file(relative).map_err(storage)?,
                    kit.executable(relative),
                )
            } else {
                (
                    node_parent
                        .read_file(
                            kit.node
                                .path
                                .file_name()
                                .and_then(|v| v.to_str())
                                .ok_or_else(integrity)?,
                        )
                        .map_err(storage)?,
                    true,
                )
            };
            copy_file(file, &staging, name, expected, executable)?;
        }
        check_entries(&staging, &files)?;
        for parent in parents(&files).iter().rev() {
            staging
                .directory(parent)
                .map_err(storage)?
                .sync()
                .map_err(storage)?;
        }
        staging.sync().map_err(storage)?;
        // Windows directory capabilities deliberately deny delete sharing to
        // prevent substitution during verification. Release the staged child
        // before its atomic rename; retain the parent capabilities throughout.
        drop(staging);
        directory
            .publish(&stage, &directory, &review.digest)
            .map_err(storage)?;
    }
    let installed = paths(profile, &review)?;
    installed.verify().await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Older installations only marked the main browser executable. Repair
        // native helpers using verified descriptors in engine-owned storage.
        let content = Root::open(&installed.root).map_err(storage)?;
        for (name, identity) in &installed.files {
            if !installed.executable(name) {
                continue;
            }
            let file = content.read_file(name).map_err(storage)?;
            if omd_files::hash_file(file.try_clone().map_err(storage)?).map_err(storage)?
                != (identity.bytes, identity.sha256.clone())
            {
                return Err(integrity());
            }
            file.set_permissions(std::fs::Permissions::from_mode(0o500))
                .map_err(storage)?;
        }
    }
    check_entries(
        &directory.directory(&review.digest).map_err(storage)?,
        &inventory(&review),
    )?;
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query("INSERT INTO browser_packages(digest,label,review_json,state,installed_at,updated_at) VALUES(?,?,?,'installed',?,?) ON CONFLICT(digest) DO UPDATE SET revision=revision+CASE WHEN state='installed' THEN 0 ELSE 1 END,state='installed',updated_at=excluded.updated_at,issue_json=NULL").bind(&review.digest).bind(label.trim()).bind(serde_json::to_string(&review).map_err(storage)?).bind(now()).bind(now()).execute(&mut *tx).await.map_err(storage)?;
    omd_store::emit(&mut tx, "browser_tools", &review.digest)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, &review.digest).await
}
pub async fn activate(store: &Store, profile: &Path, id: &str) -> Result<Installed> {
    let installed = get(store, id).await?;
    if installed.state != "installed" {
        return Err(integrity());
    }
    paths(profile, &installed.review)?.verify().await?;
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query("UPDATE browser_package_active SET digest=? WHERE singleton=1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    omd_store::emit(&mut tx, "browser_tools", id)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, id).await
}
pub async fn begin_removal(store: &Store, id: &str, approval: &str) -> Result<Installed> {
    let installed = get(store, id).await?;
    if installed.approval_digest != approval {
        return Err(integrity());
    }
    if installed.state != "installed" {
        return Ok(installed);
    }
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query("UPDATE browser_packages SET state='removing',updated_at=? WHERE digest=?")
        .bind(now())
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    sqlx::query("UPDATE browser_package_active SET digest=NULL WHERE digest=?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    omd_store::emit(&mut tx, "browser_tools", id)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, id).await
}
pub async fn cleanup(store: &Store, profile: &Path, id: &str) -> Result<Installed> {
    let installed = get(store, id).await?;
    if !matches!(installed.state.as_str(), "removing" | "retained") {
        return Ok(installed);
    }
    let directory = root(profile)?;
    match directory.directory(id) {
        Ok(folder) => {
            let files = inventory(&installed.review);
            for (name, expected) in &files {
                let path = Path::new(name);
                let held = path
                    .with_file_name(format!(
                        ".removing-{}",
                        path.file_name().unwrap().to_string_lossy()
                    ))
                    .to_string_lossy()
                    .into_owned();
                if folder.read_file(&held).is_err() {
                    match folder.publish(name, &folder, &held) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(storage(e)),
                    }
                }
                match folder.hash(&held) {
                    Ok(actual) if actual == (expected.bytes, expected.sha256.clone()) => {
                        folder.remove_file(&held).map_err(storage)?
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    _ => {
                        let _ = folder.publish(&held, &folder, name);
                    }
                }
            }
            let mut parents: Vec<_> = parents(&files).into_iter().collect();
            parents.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
            for parent in parents {
                let _ = folder.remove_empty_directory(&parent);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(storage(e)),
    }
    let retained = match directory.remove_empty_directory(id) {
        Ok(()) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    };
    let problem=retained.then(||issue("browser_files_retained","Changed or additional browser files were preserved. Move them out of the removed package directory, then retry cleanup.","retry"));
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query("UPDATE browser_packages SET state=?,updated_at=?,issue_json=? WHERE digest=?")
        .bind(if retained { "retained" } else { "removed" })
        .bind(now())
        .bind(
            problem
                .map(|p| serde_json::to_string(&p))
                .transpose()
                .map_err(storage)?,
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    omd_store::emit(&mut tx, "browser_tools", id)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, id).await
}
