//! Reviewed immutable tool sets. SQLite owns activation and removal intent;
//! only exact verified engine-owned files can be cleaned up.
use omd_domain::{Page, Problem, digest};
use omd_media::{Tool, Tools};
use omd_store::{Store, now};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

type Result<T> = std::result::Result<T, Problem>;
fn issue(code: &str, message: &str) -> Problem {
    Problem {
        code: code.into(),
        message: message.into(),
        retryable: false,
        actions: vec!["restore_tool".into()],
    }
}
fn storage(_: impl std::fmt::Display) -> Problem {
    issue(
        "tool_storage",
        "The tool operation could not finish. Check disk space and retry.",
    )
}
fn invalid() -> Problem {
    issue(
        "tool_package_invalid",
        "Choose a complete managed-tool manifest for this platform.",
    )
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "ManagedToolIdentity")]
pub struct Identity {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "ManagedToolReview")]
pub struct Review {
    pub digest: String,
    pub platform: String,
    pub tools: Vec<Identity>,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "ManagedToolSet")]
pub struct Installed {
    pub digest: String,
    pub label: String,
    pub review: Review,
    pub state: String,
    pub active: bool,
    pub installed_at: String,
    pub updated_at: String,
    pub issue: Option<Problem>,
    pub approval_digest: String,
}
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}
fn entries(tools: &Tools) -> Vec<(&'static str, &Tool)> {
    std::iter::once(("yt_dlp", &tools.yt_dlp))
        .chain(tools.node.as_ref().map(|t| ("node", t)))
        .chain(tools.ffmpeg.as_ref().map(|t| ("ffmpeg", t)))
        .chain(tools.ffprobe.as_ref().map(|t| ("ffprobe", t)))
        .collect()
}
fn filename(name: &str) -> String {
    format!("{name}{}", if cfg!(windows) { ".exe" } else { "" })
}
pub async fn read_manifest(path: &Path) -> Result<Tools> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let path = tokio::fs::canonicalize(path).await.map_err(|_| invalid())?;
    if tokio::fs::metadata(&path)
        .await
        .map_err(|_| invalid())?
        .len()
        > 65536
    {
        return Err(invalid());
    }
    let mut tools: Tools =
        serde_json::from_slice(&tokio::fs::read(&path).await.map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    for tool in std::iter::once(&mut tools.yt_dlp)
        .chain(tools.node.iter_mut())
        .chain(tools.ffmpeg.iter_mut())
        .chain(tools.ffprobe.iter_mut())
    {
        if tool.path.is_relative() {
            tool.path = path.parent().ok_or_else(invalid)?.join(&tool.path)
        }
    }
    Ok(tools)
}
pub async fn review(tools: &Tools) -> Result<Review> {
    if entries(tools).len() != 4 {
        return Err(invalid());
    }
    let mut identities = vec![];
    for (name, tool) in entries(tools) {
        if tool.version.trim().is_empty()
            || tool.version.len() > 100
            || tool.version.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        tool.verify().await?;
        let bytes = tokio::fs::metadata(&tool.path)
            .await
            .map_err(storage)?
            .len();
        identities.push(Identity {
            name: name.into(),
            version: tool.version.clone(),
            sha256: tool.sha256.clone(),
            bytes,
        });
    }
    let platform = platform();
    let digest = digest(&serde_json::to_vec(&(&platform, &identities)).map_err(storage)?);
    Ok(Review {
        digest,
        platform,
        tools: identities,
    })
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn root(profile: &Path) -> Result<omd_files::Root> {
    let directory = omd_files::Root::open(profile).map_err(storage)?;
    match directory.directory("managed-tools") {
        Ok(root) => Ok(root),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => directory
            .create_directory("managed-tools", true)
            .map_err(storage),
        Err(e) => Err(storage(e)),
    }
}
fn decode(row: sqlx::sqlite::SqliteRow) -> Result<Installed> {
    let approval_digest = digest(
        &serde_json::to_vec(&(
            row.get::<String, _>("digest"),
            row.get::<i64, _>("revision"),
        ))
        .map_err(storage)?,
    );
    Ok(Installed {
        approval_digest,
        digest: row.get("digest"),
        label: row.get("label"),
        review: serde_json::from_str(row.get("manifest_json")).map_err(storage)?,
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
const SELECT: &str = "SELECT t.*,COALESCE(t.digest=a.digest,0) AS active FROM managed_tool_sets t LEFT JOIN managed_tool_active a ON a.singleton=1";
const JOB_MATCH: &str = "state IN ('queued','transferring','verifying','paused','failed') AND json_extract(plan_json,'$.media.yt_dlp_digest')=? AND json_extract(plan_json,'$.media.ffmpeg_digest')=? AND json_extract(plan_json,'$.media.ffprobe_digest')=? AND json_extract(plan_json,'$.media.node_digest')=?";
fn hashes(review: &Review) -> Result<Vec<&str>> {
    ["yt_dlp", "ffmpeg", "ffprobe", "node"]
        .iter()
        .map(|name| {
            review
                .tools
                .iter()
                .find(|t| &t.name == name)
                .map(|t| t.sha256.as_str())
                .ok_or_else(invalid)
        })
        .collect()
}
pub async fn affected_jobs(store: &Store, review: &Review) -> Result<i64> {
    let hashes = hashes(review)?;
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM jobs WHERE {JOB_MATCH}"))
        .bind(hashes[0])
        .bind(hashes[1])
        .bind(hashes[2])
        .bind(hashes[3])
        .fetch_one(&store.pool)
        .await
        .map_err(storage)
}
pub async fn get(store: &Store, id: &str) -> Result<Installed> {
    let row = sqlx::query(&format!("{SELECT} WHERE t.digest=?"))
        .bind(id)
        .fetch_optional(&store.pool)
        .await
        .map_err(storage)?
        .ok_or_else(|| issue("tool_not_found", "The managed tool set was not found."))?;
    decode(row)
}
pub async fn list(
    store: &Store,
    query: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<Page<Installed>> {
    if query.len() > 200 || cursor.is_some_and(|c| !c.is_empty() && !valid_digest(c)) {
        return Err(invalid());
    }
    let limit = limit.clamp(1, 200);
    let rows=sqlx::query(&format!("{SELECT} WHERE t.digest>? AND (instr(lower(t.label),lower(?))>0 OR instr(t.digest,?)>0) ORDER BY t.digest LIMIT ?"))
        .bind(cursor.unwrap_or("")).bind(query).bind(query).bind(limit+1).fetch_all(&store.pool).await.map_err(storage)?;
    let mut items = rows.into_iter().map(decode).collect::<Result<Vec<_>>>()?;
    let next_cursor = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|v| v.digest.clone())
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}
pub fn paths(profile: &Path, review: &Review) -> Result<Tools> {
    if !valid_digest(&review.digest) || review.platform != platform() {
        return Err(invalid());
    }
    let tool = |name: &str| -> Result<Tool> {
        let identity = review
            .tools
            .iter()
            .find(|t| t.name == name)
            .ok_or_else(invalid)?;
        Ok(Tool {
            path: profile
                .join("managed-tools")
                .join(&review.digest)
                .join(filename(name)),
            sha256: identity.sha256.clone(),
            version: identity.version.clone(),
        })
    };
    Ok(Tools {
        yt_dlp: tool("yt_dlp")?,
        node: Some(tool("node")?),
        ffmpeg: Some(tool("ffmpeg")?),
        ffprobe: Some(tool("ffprobe")?),
    })
}
/// Callers serialize mutations. Copy and rehash before publishing; a crash before
/// SQL commit leaves an exact set that the same reviewed request can adopt.
pub async fn install(
    store: &Store,
    profile: &Path,
    tools: &Tools,
    approval: &str,
    label: &str,
) -> Result<Installed> {
    let review = review(tools).await?;
    if approval != review.digest
        || label.trim().is_empty()
        || label.len() > 120
        || label.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let directory = root(profile)?;
    if directory.directory(&review.digest).is_err() {
        // Bind staging to the reviewed bytes. After an interrupted copy the
        // same approval resumes this directory instead of abandoning a random
        // install directory and copying another complete tool set.
        let stage = format!(".install-{}", review.digest);
        let staging = match directory.directory(&stage) {
            Ok(folder) => folder,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                directory.create_directory(&stage, true).map_err(storage)?
            }
            Err(e) => return Err(storage(e)),
        };
        let names: Vec<_> = entries(tools)
            .into_iter()
            .map(|(name, _)| filename(name))
            .collect();
        for entry in staging.entries().map_err(storage)? {
            let entry = entry.map_err(storage)?;
            if !names.contains(&entry.name) {
                return Err(staging_conflict());
            }
        }
        let result = async {
            for (name, tool) in entries(tools) {
                let bytes = tool.read_verified().await?;
                let path = filename(name);
                let offset = match staging.read_file(&path) {
                    Ok(file) => {
                        let mut existing = Vec::new();
                        file.take(bytes.len() as u64 + 1)
                            .read_to_end(&mut existing)
                            .map_err(storage)?;
                        if !bytes.starts_with(&existing) {
                            return Err(staging_conflict());
                        }
                        existing.len()
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                    Err(_) => return Err(staging_conflict()),
                };
                if offset == bytes.len() {
                    // A crash can occur after all bytes are written but before
                    // executable permissions and the durability barrier.
                    #[cfg(unix)]
                    let file = staging.read_file(&path).map_err(storage)?;
                    #[cfg(not(unix))]
                    let file = staging.open_resume(&path).map_err(storage)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        file.set_permissions(std::fs::Permissions::from_mode(0o500))
                            .map_err(storage)?;
                    }
                    file.sync_all().map_err(storage)?;
                    continue;
                }
                let mut file = staging.open_resume(&path).map_err(storage)?;
                // Recheck the opened descriptor before appending: the pathname
                // may have been replaced since the first read.
                let mut existing = Vec::new();
                (&mut file)
                    .take(bytes.len() as u64 + 1)
                    .read_to_end(&mut existing)
                    .map_err(storage)?;
                if existing.len() != offset || !bytes.starts_with(&existing) {
                    return Err(staging_conflict());
                }
                file.seek(SeekFrom::Start(offset as u64)).map_err(storage)?;
                file.write_all(&bytes[offset..]).map_err(storage)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(std::fs::Permissions::from_mode(0o500))
                        .map_err(storage)?;
                }
                file.sync_all().map_err(storage)?;
            }
            staging.sync().map_err(storage)?;
            // The verified child must no longer be open when Windows renames
            // it. Parent handles remain held to prevent path substitution.
            drop(staging);
            directory
                .publish(&stage, &directory, &review.digest)
                .map_err(storage)
        }
        .await;
        result?;
    }
    let copied = paths(profile, &review)?;
    if self::review(&copied).await?.digest != review.digest {
        return Err(invalid());
    }
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query("INSERT INTO managed_tool_sets(digest,label,manifest_json,state,installed_at,updated_at,issue_json) VALUES(?,?,?,'installed',?,?,NULL) ON CONFLICT(digest) DO UPDATE SET revision=revision+CASE WHEN state='installed' THEN 0 ELSE 1 END,state='installed',updated_at=excluded.updated_at,issue_json=NULL")
        .bind(&review.digest).bind(label.trim()).bind(serde_json::to_string(&review).map_err(storage)?).bind(now()).bind(now()).execute(&mut *tx).await.map_err(storage)?;
    sqlx::query("DELETE FROM managed_tool_cleanup WHERE digest=?")
        .bind(&review.digest)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    omd_store::emit(&mut tx, "tools", &review.digest)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, &review.digest).await
}
fn staging_conflict() -> Problem {
    issue(
        "tool_staging_conflict",
        "The staged tool set contains changed or additional files. Move its .install directory out of the profile's managed-tools directory, then retry.",
    )
}
pub async fn activate(store: &Store, profile: &Path, id: &str) -> Result<Installed> {
    let installed = get(store, id).await?;
    if installed.state != "installed" {
        return Err(invalid());
    }
    if review(&paths(profile, &installed.review)?).await?.digest != id {
        return Err(invalid());
    }
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query("UPDATE managed_tool_active SET digest=? WHERE singleton=1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    omd_store::emit(&mut tx, "tools", id)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, id).await
}
pub async fn begin_removal(store: &Store, id: &str) -> Result<Installed> {
    let installed = get(store, id).await?;
    if installed.state != "installed" {
        return Ok(installed);
    }
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query(
        "UPDATE managed_tool_sets SET state='removing',updated_at=?,issue_json=NULL WHERE digest=?",
    )
    .bind(now())
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    sqlx::query("UPDATE managed_tool_active SET digest=NULL WHERE digest=?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    let hashes = hashes(&installed.review)?;
    sqlx::query(&format!(
        "UPDATE jobs SET state='paused',issue_json=?,updated_at=? WHERE {JOB_MATCH}"
    ))
    .bind(
        serde_json::to_string(&issue(
            "tool_removed",
            "Restore the approved tool set to continue.",
        ))
        .map_err(storage)?,
    )
    .bind(now())
    .bind(hashes[0])
    .bind(hashes[1])
    .bind(hashes[2])
    .bind(hashes[3])
    .execute(&mut *tx)
    .await
    .map_err(storage)?;
    omd_store::emit(&mut tx, "jobs.changed", "")
        .await
        .map_err(storage)?;
    for identity in &installed.review.tools {
        sqlx::query("INSERT INTO managed_tool_cleanup VALUES(?,?,?,'pending') ON CONFLICT(digest,name) DO UPDATE SET state='pending'").bind(id).bind(&identity.name).bind(&identity.sha256).execute(&mut *tx).await.map_err(storage)?;
    }
    omd_store::emit(&mut tx, "tools", id)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, id).await
}
/// Never remove modified or additional files. Missing exact files are a successful
/// replay of an unlink that completed before its SQLite checkpoint.
pub async fn cleanup(store: &Store, profile: &Path, id: &str) -> Result<Installed> {
    let installed = get(store, id).await?;
    if !matches!(installed.state.as_str(), "removing" | "retained") {
        return Ok(installed);
    }
    let directory = root(profile)?;
    let folder = match directory.directory(id) {
        Ok(value) => Some(value),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(storage(e)),
    };
    let rows=sqlx::query("SELECT name,sha256 FROM managed_tool_cleanup WHERE digest=? AND state<>'removed' ORDER BY name").bind(id).fetch_all(&store.pool).await.map_err(storage)?;
    for row in rows {
        let name: String = row.get("name");
        let expected: String = row.get("sha256");
        if !["yt_dlp", "node", "ffmpeg", "ffprobe"].contains(&name.as_str()) {
            return Err(invalid());
        }
        let state = if let Some(folder) = &folder {
            let held = format!(".removing-{name}");
            if folder.read_file(&held).is_err() {
                match folder.publish(&filename(&name), folder, &held) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(storage(e)),
                }
            }
            match folder.hash(&held) {
                Ok((_, actual)) if actual == expected => {
                    folder.remove_file(&held).map_err(storage)?;
                    "removed"
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => "removed",
                _ => {
                    let _ = folder.publish(&held, folder, &filename(&name));
                    "retained"
                }
            }
        } else {
            "removed"
        };
        sqlx::query("UPDATE managed_tool_cleanup SET state=? WHERE digest=? AND name=?")
            .bind(state)
            .bind(id)
            .bind(name)
            .execute(&store.pool)
            .await
            .map_err(storage)?;
    }
    drop(folder);
    let retained = match directory.remove_empty_directory(id) {
        Ok(()) => false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    };
    let problem=retained.then(||issue("tool_files_retained","Changed or additional files were preserved in the removed tool set. Restore or move them, then retry cleanup."));
    let mut tx = store
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage)?;
    sqlx::query("UPDATE managed_tool_sets SET state=?,updated_at=?,issue_json=? WHERE digest=?")
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
    omd_store::emit(&mut tx, "tools", id)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    get(store, id).await
}
