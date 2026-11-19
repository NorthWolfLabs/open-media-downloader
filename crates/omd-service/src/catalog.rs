//! Distribution-owned package discovery; independent clients use the same catalog.
use super::*;
use omd_store::{PreparedDestination, Recorded};
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub package_path: String,
}
pub async fn list(
    State(_app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<CatalogEntry>> {
    let executable = std::env::current_exe().map_err(|_| {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "catalog_unavailable",
            "The source catalog could not be located.",
        )
    })?;
    let directory = executable
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(std::path::Path::new("."))
        .join("providers");
    let entries = scan(&directory, &query.q).await?;
    let start = query
        .cursor
        .as_deref()
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_| {
            problem(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "Restart this catalog listing.",
            )
        })?;
    paginate(entries, start, query.limit)
}
/// Lists the packaged catalog. A missing `providers` directory is an empty
/// catalog: public distributions bundle no plugins by default.
async fn scan(directory: &std::path::Path, q: &str) -> Result<Vec<CatalogEntry>, ApiError> {
    let mut entries = Vec::new();
    let mut scanned = 0;
    if directory.is_dir() {
        let mut files = tokio::fs::read_dir(directory).await.map_err(|_| {
            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "catalog_unavailable",
                "The source catalog could not be read.",
            )
        })?;
        while let Some(file) = files.next_entry().await.map_err(|_| {
            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "catalog_unavailable",
                "The source catalog could not be read.",
            )
        })? {
            scanned += 1;
            if scanned > 4096 {
                return Err(problem(
                    StatusCode::CONFLICT,
                    "catalog_limit",
                    "The local catalog exceeds its package limit.",
                ));
            }
            let path = file.path();
            if path.extension().and_then(|s| s.to_str()) != Some("omdp") {
                continue;
            }
            use tokio::io::AsyncReadExt;
            let mut stream = tokio::fs::File::open(&path).await.map_err(|_| {
                problem(
                    StatusCode::CONFLICT,
                    "catalog_package",
                    "A catalog package cannot be read.",
                )
            })?;
            let mut header = [0; 10];
            stream.read_exact(&mut header).await.map_err(|_| {
                problem(
                    StatusCode::CONFLICT,
                    "catalog_package",
                    "A catalog package is damaged.",
                )
            })?;
            let length = u32::from_le_bytes(header[6..10].try_into().unwrap()) as usize;
            if &header[..6] != b"OMDP2\0" || length > 64 * 1024 {
                return Err(problem(
                    StatusCode::CONFLICT,
                    "catalog_package",
                    "A catalog package is damaged.",
                ));
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.map_err(|_| {
                problem(
                    StatusCode::CONFLICT,
                    "catalog_package",
                    "A catalog manifest is damaged.",
                )
            })?;
            let manifest: ProviderManifest = serde_json::from_slice(&bytes).map_err(|_| {
                problem(
                    StatusCode::CONFLICT,
                    "catalog_package",
                    "A catalog manifest is invalid.",
                )
            })?;
            validate_manifest(&manifest)?;
            if format!("{} {}", manifest.name, manifest.description)
                .to_lowercase()
                .contains(&q.to_lowercase())
            {
                entries.push(CatalogEntry {
                    id: manifest.id,
                    name: manifest.name,
                    description: manifest.description,
                    version: manifest.version,
                    package_path: path.to_string_lossy().into_owned(),
                });
            }
        }
    }
    entries.sort_by(|a, b| {
        (&a.name, &a.version, &a.package_path).cmp(&(&b.name, &b.version, &b.package_path))
    });
    Ok(entries)
}
fn paginate(
    entries: Vec<CatalogEntry>,
    start: usize,
    limit: Option<u32>,
) -> ApiResult<Page<CatalogEntry>> {
    if start > entries.len() {
        return Err(problem(
            StatusCode::CONFLICT,
            "cursor_expired",
            "Restart this catalog listing.",
        ));
    }
    let end = (start + limit.unwrap_or(100).clamp(1, 200) as usize).min(entries.len());
    let next_cursor = (end < entries.len()).then(|| end.to_string());
    Ok(Json(Page {
        items: entries.into_iter().skip(start).take(end - start).collect(),
        next_cursor,
    }))
}
pub async fn default_destination(State(app): State<App>) -> ApiResult<Destination> {
    Ok(Json(crate::shown_destination(
        ensure_default(
            &app.store,
            &app.source_changes,
            &SystemFolders,
            default_root,
        )
        .await?,
    )))
}
/// Folder access in the default destination flow. On a first run macOS holds
/// any of it until the user answers the Downloads permission prompt.
trait Folders: Sync {
    fn hydrate(
        &self,
        store: &Store,
        id: &str,
    ) -> impl Future<Output = omd_store::Result<Destination>> + Send;
    fn prepare(
        &self,
        root: &std::path::Path,
    ) -> impl Future<Output = omd_store::Result<PreparedDestination>> + Send;
    fn discard(&self, prepared: PreparedDestination) -> impl Future<Output = ()> + Send;
}
struct SystemFolders;
impl Folders for SystemFolders {
    async fn hydrate(&self, store: &Store, id: &str) -> omd_store::Result<Destination> {
        store.destination(id).await
    }
    async fn prepare(&self, root: &std::path::Path) -> omd_store::Result<PreparedDestination> {
        Store::prepare_destination(root).await
    }
    async fn discard(&self, prepared: PreparedDestination) {
        prepared.discard().await
    }
}
/// Every folder access waits outside `changes`, so a pending permission prompt
/// never blocks source changes; the lock covers one database transaction only.
async fn ensure_default<F, R>(
    store: &Store,
    changes: &Mutex<()>,
    folders: &F,
    root: impl FnOnce() -> R,
) -> Result<Destination, ApiError>
where
    F: Folders,
    R: Future<Output = Result<std::path::PathBuf, ApiError>>,
{
    if let Some(id) = store.first_destination_id().await? {
        return Ok(folders.hydrate(store, &id).await?);
    }
    let prepared = folders.prepare(&root().await?).await?;
    let recorded = {
        let _change = changes.lock().await;
        store.record_first_destination("Downloads", &prepared).await
    };
    match recorded {
        Ok(Recorded::Added(destination)) => Ok(destination),
        Ok(Recorded::Existing(id)) => {
            folders.discard(prepared).await;
            Ok(folders.hydrate(store, &id).await?)
        }
        Err(error) => {
            folders.discard(prepared).await;
            Err(error.into())
        }
    }
}
async fn default_root() -> Result<std::path::PathBuf, ApiError> {
    let dirs = directories::UserDirs::new().ok_or_else(|| {
        problem(
            StatusCode::CONFLICT,
            "downloads_unavailable",
            "Choose a download folder in Settings.",
        )
    })?;
    let root = dirs
        .download_dir()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| dirs.home_dir().join("Downloads"))
        .join("OMD");
    tokio::fs::create_dir_all(&root).await.map_err(|_| {
        problem(
            StatusCode::CONFLICT,
            "downloads_unavailable",
            "The default download folder could not be created. Choose a folder in Settings.",
        )
    })?;
    Ok(root)
}
#[cfg(test)]
mod tests {
    use super::*;
    // Public bundles stage no providers directory; an empty one must work too.
    #[tokio::test]
    async fn missing_or_empty_provider_directory_is_an_empty_catalog() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("providers");
        assert!(scan(&missing, "").await.unwrap().is_empty());
        tokio::fs::create_dir(&missing).await.unwrap();
        assert!(scan(&missing, "").await.unwrap().is_empty());
        tokio::fs::write(missing.join("README.txt"), b"not a package")
            .await
            .unwrap();
        let page = paginate(scan(&missing, "").await.unwrap(), 0, None).unwrap();
        assert!(page.0.items.is_empty());
        assert!(page.0.next_cursor.is_none());
        assert!(paginate(Vec::new(), 1, None).is_err());
    }

    /// What happens to the database while the first-run folder is prepared.
    enum Race {
        /// Another client registers a folder it chose.
        OtherClient(std::path::PathBuf),
        /// The database becomes unusable, so recording fails.
        Closed,
    }
    /// Real folder access that notes whether the source lock was held at each
    /// call. Under that lock, a pending macOS prompt would stall source changes.
    struct Probe {
        store: Store,
        changes: Arc<Mutex<()>>,
        race: Race,
        calls: std::sync::Mutex<Vec<(&'static str, bool)>>,
    }
    impl Probe {
        fn new(store: &Store, changes: &Arc<Mutex<()>>, race: Race) -> Self {
            Self {
                store: store.clone(),
                changes: changes.clone(),
                race,
                calls: Default::default(),
            }
        }
        fn note(&self, call: &'static str) {
            let held = self.changes.try_lock().is_err();
            self.calls.lock().unwrap().push((call, held));
        }
        fn calls(&self) -> Vec<(&'static str, bool)> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl Folders for Probe {
        async fn hydrate(&self, store: &Store, id: &str) -> omd_store::Result<Destination> {
            self.note("hydrate");
            store.destination(id).await
        }
        async fn prepare(&self, root: &std::path::Path) -> omd_store::Result<PreparedDestination> {
            self.note("prepare");
            let prepared = Store::prepare_destination(root).await?;
            match &self.race {
                Race::OtherClient(folder) => {
                    self.store.add_destination("Chosen", folder).await.unwrap();
                }
                Race::Closed => self.store.pool.close().await,
            }
            Ok(prepared)
        }
        async fn discard(&self, prepared: PreparedDestination) {
            self.note("discard");
            prepared.discard().await
        }
    }
    fn markers(folder: &std::path::Path) -> usize {
        std::fs::read_dir(folder)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".omd-destination-")
            })
            .count()
    }
    #[tokio::test]
    async fn default_folder_access_never_waits_under_the_source_lock() {
        let temp = tempfile::tempdir().unwrap();
        let downloads = temp.path().join("Downloads/OMD");
        let chosen = temp.path().join("Chosen");
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::create_dir(&chosen).unwrap();
        let root = || std::future::ready(Ok::<_, ApiError>(downloads.clone()));

        // Another client wins while this request waits for the prompt: its
        // marker is discarded and the winner hydrated, both after the lock.
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let changes = Arc::new(Mutex::new(()));
        let probe = Probe::new(&store, &changes, Race::OtherClient(chosen.clone()));
        let winner = ensure_default(&store, &changes, &probe, root)
            .await
            .unwrap();
        assert_eq!(
            std::path::Path::new(&winner.root),
            std::fs::canonicalize(&chosen).unwrap()
        );
        assert!(winner.available);
        assert_eq!(markers(&downloads), 0);
        // Later requests only hydrate the existing destination.
        let again = ensure_default(&store, &changes, &probe, root)
            .await
            .unwrap();
        assert_eq!(again.id, winner.id);
        assert_eq!(
            probe.calls(),
            [
                ("prepare", false),
                ("discard", false),
                ("hydrate", false),
                ("hydrate", false)
            ]
        );
        assert_eq!(store.destinations().await.unwrap().len(), 1);

        // A failed record also discards the prepared marker outside the lock.
        let store = Store::open(&temp.path().join("closed-db")).await.unwrap();
        let probe = Probe::new(&store, &changes, Race::Closed);
        assert!(
            ensure_default(&store, &changes, &probe, root)
                .await
                .is_err()
        );
        assert_eq!(markers(&downloads), 0);
        assert_eq!(probe.calls(), [("prepare", false), ("discard", false)]);
    }
}
