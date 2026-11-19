//! Durable acquisition and publication. Source code supplies locators, never paths.
mod media_progress;
use omd_domain::*;
use omd_files::Root;
use omd_network::{Network, Request};
use omd_store::Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Component, Path},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum AcquisitionError {
    #[error("{}", .0.message)]
    Media(Problem),
    #[error(transparent)]
    Store(#[from] omd_store::StoreError),
    #[error(transparent)]
    Network(#[from] omd_network::NetworkError),
    #[error("The destination is unavailable or cannot be written")]
    Destination,
    #[error("An unrelated file already occupies the output path; choose a new version")]
    Collision,
    #[error("The source output failed identity, size, type, or hash verification")]
    Integrity,
    #[error(
        "The source returned an HTML challenge or error page instead of an image. The chapter was not published; check source access and retry."
    )]
    SourcePage,
    #[error("The requested output recipe does not match these source resources")]
    Recipe,
    #[error("The acquisition was paused or canceled")]
    Canceled,
    #[error("File operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Archive operation failed: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("Publication manifest is invalid")]
    Manifest,
}
type Result<T> = std::result::Result<T, AcquisitionError>;

/// All sidecars are explicit at preparation time. A published chapter is one
/// directory rename, whether its page representation is CBZ or loose images.
pub fn prepare(
    resolved: ResolvedRelease,
    recipe: Recipe,
    policy: SelectionPolicy,
    provider_digest: String,
) -> Result<Plan> {
    if resolved.release.availability != Availability::Available
        || resolved.resources.is_empty()
        || resolved.resources.len() > 20_000
        || resolved.release.collection != resolved.collection.reference
    {
        return Err(AcquisitionError::Integrity);
    }
    if !matches!(
        recipe,
        Recipe::Cbz | Recipe::ImageFolder | Recipe::OriginalImages
    ) {
        return Err(AcquisitionError::Recipe);
    }
    if recipe == Recipe::OriginalImages
        && (resolved
            .collection
            .summary
            .as_ref()
            .and_then(|s| s.image.as_ref())
            .is_none()
            || resolved.collection.kind != CollectionKind::Item)
    {
        return Err(AcquisitionError::Recipe);
    }
    if recipe == Recipe::OriginalImages
        && resolved
            .collection
            .summary
            .as_ref()
            .and_then(|s| s.image.as_ref())
            .is_some_and(|image| {
                image.count as usize != resolved.resources.len()
                    || image.release_id != resolved.release.reference.id
            })
    {
        return Err(AcquisitionError::Integrity);
    }
    let mut seen = BTreeSet::new();
    let mut positions = BTreeSet::new();
    let mut outputs = vec![];
    for resource in resolved.resources {
        if resource.id.is_empty()
            || !seen.insert(resource.id.clone())
            || resource.position >= 20_000
            || !positions.insert(resource.position)
            || !matches!(resource.locator, Locator::Http { .. })
        {
            return Err(AcquisitionError::Integrity);
        }
        let extension = image_extension(
            resource
                .media_type
                .as_deref()
                .ok_or(AcquisitionError::Integrity)?,
        )?;
        outputs.push(LogicalOutput {
            id: resource.id,
            position: resource.position,
            relative_path: format!("{:05}.{extension}", resource.position + 1),
            role: resource.role,
            media_type: resource.media_type,
            expected_size: resource.expected_size,
            expected_sha256: resource.expected_sha256,
            locator: resource.locator,
        });
    }
    outputs.sort_by_key(|o| o.position);
    if outputs
        .iter()
        .enumerate()
        .any(|(index, o)| o.position as usize != index)
    {
        return Err(AcquisitionError::Integrity);
    }
    let collection = format!(
        "{} [{}]",
        path_segment(&resolved.collection.title, "Series"),
        &resolved.collection.reference.key()[..10]
    );
    let chapter = format!(
        "{} [{}]",
        path_segment(&resolved.release.title, "Chapter"),
        &resolved.release.reference.key()[..10]
    );
    Ok(Plan {
        metadata: Default::default(),
        media: None,
        credential_profile: None,
        generation: 0,
        release: resolved.release,
        collection: resolved.collection,
        recipe,
        policy,
        outputs,
        final_relative_path: if recipe == Recipe::OriginalImages {
            collection
        } else {
            format!("{collection}/{chapter}")
        },
        expires_at: resolved.expires_at,
        provider_digest,
    })
}
pub fn final_outputs(plan: &Plan) -> Vec<String> {
    let mut paths = match plan.recipe {
        Recipe::Cbz => vec!["chapter.cbz".into()],
        _ => plan
            .outputs
            .iter()
            .map(|o| o.relative_path.clone())
            .collect(),
    };
    paths.extend([
        if plan.media.is_some() || plan.recipe == Recipe::OriginalImages {
            "metadata.json"
        } else {
            "ComicInfo.xml"
        }
        .into(),
        "provenance.json".into(),
    ]);
    paths
}
fn image_extension(media: &str) -> Result<&'static str> {
    match media {
        "image/jpeg" => Ok("jpg"),
        "image/png" => Ok("png"),
        "image/webp" => Ok("webp"),
        "image/gif" => Ok("gif"),
        "image/avif" => Ok("avif"),
        _ => Err(AcquisitionError::Integrity),
    }
}
pub fn image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.len() >= 12
        && &bytes[4..8] == b"ftyp"
        && matches!(&bytes[8..12], b"avif" | b"avis")
    {
        Some("image/avif")
    } else {
        None
    }
}
fn safe_relative(path: &str) -> Result<&Path> {
    let p = Path::new(path);
    if p.as_os_str().is_empty() || !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(AcquisitionError::Manifest);
    }
    Ok(p)
}

#[derive(Clone)]
pub struct Acquisition {
    pub store: Store,
    pub network: Network,
}
#[derive(Serialize, Deserialize)]
struct Checkpoint {
    #[serde(default)]
    prefix_sha256: Option<String>,
    bytes: u64,
    etag: Option<String>,
    total: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Publication {
    final_path: String,
    artifacts: Vec<Artifact>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Boundary {
    TransferVerified,
    ArchiveMember,
    AssemblyComplete,
    Journaled,
    Published,
    Recorded,
}
fn boundary(current: Boundary, interrupt: Option<Boundary>) -> Result<()> {
    if interrupt == Some(current) {
        return Err(std::io::Error::other("Injected interruption").into());
    }
    Ok(())
}

impl Acquisition {
    async fn cleanup(&self, job: &Job) -> Result<()> {
        let root = self.store.destination_root(&job.destination_id).await?;
        let name = format!(".omd-stage-v2-{}", job.id);
        match root.directory(&name) {
            Ok(stage) => {
                let mut owner = Vec::new();
                stage
                    .read_file("owner")?
                    .take(256)
                    .read_to_end(&mut owner)?;
                if owner != job.id.as_bytes() {
                    return Err(AcquisitionError::Destination);
                }
                drop(stage);
                root.remove_directory(&name)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.store.publication_cleaned(&job.id).await?;
        Ok(())
    }
    pub async fn cleanup_completed(&self) -> Result<()> {
        for job in self.store.publication_cleanup_batch().await? {
            // Disconnected destinations are retried after reconnection. Never
            // reclassify the completed acquisition merely because cleanup waits.
            if self.cleanup(&job).await.is_err() {
                let _ = self.store.defer_publication_cleanup(&job.id).await;
            }
        }
        Ok(())
    }
    /// Finish a previously published set without requiring a provider or network.
    pub async fn recover_publication(&self, job: &Job) -> Result<bool> {
        let Some(journal) = self.store.publication(&job.id).await? else {
            return Ok(false);
        };
        let publication: Publication =
            serde_json::from_value(journal).map_err(|_| AcquisitionError::Manifest)?;
        let expected: BTreeSet<_> = final_outputs(&job.plan)
            .into_iter()
            .map(|name| format!("{}/{name}", job.plan.final_relative_path))
            .collect();
        let actual: BTreeSet<_> = publication
            .artifacts
            .iter()
            .map(|a| a.relative_path.clone())
            .collect();
        if publication.final_path != job.plan.final_relative_path
            || actual != expected
            || actual.len() != publication.artifacts.len()
            || publication.artifacts.iter().any(|a| a.job_id != job.id)
        {
            return Err(AcquisitionError::Manifest);
        }
        let destination = self.store.destination(&job.destination_id).await?;
        if !destination.available {
            return Err(AcquisitionError::Destination);
        }
        let root = self.store.destination_root(&job.destination_id).await?;
        match root.directory(&publication.final_path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        verify_publication(&root, &publication).await?;
        self.store.complete(&job.id, &publication.artifacts).await?;
        self.cleanup(job).await?;
        Ok(true)
    }
    pub async fn execute(
        &self,
        job: &Job,
        grants: &[HostGrant],
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.execute_inner(job, grants, cancel, None, None).await
    }
    pub async fn execute_media(
        &self,
        job: &Job,
        grants: &[HostGrant],
        media: &omd_media::Media,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.execute_inner(job, grants, cancel, None, Some(media))
            .await
    }
    async fn execute_inner(
        &self,
        job: &Job,
        grants: &[HostGrant],
        cancel: &CancellationToken,
        interrupt: Option<Boundary>,
        media: Option<&omd_media::Media>,
    ) -> Result<()> {
        if self.recover_publication(job).await? {
            return Ok(());
        }
        let destination = self.store.destination(&job.destination_id).await?;
        if !destination.available {
            return Err(AcquisitionError::Destination);
        }
        let root = self.store.destination_root(&job.destination_id).await?;
        safe_relative(&job.plan.final_relative_path)?;
        let staging_name = format!(".omd-stage-v2-{}", job.id);
        let staging = private_stage(&root, &staging_name, &job.id)?;
        if let Some(selection) = &job.plan.media {
            let media = media.ok_or_else(|| {
                AcquisitionError::Media(Problem {
                    code: "media_tools_unavailable".into(),
                    message: "Restore the approved media tools to continue this acquisition."
                        .into(),
                    retryable: false,
                    actions: vec!["restore_tool".into()],
                })
            })?;
            let native = match staging.create_directory("native", true) {
                Ok(root) => root,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    staging.directory("native")?
                }
                Err(e) => return Err(e.into()),
            };
            let work = std::path::Path::new(&destination.root)
                .join(&staging_name)
                .join("native");
            let fingerprint = media_fingerprint(&job.plan)?;
            let saved = self
                .store
                .read_checkpoint(&job.id, "__native_media", &fingerprint)
                .await?;
            let saved: Option<BTreeMap<String, (u64, String)>> =
                saved.and_then(|v| serde_json::from_value(v).ok());
            let verified = saved.as_ref().is_some_and(|saved| {
                saved.len() == job.plan.outputs.len()
                    && job.plan.outputs.iter().all(|output| {
                        saved.get(&output.id).is_some_and(|expected| {
                            native
                                .hash(&output.relative_path)
                                .is_ok_and(|actual| &actual == expected)
                        })
                    })
            });
            if !verified {
                // yt-dlp can leave a truncated final container after a canceled
                // FFmpeg process. Discard only unverified final names in this
                // owned stage; native .part and fragment checkpoints survive.
                for output in &job.plan.outputs {
                    match native.remove_file(&output.relative_path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                let (progress, mut updates) = tokio::sync::watch::channel(serde_json::Value::Null);
                let download = media.download(
                    omd_media::Download {
                        plan: &job.plan,
                        grants,
                        work: &work,
                        progress,
                    },
                    cancel,
                );
                tokio::pin!(download);
                let mut receiving = true;
                let mut progress_state = media_progress::Progress::load(
                    &self.store,
                    job,
                    &fingerprint,
                    &selection.format_ids,
                )
                .await?;
                loop {
                    tokio::select! {
                        result=&mut download=>{result.map_err(AcquisitionError::Media)?;break;},
                        changed=updates.changed(),if receiving=>{
                            if changed.is_err(){receiving=false;continue;}
                            let value=updates.borrow_and_update().clone();
                            if progress_state.observe(&value){progress_state.persist(&self.store,job,&fingerprint).await?;}
                        }
                    }
                }
                // The download completion and its last watch update may become
                // ready together. Drain that final value before recording inputs.
                let value = updates.borrow_and_update().clone();
                if progress_state.observe(&value) {
                    progress_state
                        .persist(&self.store, job, &fingerprint)
                        .await?;
                }
                let mut checksums = BTreeMap::new();
                for output in &job.plan.outputs {
                    let file = native.open_existing_read_write(&output.relative_path)?;
                    file.sync_all()?;
                    checksums.insert(output.id.clone(), omd_files::hash_file(file)?);
                }
                native.sync()?;
                self.store
                    .checkpoint(
                        &job.id,
                        "__native_media",
                        &fingerprint,
                        &serde_json::to_value(checksums).map_err(|_| AcquisitionError::Manifest)?,
                    )
                    .await?;
            }
            boundary(Boundary::TransferVerified, interrupt)?;
        } else {
            for output in &job.plan.outputs {
                canceled(cancel)?;
                self.store.destination_root(&job.destination_id).await?;
                self.transfer(job, output, grants, &staging, cancel).await?;
                boundary(Boundary::TransferVerified, interrupt)?;
            }
        }
        self.store
            .transition(&job.id, &["transferring"], "verifying", None)
            .await?;
        canceled(cancel)?;
        match staging.remove_directory("publish") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let publish = staging.create_directory("publish", true)?;
        let metadata = comic_info(&job.plan);
        // Compression and hashing run off the async reactor. Cancellation is checked
        // between files; the task is always awaited before staging ownership ends.
        let plan = job.plan.clone();
        let source = staging.try_clone()?;
        let target = publish.try_clone()?;
        let stop = cancel.clone();
        tokio::task::spawn_blocking(move || {
            assemble(&plan, &source, &target, &metadata, &stop, interrupt)
        })
        .await
        .map_err(|_| AcquisitionError::Integrity)??;
        boundary(Boundary::AssemblyComplete, interrupt)?;
        publish.write_new("provenance.json",&serde_json::to_vec_pretty(&serde_json::json!({"schema":"omd:provenance@2","job_id":job.id,"source":job.plan.release.reference,"url":job.plan.release.canonical_url,"revision":job.plan.release.revision,"provider_digest":job.plan.provider_digest,"recipe":job.plan.recipe,"provider_metadata":{"collection":job.plan.collection,"release":job.plan.release},"user_overrides":job.plan.metadata})).map_err(|_|AcquisitionError::Manifest)?)?;
        let mut artifacts = vec![];
        for name in final_outputs(&job.plan) {
            let (size, hash) = publish.hash(&name)?;
            let media = if name.ends_with(".cbz") {
                "application/vnd.comicbook+zip"
            } else if name.ends_with(".xml") {
                "application/xml"
            } else if name.ends_with(".json") {
                "application/json"
            } else {
                job.plan
                    .outputs
                    .iter()
                    .find(|o| o.relative_path == name)
                    .and_then(|o| o.media_type.as_deref())
                    .ok_or(AcquisitionError::Manifest)?
            };
            artifacts.push(Artifact {
                id: omd_store::id("artifact"),
                job_id: job.id.clone(),
                relative_path: format!("{}/{name}", job.plan.final_relative_path),
                size,
                sha256: hash,
                media_type: media.into(),
                status: FileStatus::Present,
            });
        }
        publish.sync()?;
        drop(publish);
        let publication = Publication {
            final_path: job.plan.final_relative_path.clone(),
            artifacts,
        };
        self.store
            .journal_publication(
                &job.id,
                &serde_json::to_value(&publication).map_err(|_| AcquisitionError::Manifest)?,
            )
            .await?;
        boundary(Boundary::Journaled, interrupt)?;
        canceled(cancel)?;
        self.store
            .transition(&job.id, &["verifying"], "publishing", None)
            .await?;
        // Publishing is a short commit section. Pause/cancel requests must wait for
        // its recorded outcome instead of reporting a false canceled state.
        self.store.destination_root(&job.destination_id).await?;
        staging
            .publish("publish", &root, &job.plan.final_relative_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    AcquisitionError::Collision
                } else {
                    AcquisitionError::Io(e)
                }
            })?;
        boundary(Boundary::Published, interrupt)?;
        verify_publication(&root, &publication).await?;
        self.store.complete(&job.id, &publication.artifacts).await?;
        boundary(Boundary::Recorded, interrupt)?;
        // Only discard resumable sources after the durable acquisition record exists.
        drop(staging);
        self.cleanup(job).await?;
        Ok(())
    }
    async fn transfer(
        &self,
        job: &Job,
        output: &LogicalOutput,
        grants: &[HostGrant],
        stage: &Root,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let Locator::Http {
            url,
            permission,
            headers,
            credential_profile,
        } = &output.locator
        else {
            return Err(AcquisitionError::Recipe);
        };
        let session = self
            .network
            .session(
                &job.plan.release.reference.provider,
                credential_profile.as_deref(),
                grants,
            )
            .await?;
        let identity = serde_json::to_vec(&(
            &output.id,
            &output.role,
            &output.media_type,
            &output.expected_size,
            &output.expected_sha256,
        ))
        .map_err(|_| AcquisitionError::Manifest)?;
        let fingerprint = digest(&identity);
        let path = format!("{}.part", digest(output.id.as_bytes()));
        let saved = self
            .store
            .read_checkpoint(&job.id, &output.id, &fingerprint)
            .await?;
        let mut checkpoint: Checkpoint = saved
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| AcquisitionError::Manifest)?
            .unwrap_or(Checkpoint {
                prefix_sha256: None,
                bytes: 0,
                etag: None,
                total: None,
            });
        let mut hasher = match validated_prefix(stage, &path, &checkpoint, cancel).await? {
            Some(hash) => hash,
            None => {
                checkpoint.bytes = 0;
                checkpoint.total = None;
                checkpoint.prefix_sha256 = None;
                Sha256::new()
            }
        };
        if stage.read_file(&path).is_ok()
            && checkpoint.total == Some(checkpoint.bytes)
            && checkpoint.bytes > 0
        {
            if verify_image(stage, &path, output).is_ok() {
                return Ok(());
            }
            checkpoint = Checkpoint {
                prefix_sha256: None,
                bytes: 0,
                etag: None,
                total: None,
            };
        }
        if stage.read_file(&path).is_err() {
            checkpoint.bytes = 0;
        }
        let mut headers = headers.clone();
        if checkpoint.bytes > 0 && checkpoint.etag.is_some() {
            headers.insert("range".into(), format!("bytes={}-", checkpoint.bytes));
            headers.insert("if-range".into(), checkpoint.etag.clone().unwrap());
        } else {
            checkpoint.bytes = 0;
            hasher = Sha256::new();
        }
        let mut response = self
            .network
            .open_authenticated(
                &Request {
                    url: url.clone(),
                    permission: permission.clone(),
                    method: "GET".into(),
                    headers,
                    body: String::new(),
                },
                grants,
                session.as_ref(),
                cancel,
            )
            .await?;
        if session.is_some() && matches!(response.status().as_u16(), 401 | 403) {
            return Err(
                omd_network::NetworkError::Credential(omd_credentials::Error::Expired).into(),
            );
        }
        let etag = response
            .headers()
            .get("etag")
            .and_then(|s| s.to_str().ok())
            .filter(|s| !s.starts_with("W/"))
            .map(str::to_owned);
        match response.status().as_u16() {
            200 => {
                if checkpoint.bytes > 0 && checkpoint.etag != etag {
                    return Err(AcquisitionError::Integrity);
                }
                checkpoint.bytes = 0;
                checkpoint.prefix_sha256 = None;
                hasher = Sha256::new();
                checkpoint.total = response.content_length();
            }
            206 => {
                if checkpoint.bytes == 0 || etag != checkpoint.etag {
                    return Err(AcquisitionError::Integrity);
                }
                let content = response
                    .headers()
                    .get("content-range")
                    .and_then(|s| s.to_str().ok())
                    .ok_or(AcquisitionError::Integrity)?;
                let (start, total) = parse_range(content)?;
                if start != checkpoint.bytes {
                    return Err(AcquisitionError::Integrity);
                }
                checkpoint.total = Some(total);
            }
            _ => return Err(AcquisitionError::Integrity),
        }
        if checkpoint.total.is_some_and(|n| n > 512 * 1024 * 1024)
            || output
                .expected_size
                .zip(checkpoint.total)
                .is_some_and(|(a, b)| a != b)
        {
            return Err(AcquisitionError::Integrity);
        }
        checkpoint.etag = etag;
        let mut file = tokio::fs::File::from_std(stage.open_resume(&path)?);
        file.set_len(checkpoint.bytes).await?;
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(checkpoint.bytes))
            .await?;
        self.store
            .checkpoint(
                &job.id,
                &output.id,
                &fingerprint,
                &serde_json::to_value(&checkpoint).map_err(|_| AcquisitionError::Manifest)?,
            )
            .await?;
        loop {
            let chunk = tokio::select! {_ = cancel.cancelled()=>return Err(AcquisitionError::Canceled),result=response.chunk()=>result.map_err(|_|AcquisitionError::Integrity)?};
            let Some(chunk) = chunk else { break };
            if checkpoint.bytes + chunk.len() as u64 > 512 * 1024 * 1024 {
                return Err(AcquisitionError::Integrity);
            }
            self.network.bandwidth.consume(chunk.len(), cancel).await?;
            file.write_all(&chunk).await?;
            file.sync_data().await?;
            hasher.update(&chunk);
            checkpoint.prefix_sha256 = Some(hex::encode(hasher.clone().finalize()));
            checkpoint.bytes += chunk.len() as u64;
            self.store
                .checkpoint(
                    &job.id,
                    &output.id,
                    &fingerprint,
                    &serde_json::to_value(&checkpoint).map_err(|_| AcquisitionError::Manifest)?,
                )
                .await?;
        }
        if checkpoint.total.is_some_and(|n| n != checkpoint.bytes) {
            return Err(AcquisitionError::Integrity);
        }
        checkpoint.total = Some(checkpoint.bytes);
        file.sync_all().await?;
        drop(file);
        verify_image(stage, &path, output)?;
        self.store
            .checkpoint(
                &job.id,
                &output.id,
                &fingerprint,
                &serde_json::to_value(checkpoint).map_err(|_| AcquisitionError::Manifest)?,
            )
            .await?;
        Ok(())
    }
}
/// Validate only the journaled prefix. A crash may have appended unjournaled
/// bytes; those are discarded on resume. Corrupt/truncated prefixes restart at
/// zero instead of extending holes or silently publishing changed image bytes.
async fn validated_prefix(
    stage: &Root,
    path: &str,
    checkpoint: &Checkpoint,
    cancel: &CancellationToken,
) -> Result<Option<Sha256>> {
    if checkpoint.bytes == 0
        || checkpoint.bytes > 512 * 1024 * 1024
        || checkpoint.prefix_sha256.is_none()
    {
        return Ok(None);
    }
    let file = match stage.read_file(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if file.metadata()?.len() < checkpoint.bytes {
        return Ok(None);
    }
    let mut file = tokio::fs::File::from_std(file).take(checkpoint.bytes);
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let count = tokio::select! {biased;_=cancel.cancelled()=>return Err(AcquisitionError::Canceled),n=file.read(&mut buffer)=>n?};
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok((Some(hex::encode(hash.clone().finalize())) == checkpoint.prefix_sha256).then_some(hash))
}
fn parse_range(value: &str) -> Result<(u64, u64)> {
    let value = value
        .strip_prefix("bytes ")
        .ok_or(AcquisitionError::Integrity)?;
    let (range, total) = value.split_once('/').ok_or(AcquisitionError::Integrity)?;
    let (start, end) = range.split_once('-').ok_or(AcquisitionError::Integrity)?;
    let start: u64 = start.parse().map_err(|_| AcquisitionError::Integrity)?;
    let end: u64 = end.parse().map_err(|_| AcquisitionError::Integrity)?;
    let total: u64 = total.parse().map_err(|_| AcquisitionError::Integrity)?;
    if start > end || end >= total {
        return Err(AcquisitionError::Integrity);
    }
    Ok((start, total))
}
fn canceled(token: &CancellationToken) -> Result<()> {
    if token.is_cancelled() {
        Err(AcquisitionError::Canceled)
    } else {
        Ok(())
    }
}
fn private_stage(root: &Root, path: &str, job: &str) -> Result<Root> {
    match root.create_directory(path, true) {
        Ok(stage) => {
            stage.write_new("owner", job.as_bytes())?;
            Ok(stage)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let stage = root.directory(path)?;
            let mut marker = Vec::new();
            stage
                .read_file("owner")?
                .take(256)
                .read_to_end(&mut marker)?;
            if marker != job.as_bytes() {
                return Err(AcquisitionError::Destination);
            }
            Ok(stage)
        }
        Err(e) => Err(e.into()),
    }
}
#[cfg(test)]
fn file_hash(path: &Path) -> Result<(u64, String)> {
    Ok(omd_files::hash_file(std::fs::File::open(path)?)?)
}
fn verify_image(root: &Root, path: &str, output: &LogicalOutput) -> Result<()> {
    let (size, hash) = root.hash(path)?;
    let mut header = [0; 16];
    let count = root.read_file(path)?.read(&mut header)?;
    if header[..count].starts_with(b"<!DOCTYPE")
        || header[..count].starts_with(b"<html")
        || header[..count].starts_with(b"<!doctype")
    {
        return Err(AcquisitionError::SourcePage);
    }
    if image_type(&header[..count]) != output.media_type.as_deref()
        || output.expected_size.is_some_and(|n| n != size)
        || output.expected_sha256.as_ref().is_some_and(|s| s != &hash)
    {
        return Err(AcquisitionError::Integrity);
    }
    Ok(())
}
async fn verify_publication(root: &Root, journal: &Publication) -> Result<()> {
    let root = root.try_clone()?;
    let journal = journal.clone();
    tokio::task::spawn_blocking(move || {
        for artifact in &journal.artifacts {
            let (size, hash) = root.hash(&artifact.relative_path)?;
            if size != artifact.size || hash != artifact.sha256 {
                return Err(AcquisitionError::Integrity);
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| AcquisitionError::Integrity)?
}
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn comic_info(plan: &Plan) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<ComicInfo><Title>{}</Title><Series>{}</Series><Number>{}</Number><Volume>{}</Volume><LanguageISO>{}</LanguageISO><Summary>{}</Summary><Web>{}</Web><PageCount>{}</PageCount></ComicInfo>\n",
        xml(plan.release_title()),
        xml(plan.collection_title()),
        xml(plan.chapter()),
        xml(plan.volume()),
        xml(plan.release.language.as_deref().unwrap_or("")),
        xml(plan.description().unwrap_or("")),
        xml(&plan.release.canonical_url),
        plan.outputs.len()
    )
}
fn assemble(
    plan: &Plan,
    stage: &Root,
    publish: &Root,
    metadata: &str,
    cancel: &CancellationToken,
    interrupt: Option<Boundary>,
) -> Result<()> {
    if plan.recipe == Recipe::OriginalImages {
        publish.write_new("metadata.json", &serde_json::to_vec_pretty(&serde_json::json!({"schema":"omd:image-metadata@2","title":plan.collection_title(),"source":plan.release.canonical_url,"published_at":plan.release.published_at,"summary":plan.collection.summary})).map_err(|_|AcquisitionError::Manifest)?)?;
    } else if plan.media.is_none() {
        publish.write_new("ComicInfo.xml", metadata.as_bytes())?;
    }
    if plan.media.is_some() {
        let native = stage.directory("native")?;
        publish.write_new("metadata.json",&serde_json::to_vec_pretty(&serde_json::json!({"schema":"omd:media-metadata@2","title":plan.release_title(),"description":plan.description(),"source":plan.release.canonical_url,"collection":plan.collection.canonical_url,"published_at":plan.release.published_at,"selection":plan.media})).map_err(|_|AcquisitionError::Manifest)?)?;
        let mut buffer = vec![0u8; 128 * 1024];
        for output in &plan.outputs {
            let mut source = native.read_file(&output.relative_path)?;
            let mut target = publish.create_new(&output.relative_path)?;
            loop {
                canceled(cancel)?;
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                target.write_all(&buffer[..count])?;
            }
            target.sync_all()?;
            boundary(Boundary::ArchiveMember, interrupt)?;
        }
        return Ok(());
    }
    if plan.recipe == Recipe::Cbz {
        let file = publish.create_new("chapter.cbz")?;
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for output in &plan.outputs {
            canceled(cancel)?;
            let source = format!("{}.part", digest(output.id.as_bytes()));
            verify_image(stage, &source, output)?;
            zip.start_file(&output.relative_path, options)?;
            std::io::copy(&mut stage.read_file(&source)?, &mut zip)?;
            boundary(Boundary::ArchiveMember, interrupt)?;
        }
        zip.start_file("ComicInfo.xml", options)?;
        zip.write_all(metadata.as_bytes())?;
        zip.finish()?.sync_all()?;
    } else if matches!(plan.recipe, Recipe::ImageFolder | Recipe::OriginalImages) {
        for output in &plan.outputs {
            canceled(cancel)?;
            let source = format!("{}.part", digest(output.id.as_bytes()));
            verify_image(stage, &source, output)?;
            let mut target = publish.create_new(&output.relative_path)?;
            std::io::copy(&mut stage.read_file(&source)?, &mut target)?;
            target.sync_all()?;
            boundary(Boundary::ArchiveMember, interrupt)?;
        }
    } else {
        return Err(AcquisitionError::Recipe);
    }
    Ok(())
}

fn media_fingerprint(plan: &Plan) -> Result<String> {
    Ok(digest(
        &serde_json::to_vec(&(
            &plan.media,
            &plan.recipe,
            plan.outputs
                .iter()
                .map(|o| (&o.id, &o.relative_path, &o.role, &o.media_type))
                .collect::<Vec<_>>(),
        ))
        .map_err(|_| AcquisitionError::Manifest)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap()
    }
    #[tokio::test]
    async fn raw_transfer_recovery_validates_prefixes_ranges_and_changed_expectations() {
        use futures_util::StreamExt;
        use std::io::{Seek, SeekFrom};
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };
        for mode in [
            "pause",
            "drop",
            "tail",
            "truncate",
            "corrupt",
            "weak_etag",
            "changed_etag",
            "changed_expectations",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let db = temp.path().join("db");
            let store = Store::open(&db).await.unwrap();
            let destination = store.add_destination("Fixture", temp.path()).await.unwrap();
            let mut data = vec![42u8; 192 * 1024];
            data[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
            let data = Arc::new(data);
            let mut plan = plan();
            plan.outputs.truncate(1);
            plan.outputs[0].expected_size = Some(data.len() as u64);
            store
                .enqueue(&plan, &destination.id, "raw", "raw", None)
                .await
                .unwrap();
            let job = store.claim().await.unwrap().unwrap();
            let root = store.destination_root(&destination.id).await.unwrap();
            let stage_name = format!(".omd-stage-v2-{}", job.id);
            let stage = private_stage(&root, &stage_name, &job.id).unwrap();
            let path = format!("{}.part", digest(job.plan.outputs[0].id.as_bytes()));
            let ranges = Arc::new(Mutex::new(Vec::new()));
            let calls = Arc::new(AtomicUsize::new(0));
            let response_data = data.clone();
            let seen = ranges.clone();
            let invocation = calls.clone();
            let network = Network::new(0).with_transfer_fixture(move |_, _, headers| {
                let call = invocation.fetch_add(1, Ordering::SeqCst);
                let range = headers.get("range").map(|s| s.to_str().unwrap().to_owned());
                seen.lock().unwrap().push(range.clone());
                let etag = if mode == "weak_etag" {
                    "W/\"v1\""
                } else if mode == "changed_etag" && call == 1 {
                    "\"v2\""
                } else {
                    "\"v1\""
                };
                let start = range
                    .as_deref()
                    .map(|s| {
                        s.strip_prefix("bytes=")
                            .unwrap()
                            .trim_end_matches('-')
                            .parse::<usize>()
                            .unwrap()
                    })
                    .unwrap_or(0);
                let mut response = http::Response::builder()
                    .status(if start > 0 { 206 } else { 200 })
                    .header("content-type", "image/png")
                    .header("etag", etag)
                    .header("content-length", (response_data.len() - start).to_string());
                if start > 0 {
                    response = response.header(
                        "content-range",
                        format!(
                            "bytes {}-{}/{}",
                            start,
                            response_data.len() - 1,
                            response_data.len()
                        ),
                    );
                }
                let body = if call == 0 {
                    reqwest::Body::wrap_stream(
                        futures_util::stream::iter([Ok::<_, std::io::Error>(
                            response_data[..65536].to_vec(),
                        )])
                        .chain(futures_util::stream::pending()),
                    )
                } else {
                    reqwest::Body::from(response_data[start..].to_vec())
                };
                Ok(response.body(body).unwrap())
            });
            let grants = vec![HostGrant {
                request_intervals: Default::default(),
                id: "images".into(),
                hosts: vec!["example.com".into()],
                methods: vec!["GET".into()],
                credential: false,
            }];
            let cancel = CancellationToken::new();
            let stop = cancel.clone();
            let transfer_store = store.clone();
            let transfer_network = network.clone();
            let transfer_job = job.clone();
            let transfer_stage = stage.try_clone().unwrap();
            let transfer_grants = grants.clone();
            let task = tokio::spawn(async move {
                Acquisition {
                    store: transfer_store,
                    network: transfer_network,
                }
                .transfer(
                    &transfer_job,
                    &transfer_job.plan.outputs[0],
                    &transfer_grants,
                    &transfer_stage,
                    &stop,
                )
                .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if store.job(&job.id).await.unwrap().bytes_done >= 65536 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            if mode == "pause" {
                cancel.cancel();
                assert!(matches!(
                    task.await.unwrap(),
                    Err(AcquisitionError::Canceled)
                ));
            } else {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            }
            assert_eq!(
                stage.read_file(&path).unwrap().metadata().unwrap().len(),
                65536
            );
            match mode {
                "tail" => {
                    let mut file = stage.open_resume(&path).unwrap();
                    file.seek(SeekFrom::End(0)).unwrap();
                    file.write_all(b"uncommitted-tail").unwrap();
                    file.sync_all().unwrap();
                }
                "truncate" => stage.open_resume(&path).unwrap().set_len(100).unwrap(),
                "corrupt" => {
                    let mut file = stage.open_resume(&path).unwrap();
                    file.seek(SeekFrom::Start(100)).unwrap();
                    file.write_all(b"changed").unwrap();
                    file.sync_all().unwrap();
                }
                _ => {}
            }
            store.pool.close().await;
            let store = Store::open(&db).await.unwrap();
            store.recover().await.unwrap();
            let mut job = store.claim().await.unwrap().unwrap();
            if mode == "changed_expectations" {
                job.plan.outputs[0].expected_sha256 = Some(digest(data.as_slice()));
            }
            let acquisition = Acquisition {
                store: store.clone(),
                network,
            };
            let stop = CancellationToken::new();
            let result = acquisition
                .transfer(&job, &job.plan.outputs[0], &grants, &stage, &stop)
                .await;
            if mode == "changed_etag" {
                assert!(matches!(result, Err(AcquisitionError::Integrity)));
                assert_eq!(
                    stage.read_file(&path).unwrap().metadata().unwrap().len(),
                    65536
                );
                acquisition
                    .transfer(&job, &job.plan.outputs[0], &grants, &stage, &stop)
                    .await
                    .unwrap();
            } else {
                result.unwrap();
            }
            let seen = ranges.lock().unwrap().clone();
            assert_eq!(seen[0], None);
            assert_eq!(
                seen[1],
                if matches!(
                    mode,
                    "truncate" | "corrupt" | "weak_etag" | "changed_expectations"
                ) {
                    None
                } else {
                    Some("bytes=65536-".into())
                },
                "{mode}"
            );
            assert_eq!(
                stage.hash(&path).unwrap(),
                (data.len() as u64, digest(data.as_slice()))
            );
            if mode != "changed_expectations" {
                drop(stage);
                acquisition.execute(&job, &grants, &stop).await.unwrap();
                assert_eq!(store.job(&job.id).await.unwrap().state, JobState::Completed);
            }
        }
    }
    #[tokio::test]
    async fn interruption_boundaries_preserve_verified_inputs_and_recover_without_network() {
        for recipe in [Recipe::Cbz, Recipe::ImageFolder, Recipe::OriginalImages] {
            for stop in [
                Boundary::TransferVerified,
                Boundary::ArchiveMember,
                Boundary::AssemblyComplete,
                Boundary::Journaled,
                Boundary::Published,
                Boundary::Recorded,
            ] {
                let temp = tempfile::tempdir().unwrap();
                let database = temp.path().join("db");
                let store = Store::open(&database).await.unwrap();
                let dest = store.add_destination("Files", temp.path()).await.unwrap();
                let mut plan = plan();
                plan.recipe = recipe;
                if recipe == Recipe::OriginalImages {
                    plan.collection.kind = CollectionKind::Item;
                    plan.collection.summary = Some(serde_json::from_value(serde_json::json!({"image":{"release_id":plan.release.reference.id,"count":plan.outputs.len(),"width":1200,"height":900},"tags":["landscape"]})).unwrap());
                }
                plan.metadata.collection.title = Some("My & series".into());
                plan.metadata.release.title = Some("Special <chapter>".into());
                plan.metadata.release.chapter = Some("12.5a".into());
                plan.metadata.collection.description = Some("A personal description".into());
                store
                    .enqueue(&plan, &dest.id, "intent", "intent", None)
                    .await
                    .unwrap();
                let job = store.claim().await.unwrap().unwrap();
                let root = store.destination_root(&dest.id).await.unwrap();
                let stage_name = format!(".omd-stage-v2-{}", job.id);
                let stage = private_stage(&root, &stage_name, &job.id).unwrap();
                for output in &job.plan.outputs {
                    let bytes = b"\x89PNG\r\n\x1a\nfixture";
                    stage
                        .write_new(&format!("{}.part", digest(output.id.as_bytes())), bytes)
                        .unwrap();
                    let fingerprint = digest(
                        &serde_json::to_vec(&(
                            &output.id,
                            &output.role,
                            &output.media_type,
                            &output.expected_size,
                            &output.expected_sha256,
                        ))
                        .unwrap(),
                    );
                    store.checkpoint(&job.id, &output.id, &fingerprint, &serde_json::json!({"bytes": bytes.len(), "total": bytes.len(), "etag":"strong","prefix_sha256":digest(bytes)})).await.unwrap();
                }
                let acquisition = Acquisition {
                    store: store.clone(),
                    network: Network::new(0),
                };
                assert!(
                    acquisition
                        .execute_inner(&job, &[], &CancellationToken::new(), Some(stop), None)
                        .await
                        .is_err(),
                    "{recipe:?} {stop:?}"
                );
                // The source bytes remain until the durable acquisition record exists.
                assert!(
                    stage
                        .read_file(&format!(
                            "{}.part",
                            digest(job.plan.outputs[0].id.as_bytes())
                        ))
                        .is_ok()
                );
                // A simulated process interruption must release its fixture
                // handles too; Windows correctly prevents deleting an open stage.
                drop(stage);
                drop(acquisition);
                store.pool.close().await;
                let store = Store::open(&database).await.unwrap();
                store.recover().await.unwrap();
                if let Some(recovered) = store.claim().await.unwrap() {
                    Acquisition {
                        store: store.clone(),
                        network: Network::new(0),
                    }
                    .execute(&recovered, &[], &CancellationToken::new())
                    .await
                    .unwrap();
                }
                Acquisition {
                    store: store.clone(),
                    network: Network::new(0),
                }
                .cleanup_completed()
                .await
                .unwrap();
                assert!(root.directory(&stage_name).is_err());
                assert_eq!(store.job(&job.id).await.unwrap().state, JobState::Completed);
                let artifacts = store.artifact_page(&job.id, None, 200).await.unwrap().items;
                assert_eq!(artifacts.len(), final_outputs(&job.plan).len());
                assert!(
                    artifacts
                        .iter()
                        .all(|a| matches!(a.status, FileStatus::Present))
                );
                assert_eq!(
                    store.jobs("", None, None, 100).await.unwrap().items.len(),
                    1
                );
                let published = temp.path().join(&job.plan.final_relative_path);
                if recipe == Recipe::OriginalImages {
                    assert!(!published.join("ComicInfo.xml").exists());
                    let metadata: serde_json::Value = serde_json::from_slice(
                        &std::fs::read(published.join("metadata.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(metadata["schema"], "omd:image-metadata@2");
                    assert_eq!(metadata["summary"]["tags"][0], "landscape");
                } else {
                    let metadata =
                        std::fs::read_to_string(published.join("ComicInfo.xml")).unwrap();
                    assert!(metadata.contains("<Title>Special &lt;chapter&gt;</Title>"));
                    assert!(metadata.contains("<Series>My &amp; series</Series>"));
                    assert!(metadata.contains("<Number>12.5a</Number>"));
                    assert!(metadata.contains("<Summary>A personal description</Summary>"));
                }
                let provenance: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(published.join("provenance.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    provenance["provider_metadata"]["release"]["title"],
                    job.plan.release.title
                );
                assert_eq!(
                    provenance["user_overrides"]["release"]["title"],
                    "Special <chapter>"
                );
            }
        }
    }
    #[tokio::test]
    async fn media_publication_interruptions_reuse_identity_bound_verified_outputs() {
        for recipe in [
            Recipe::Mp4,
            Recipe::Mkv,
            Recipe::Webm,
            Recipe::M4a,
            Recipe::Mp3,
            Recipe::Opus,
        ] {
            for stop in [
                Boundary::TransferVerified,
                Boundary::ArchiveMember,
                Boundary::AssemblyComplete,
                Boundary::Journaled,
                Boundary::Published,
                Boundary::Recorded,
            ] {
                let temp = tempfile::tempdir().unwrap();
                let database = temp.path().join("db");
                let store = Store::open(&database).await.unwrap();
                let dest = store.add_destination("Files", temp.path()).await.unwrap();
                let mut plan = plan();
                plan.recipe = recipe;
                plan.outputs.truncate(1);
                plan.outputs[0].relative_path = format!("media.{}", recipe.extension());
                plan.outputs[0].role = "media".into();
                plan.outputs[0].locator = Locator::Media {
                    url: "https://example.com/video".into(),
                    permission: "media".into(),
                    credential_profile: None,
                };
                plan.media = Some(MediaSelection {
                    source_signature: "fixture".into(),
                    selected_height: None,
                    duration_ms: Some(1000),
                    format_ids: vec!["fixture-format".into()],
                    subtitles: vec![],
                    yt_dlp_digest: "fixture".into(),
                    ffmpeg_digest: "fixture".into(),
                    ffprobe_digest: "fixture".into(),
                    node_digest: None,
                });
                store
                    .enqueue(&plan, &dest.id, "intent", "intent", None)
                    .await
                    .unwrap();
                let job = store.claim().await.unwrap().unwrap();
                let root = store.destination_root(&dest.id).await.unwrap();
                let stage_name = format!(".omd-stage-v2-{}", job.id);
                let stage = private_stage(&root, &stage_name, &job.id).unwrap();
                let native = stage.create_directory("native", true).unwrap();
                // The adapter's verification gate is tested separately. At this
                // boundary the engine already owns an fsynced, hashed media set.
                native
                    .write_new(
                        &job.plan.outputs[0].relative_path,
                        b"verified fixture media",
                    )
                    .unwrap();
                let verified = BTreeMap::from([(
                    job.plan.outputs[0].id.clone(),
                    native.hash(&job.plan.outputs[0].relative_path).unwrap(),
                )]);
                drop(native);
                drop(stage);
                store
                    .checkpoint(
                        &job.id,
                        "__native_media",
                        &media_fingerprint(&job.plan).unwrap(),
                        &serde_json::to_value(verified).unwrap(),
                    )
                    .await
                    .unwrap();
                let media = omd_media::Media {
                    revoked: CancellationToken::new(),
                    tools: omd_media::Tools {
                        yt_dlp: omd_media::Tool {
                            path: temp.path().join("deliberately-absent-tool"),
                            sha256: "fixture".into(),
                            version: "fixture".into(),
                        },
                        node: None,
                        ffmpeg: None,
                        ffprobe: None,
                    },
                    network: Network::new(0),
                    work_root: temp.path().into(),
                };
                let acquisition = Acquisition {
                    store: store.clone(),
                    network: Network::new(0),
                };
                assert!(
                    acquisition
                        .execute_inner(
                            &job,
                            &[],
                            &CancellationToken::new(),
                            Some(stop),
                            Some(&media)
                        )
                        .await
                        .is_err(),
                    "{recipe:?} {stop:?}"
                );
                drop(acquisition);
                store.pool.close().await;
                let store = Store::open(&database).await.unwrap();
                store.recover().await.unwrap();
                let acquisition = Acquisition {
                    store: store.clone(),
                    network: Network::new(0),
                };
                if let Some(recovered) = store.claim().await.unwrap() {
                    acquisition
                        .execute_media(&recovered, &[], &media, &CancellationToken::new())
                        .await
                        .unwrap();
                }
                acquisition.cleanup_completed().await.unwrap();
                assert_eq!(store.job(&job.id).await.unwrap().state, JobState::Completed);
                assert!(root.directory(&stage_name).is_err());
                let artifacts = store.artifact_page(&job.id, None, 200).await.unwrap().items;
                assert_eq!(artifacts.len(), 3);
                assert!(
                    artifacts
                        .iter()
                        .all(|a| matches!(a.status, FileStatus::Present))
                );
            }
        }
    }
    #[tokio::test]
    async fn crash_after_publication_recovers_record_without_network_or_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        let (job, _) = store
            .enqueue(&plan(), &dest.id, "key", "request", None)
            .await
            .unwrap();
        let claimed = store.claim().await.unwrap().unwrap();
        assert_eq!(job.id, claimed.id);
        let final_dir = root.path().join(&job.plan.final_relative_path);
        std::fs::create_dir_all(&final_dir).unwrap();
        let mut artifacts = vec![];
        for name in final_outputs(&job.plan) {
            let path = final_dir.join(&name);
            std::fs::write(&path, job.id.as_bytes()).unwrap();
            let (size, sha256) = file_hash(&path).unwrap();
            artifacts.push(Artifact {
                id: omd_store::id("artifact"),
                job_id: job.id.clone(),
                relative_path: format!("{}/{name}", job.plan.final_relative_path),
                size,
                sha256,
                media_type: "application/octet-stream".into(),
                status: FileStatus::Present,
            });
        }
        let journal = Publication {
            final_path: job.plan.final_relative_path.clone(),
            artifacts,
        };
        store
            .journal_publication(&job.id, &serde_json::to_value(journal).unwrap())
            .await
            .unwrap();
        store.recover().await.unwrap();
        let job = store.claim().await.unwrap().unwrap();
        Acquisition {
            store: store.clone(),
            network: Network::new(0),
        }
        .execute(&job, &[], &CancellationToken::new())
        .await
        .unwrap();
        assert_eq!(store.job(&job.id).await.unwrap().state, JobState::Completed);
        assert_eq!(store.artifacts(&job.id).await.unwrap().len(), 3);
        assert_eq!(
            std::fs::read(final_dir.join("provenance.json")).unwrap(),
            job.id.as_bytes()
        );
    }
    #[test]
    fn preparation_rejects_empty_duplicate_missing_and_overflowing_page_selections() {
        let plan = plan();
        let original = ResolvedRelease {
            release: plan.release.clone(),
            collection: plan.collection.clone(),
            resources: plan
                .outputs
                .iter()
                .map(|o| Resource {
                    id: o.id.clone(),
                    position: o.position,
                    role: o.role.clone(),
                    media_type: o.media_type.clone(),
                    expected_size: o.expected_size,
                    expected_sha256: o.expected_sha256.clone(),
                    locator: o.locator.clone(),
                })
                .collect(),
            expires_at: None,
        };
        assert!(
            prepare(
                original.clone(),
                Recipe::Cbz,
                plan.policy.clone(),
                plan.provider_digest.clone()
            )
            .is_ok()
        );
        for variant in 0..5 {
            let mut changed = original.clone();
            match variant {
                0 => changed.resources.clear(),
                1 => changed.resources.push(changed.resources[0].clone()),
                2 => changed.resources[0].position = u32::MAX,
                3 => changed.resources[0].position = 19999,
                4 => changed.release.availability = Availability::Unavailable,
                _ => unreachable!(),
            }
            assert!(
                prepare(
                    changed,
                    Recipe::Cbz,
                    plan.policy.clone(),
                    plan.provider_digest.clone()
                )
                .is_err(),
                "variant {variant}"
            );
        }
        let mut french = original.release.clone();
        french.language = Some("fr".into());
        french.group = Some("Group B".into());
        let selected = SelectionPolicy {
            languages: vec!["en".into()],
            groups: vec!["Group A".into()],
            ..SelectionPolicy::default()
        };
        assert!(!selected.accepts(&french));
    }
    #[test]
    fn cbz_confirmation_includes_the_unarchived_sidecars() {
        assert_eq!(
            final_outputs(&plan()),
            vec!["chapter.cbz", "ComicInfo.xml", "provenance.json"]
        );
    }
    #[test]
    fn publication_never_overwrites_unrelated_files_or_directories() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("staged");
        let target = root.path().join("owned");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("data"), "new").unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("data"), "user changes").unwrap();
        let handle = Root::open(root.path()).unwrap();
        assert!(handle.publish("staged", &handle, "owned").is_err());
        assert_eq!(
            std::fs::read_to_string(target.join("data")).unwrap(),
            "user changes"
        );
        assert!(source.exists());
    }
    #[test]
    fn traversal_and_absolute_paths_are_rejected() {
        for path in ["../a", "/tmp/a", "a/../../b", ""] {
            assert!(safe_relative(path).is_err());
        }
    }
    #[test]
    fn media_extensions_follow_bytes() {
        assert_eq!(image_type(b"\x89PNG\r\n\x1a\n"), Some("image/png"));
        assert_eq!(image_type(b"<html>Error</html>"), None);
        assert_eq!(image_extension("image/webp").unwrap(), "webp");
    }
    #[test]
    fn range_validation_rejects_swapped_and_impossible_offsets() {
        assert_eq!(parse_range("bytes 10-19/20").unwrap(), (10, 20));
        for value in [
            "bytes 19-10/20",
            "bytes 0-20/20",
            "bytes 10-19/*",
            "garbage",
        ] {
            assert!(parse_range(value).is_err());
        }
    }
}
