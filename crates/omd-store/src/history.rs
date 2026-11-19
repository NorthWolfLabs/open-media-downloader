use super::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AcquisitionStatus {
    pub reference: SourceRef,
    pub acquired_versions: i64,
    pub last_acquired_at: Option<String>,
    pub latest_job_id: Option<String>,
    #[serde(default)]
    pub file_state: Option<String>,
    #[serde(default)]
    pub saved_bytes: Option<u64>,
    #[serde(default)]
    pub source_revision: Option<String>,
}
impl Store {
    /// Complete-ledger lookup for a bounded, explicitly identified release page.
    /// This is acquisition history, independently of current file presence.
    pub async fn acquisition_status(
        &self,
        references: &[SourceRef],
    ) -> Result<Vec<AcquisitionStatus>> {
        if references.len() > 200
            || references.iter().any(|r| r.validate().is_err())
            || references
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != references.len()
        {
            return Err(StoreError::StateConflict);
        }
        let rows=sqlx::query("SELECT q.key AS position,COUNT(j.id) AS versions,MAX(j.updated_at) AS acquired_at, (SELECT h.id FROM jobs h WHERE json_extract(h.plan_json,'$.release.reference.provider')=json_extract(q.value,'$.provider') AND json_extract(h.plan_json,'$.release.reference.id')=json_extract(q.value,'$.id') AND h.state='completed' AND h.history_removed=0 ORDER BY h.updated_at DESC,h.id DESC LIMIT 1) AS latest_job_id FROM json_each(?) q LEFT JOIN jobs j ON json_extract(j.plan_json,'$.release.reference.provider')=json_extract(q.value,'$.provider') AND json_extract(j.plan_json,'$.release.reference.id')=json_extract(q.value,'$.id') AND j.state='completed' AND j.history_removed=0 GROUP BY q.key ORDER BY CAST(q.key AS INTEGER)").bind(serde_json::to_string(references)?).fetch_all(&self.pool).await?;
        let mut items: Vec<AcquisitionStatus> = rows
            .into_iter()
            .map(|row| AcquisitionStatus {
                reference: references[row.get::<i64, _>("position") as usize].clone(),
                acquired_versions: row.get("versions"),
                last_acquired_at: row.get("acquired_at"),
                latest_job_id: row.get("latest_job_id"),
                file_state: None,
                saved_bytes: None,
                source_revision: None,
            })
            .collect();
        for item in &mut items {
            let Some(id) = item.latest_job_id.as_deref() else {
                continue;
            };
            let job = self.job(id).await?;
            item.source_revision = job.plan.release.revision.clone();
            let artifacts: Vec<_> = self
                .artifacts(id)
                .await?
                .into_iter()
                .filter(|a| {
                    !matches!(
                        a.relative_path.rsplit('/').next(),
                        Some("ComicInfo.xml" | "provenance.json")
                    )
                })
                .collect();
            item.saved_bytes = Some(artifacts.iter().map(|a| a.size).sum());
            let root = self.destination_root(&job.destination_id).await.ok();
            // Presence is a cheap local metadata check. Source revisions come
            // from the provider; browsing never downloads or hashes remote media.
            item.file_state = Some(
                tokio::task::spawn_blocking(move || {
                    let Some(root) = root else {
                        return "destination_unavailable".to_owned();
                    };
                    if artifacts.is_empty() {
                        return "missing".to_owned();
                    }
                    let mut present = 0;
                    let mut modified = false;
                    for artifact in &artifacts {
                        match root
                            .read_file(&artifact.relative_path)
                            .and_then(|file| file.metadata())
                        {
                            Ok(meta) => {
                                present += 1;
                                modified |= meta.len() != artifact.size;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(_) => return "unavailable".to_owned(),
                        }
                    }
                    if present == 0 {
                        "missing"
                    } else if present != artifacts.len() {
                        "partial"
                    } else if modified {
                        "modified"
                    } else {
                        "present"
                    }
                    .to_owned()
                })
                .await
                .map_err(|e| StoreError::Migration(e.to_string()))?,
            );
        }
        Ok(items)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn presence_tracks_moved_files_without_discarding_history_or_source_revision() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let destination = store
            .add_destination("Downloads", temp.path())
            .await
            .unwrap();
        let mut plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        plan.release.revision = Some("provider-revision-1".into());
        let (job, _) = store
            .enqueue(&plan, &destination.id, "presence-test", "digest", None)
            .await
            .unwrap();
        std::fs::write(temp.path().join("chapter.cbz"), b"test").unwrap();
        store
            .complete(
                &job.id,
                &[Artifact {
                    id: "art-presence".into(),
                    job_id: job.id.clone(),
                    relative_path: "chapter.cbz".into(),
                    size: 4,
                    sha256: "unused-for-presence".into(),
                    media_type: "application/zip".into(),
                    status: FileStatus::Present,
                }],
            )
            .await
            .unwrap();
        let refs = [plan.release.reference];
        let status = store.acquisition_status(&refs).await.unwrap();
        assert_eq!(status[0].file_state.as_deref(), Some("present"));
        assert_eq!(status[0].saved_bytes, Some(4));
        assert_eq!(
            status[0].source_revision.as_deref(),
            Some("provider-revision-1")
        );
        std::fs::rename(
            temp.path().join("chapter.cbz"),
            temp.path().join("reader.cbz"),
        )
        .unwrap();
        let status = store.acquisition_status(&refs).await.unwrap();
        assert_eq!(status[0].file_state.as_deref(), Some("missing"));
        assert_eq!(status[0].acquired_versions, 1);
        assert!(temp.path().join("reader.cbz").exists());
    }
    #[tokio::test]
    async fn complete_history_lookup_is_namespaced_and_independent_of_pagination_or_missing_files()
    {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        let base: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let original = base.release.reference.clone();
        for n in 0..251 {
            let mut plan = base.clone();
            plan.release.reference.id = format!("id-{n}");
            plan.final_relative_path = format!("chapter-{n}");
            let (job, _) = store
                .enqueue(&plan, &dest.id, &format!("key-{n}"), "digest", None)
                .await
                .unwrap();
            store.complete(&job.id, &[]).await.unwrap();
        }
        let wanted = SourceRef {
            provider: original.provider.clone(),
            id: "id-0".into(),
        };
        let unrelated = SourceRef {
            provider: "another.website".into(),
            id: "id-0".into(),
        };
        let items = store
            .acquisition_status(&[wanted.clone(), unrelated])
            .await
            .unwrap();
        assert_eq!(items[0].acquired_versions, 1);
        assert_eq!(items[1].acquired_versions, 0);
        assert!(items[0].latest_job_id.is_some());
        assert!(items[1].latest_job_id.is_none());
        assert_eq!(
            store
                .job(items[0].latest_job_id.as_deref().unwrap())
                .await
                .unwrap()
                .plan
                .release
                .reference,
            wanted
        );
        assert!(
            store
                .acquisition_status(&[wanted.clone(), wanted.clone()])
                .await
                .is_err()
        );
        sqlx::query("UPDATE jobs SET history_removed=1 WHERE json_extract(plan_json,'$.release.reference.id')='id-0'").execute(&store.pool).await.unwrap();
        assert_eq!(
            store.acquisition_status(&[wanted]).await.unwrap()[0].acquired_versions,
            0
        );
    }
}
