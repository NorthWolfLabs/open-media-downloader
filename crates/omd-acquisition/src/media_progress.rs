use super::*;
/// yt-dlp may omit progress events for already complete streams after restart.
/// Keep their counters bound to the exact approved selection and tool identities.
pub(super) struct Progress {
    streams: BTreeMap<String, (u64, Option<u64>)>,
    allowed: BTreeSet<String>,
}
impl Progress {
    pub async fn load(
        store: &Store,
        job: &Job,
        fingerprint: &str,
        formats: &[String],
    ) -> Result<Self> {
        let allowed: BTreeSet<_> = formats.iter().cloned().collect();
        let mut streams: BTreeMap<String, (u64, Option<u64>)> = store
            .read_checkpoint(&job.id, "__native_progress", fingerprint)
            .await?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        streams.retain(|id, (done, total)| {
            allowed.contains(id)
                && *done <= 1024_u64.pow(4)
                && total.is_none_or(|n| n >= *done && n <= 1024_u64.pow(4))
        });
        Ok(Self { streams, allowed })
    }
    pub fn observe(&mut self, value: &serde_json::Value) -> bool {
        if let Some(streams) = value["streams"].as_object() {
            let mut changed = false;
            for stream in streams.values() {
                changed |= self.observe_one(stream);
            }
            return changed;
        }
        self.observe_one(value)
    }
    fn observe_one(&mut self, value: &serde_json::Value) -> bool {
        let (Some(id), Some(done)) = (value["format"].as_str(), value["done"].as_u64()) else {
            return false;
        };
        if !self.allowed.contains(id) || done > 1024_u64.pow(4) {
            return false;
        }
        let total = value["total"]
            .as_u64()
            .filter(|n| *n >= done && *n <= 1024_u64.pow(4));
        let changed = self.streams.get(id) != Some(&(done, total));
        self.streams.insert(id.into(), (done, total));
        changed
    }
    pub async fn persist(&self, store: &Store, job: &Job, fingerprint: &str) -> Result<()> {
        let done = self.streams.values().map(|(n, _)| n).sum();
        let total = if self.streams.len() == self.allowed.len() {
            self.streams
                .values()
                .map(|(_, n)| *n)
                .collect::<Option<Vec<_>>>()
                .map(|v| v.iter().sum())
        } else {
            None
        };
        store
            .checkpoint_progress(
                &job.id,
                "__native_progress",
                fingerprint,
                &serde_json::to_value(&self.streams).map_err(|_| AcquisitionError::Manifest)?,
                done,
                total,
            )
            .await?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn resumed_audio_preserves_the_completed_video_counter_and_new_selection_rejects_old_counts()
     {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let destination = store.add_destination("Files", root.path()).await.unwrap();
        let plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        store
            .enqueue(&plan, &destination.id, "progress", "progress", None)
            .await
            .unwrap();
        let job = store.claim().await.unwrap().unwrap();
        let formats = vec!["video".into(), "audio".into()];
        let mut progress = Progress::load(&store, &job, "approved-selection", &formats)
            .await
            .unwrap();
        assert!(progress.observe(&serde_json::json!({"streams":{
            "video":{"format":"video","done":200,"total":200},
            "audio":{"format":"audio","done":40,"total":100}
        }})));
        progress
            .persist(&store, &job, "approved-selection")
            .await
            .unwrap();
        assert_eq!(store.job(&job.id).await.unwrap().bytes_done, 240);
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        let mut progress = Progress::load(&store, &job, "approved-selection", &formats)
            .await
            .unwrap();
        assert!(!progress.observe(&serde_json::json!({"format":"unselected","done":999999})));
        progress.observe(&serde_json::json!({"format":"audio","done":70,"total":100}));
        progress
            .persist(&store, &job, "approved-selection")
            .await
            .unwrap();
        let current = store.job(&job.id).await.unwrap();
        assert_eq!(current.bytes_done, 270);
        assert_eq!(current.bytes_total, Some(300));
        assert!(
            Progress::load(&store, &job, "different-selection", &formats)
                .await
                .unwrap()
                .streams
                .is_empty()
        );
    }
}
