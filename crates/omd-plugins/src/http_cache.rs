//! Brief public-metadata reuse across collection/details/chapter requests.
//! Authentication and acquisition resolution never use this cache.
use crate::{PluginError, Result};
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
type Slot = Arc<Mutex<Option<(Instant, Value)>>>;
#[derive(Clone, Default)]
pub(crate) struct HttpCache(Arc<Mutex<VecDeque<(String, Slot)>>>);
impl HttpCache {
    pub async fn read<F, Fut>(
        &self,
        key: String,
        cancel: &CancellationToken,
        fetch: F,
    ) -> Result<Value>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Value>>,
    {
        self.read_if(key, cancel, fetch, |result| {
            result.get("status").and_then(Value::as_u64) == Some(200)
                && result
                    .get("body")
                    .and_then(Value::as_str)
                    .is_some_and(|body| body.len() <= 2 * 1024 * 1024)
        })
        .await
    }
    pub async fn read_metadata<F, Fut>(
        &self,
        key: String,
        cancel: &CancellationToken,
        fetch: F,
    ) -> Result<Value>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Value>>,
    {
        self.read_if(key, cancel, fetch, |value| {
            serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= 2 * 1024 * 1024)
        })
        .await
    }
    async fn read_if<F, Fut, Accept>(
        &self,
        key: String,
        cancel: &CancellationToken,
        fetch: F,
        accept: Accept,
    ) -> Result<Value>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Value>>,
        Accept: FnOnce(&Value) -> bool,
    {
        let slot = {
            let mut entries = self.0.lock().await;
            if let Some((_, slot)) = entries.iter().find(|(k, _)| k == &key) {
                slot.clone()
            } else {
                let slot = Arc::new(Mutex::new(None));
                entries.push_back((key, slot.clone()));
                while entries.len() > 8 {
                    entries.pop_front();
                }
                slot
            }
        };
        let mut cached = tokio::select! {_ = cancel.cancelled()=>return Err(PluginError::Canceled),v=slot.lock()=>v};
        if let Some((at, value)) = &*cached
            && at.elapsed() < Duration::from_secs(30)
        {
            return Ok(value.clone());
        }
        let result = fetch().await?;
        if accept(&result) {
            *cached = Some((Instant::now(), result.clone()));
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn metadata_reuses_success_but_expires_and_retries_errors() {
        let cache = HttpCache::default();
        let cancel = CancellationToken::new();
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(serde_json::json!({"kind":"video","id":"sample","title":"Sample"}))
        };
        let (first, second) = tokio::join!(
            cache.read_metadata("tool-provider-request".into(), &cancel, fetch),
            cache.read_metadata("tool-provider-request".into(), &cancel, fetch)
        );
        assert_eq!(first.unwrap(), second.unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let slot = cache.0.lock().await[0].1.clone();
        slot.lock().await.as_mut().unwrap().0 = Instant::now() - Duration::from_secs(31);
        cache
            .read_metadata("tool-provider-request".into(), &cancel, fetch)
            .await
            .unwrap();
        cache
            .read_metadata("different-provider-request".into(), &cancel, fetch)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        for _ in 0..2 {
            assert!(
                cache
                    .read_metadata("failure".into(), &cancel, || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err(PluginError::Worker)
                    })
                    .await
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }
    #[tokio::test]
    async fn coalesces_successful_reads_and_retries_failures() {
        let cache = HttpCache::default();
        let cancel = CancellationToken::new();
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(serde_json::json!({"status":200,"body":"page"}))
        };
        let (first, second) = tokio::join!(
            cache.read("page".into(), &cancel, fetch),
            cache.read("page".into(), &cancel, fetch),
        );
        assert_eq!(first.unwrap(), second.unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for _ in 0..2 {
            cache
                .read("error".into(), &cancel, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(serde_json::json!({"status":503,"body":"retry"}))
                })
                .await
                .unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
