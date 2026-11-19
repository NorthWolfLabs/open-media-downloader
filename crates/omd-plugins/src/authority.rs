use super::{PluginError, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
#[derive(Default)]
struct Scope {
    stop: CancellationToken,
    active: AtomicUsize,
    idle: Notify,
}
#[derive(Default)]
struct Authority {
    scope: Arc<Scope>,
    allowed: Option<BTreeSet<String>>,
}
#[derive(Clone, Default)]
pub(super) struct Registry(Arc<Mutex<BTreeMap<String, Authority>>>);
pub(super) struct Guard {
    scope: Arc<Scope>,
    pub stop: CancellationToken,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.scope.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.scope.idle.notify_waiters();
        }
    }
}
pub(super) fn denied() -> PluginError {
    PluginError::Source(omd_domain::Problem{code:"source_removed".into(),message:"This source's execution permission was removed. Review and reinstall its package to use it again.".into(),retryable:false,actions:vec!["install_source".into()]})
}
impl Registry {
    pub fn enter(&self, id: &str, digest: &str) -> Result<Guard> {
        let scope = {
            let mut entries = self.0.lock().unwrap();
            let entry = entries.entry(id.into()).or_default();
            if entry
                .allowed
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(digest))
            {
                return Err(denied());
            }
            entry.scope.clone()
        };
        scope.active.fetch_add(1, Ordering::SeqCst);
        Ok(Guard {
            stop: scope.stop.clone(),
            scope,
        })
    }
    pub fn restore(&self, id: &str, digest: &str) {
        let mut entries = self.0.lock().unwrap();
        let entry = entries.entry(id.into()).or_default();
        if entry.scope.stop.is_cancelled() {
            entry.scope = Arc::default();
        }
        entry
            .allowed
            .get_or_insert_with(BTreeSet::new)
            .insert(digest.into());
    }
    pub async fn revoke(&self, id: &str) -> Result<()> {
        let scope = {
            let mut entries = self.0.lock().unwrap();
            let entry = entries.entry(id.into()).or_default();
            entry.allowed = Some(BTreeSet::new());
            entry.scope.stop.cancel();
            entry.scope.clone()
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = scope.idle.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if scope.active.load(Ordering::SeqCst) == 0 {
                    return;
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| PluginError::Budget)
    }
}
