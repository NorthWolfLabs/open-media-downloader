//! Ordered, bounded request/reply transport for an engine-owned native adapter.
//! A failed exchange destroys the session; late responses cannot cross requests.
use super::{Error, Group, Policy, Result, configured_command};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{ChildStdin, ChildStdout},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub struct Session {
    child: Group,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    diagnostic: Arc<Mutex<Vec<u8>>>,
    diagnostic_task: JoinHandle<()>,
    budget: CancellationToken,
    closed: bool,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.diagnostic_task.abort();
    }
}
impl Session {
    pub fn start(
        policy: &Policy,
        args: &[String],
        environment: &BTreeMap<String, String>,
        browser: bool,
    ) -> Result<Self> {
        let mut child = configured_command(policy, args, environment, browser)?.spawn()?;
        let input = child.0.stdin.take().ok_or(Error::Start)?;
        let output = BufReader::new(child.0.stdout.take().ok_or(Error::Start)?);
        let mut stderr = child.0.stderr.take().ok_or(Error::Start)?;
        let diagnostic = Arc::new(Mutex::new(Vec::new()));
        let target = diagnostic.clone();
        let budget = CancellationToken::new();
        let budget_signal = budget.clone();
        let diagnostic_task = tokio::spawn(async move {
            let mut bytes = [0u8; 4096];
            loop {
                let size = match stderr.read(&mut bytes).await {
                    Ok(0) => break,
                    Ok(size) => size,
                    Err(_) => {
                        budget_signal.cancel();
                        break;
                    }
                };
                let mut collected = target.lock().unwrap_or_else(|e| e.into_inner());
                if collected.len() + size > 65536 {
                    budget_signal.cancel();
                    break;
                }
                collected.extend_from_slice(&bytes[..size]);
            }
        });
        Ok(Self {
            child,
            input,
            output,
            diagnostic,
            diagnostic_task,
            budget,
            closed: false,
        })
    }
    pub async fn exchange(
        &mut self,
        request: &[u8],
        limit: usize,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>> {
        if self.closed {
            return Err(Error::Failed);
        }
        if request.len() > 2 * 1024 * 1024
            || request.contains(&b'\n')
            || limit == 0
            || limit > 4 * 1024 * 1024
            || timeout > Duration::from_secs(180)
        {
            return Err(Error::Invalid);
        }
        let result = {
            let operation = async {
                self.input
                    .write_all(request)
                    .await
                    .map_err(|_| Error::Failed)?;
                self.input
                    .write_all(b"\n")
                    .await
                    .map_err(|_| Error::Failed)?;
                self.input.flush().await.map_err(|_| Error::Failed)?;
                let mut result = Vec::new();
                loop {
                    let buffered = self.output.fill_buf().await.map_err(|_| Error::Failed)?;
                    if buffered.is_empty() {
                        return Err(Error::Failed);
                    }
                    let newline = buffered.iter().position(|byte| *byte == b'\n');
                    let count = newline.map_or(buffered.len(), |i| i + 1);
                    if result.len() + count > limit {
                        return Err(Error::Budget);
                    }
                    result.extend_from_slice(&buffered[..count]);
                    self.output.consume(count);
                    if newline.is_some() {
                        result.pop();
                        return Ok(result);
                    }
                }
            };
            tokio::select! {
                biased;
                _=cancel.cancelled()=>Err(Error::Canceled),
                _=self.budget.cancelled()=>Err(Error::Budget),
                value=tokio::time::timeout(timeout,operation)=>value.unwrap_or(Err(Error::Budget)),
            }
        };
        if result.is_err() {
            self.close().await;
            let diagnostic = self.diagnostic.lock().unwrap_or_else(|e| e.into_inner());
            if diagnostic
                .windows(b"OMD elevated engine".len())
                .any(|v| v == b"OMD elevated engine")
            {
                return Err(Error::Elevated);
            }
            if diagnostic
                .windows(b"OMD resource budget exceeded".len())
                .any(|v| v == b"OMD resource budget exceeded")
            {
                return Err(Error::Budget);
            }
            if diagnostic.starts_with(b"OMD ")
                || diagnostic
                    .windows(b"OMD resource accounting unavailable".len())
                    .any(|v| v == b"OMD resource accounting unavailable")
            {
                return Err(Error::Unavailable);
            }
        }
        result
    }
    pub async fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        #[cfg(unix)]
        if let Some(id) = self.child.1.take()
            && self.child.0.id() == Some(id)
        {
            unsafe {
                libc::kill(-(id as i32), libc::SIGKILL);
            }
        }
        if self.child.close().await.is_err() {
            self.budget.cancel();
        }
        if tokio::time::timeout(Duration::from_millis(100), &mut self.diagnostic_task)
            .await
            .is_err()
        {
            self.diagnostic_task.abort();
        }
    }
}
