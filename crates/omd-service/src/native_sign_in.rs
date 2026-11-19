//! Native sign-in windows: the engine launches its `omd-signin` helper, which
//! shows the source's sign-in page in the operating system's own web view and
//! returns one credential-scoped session. Unlike the isolated browser, the page
//! runs with the person's ordinary network access; only state for the source's
//! credential grants is kept, and the engine validates it again before saving.
use omd_credentials::native_sign_in::{Outcome, Request};
use omd_domain::Problem;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Largest helper reply: one session within the credential size limit.
const MAX_REPLY: u64 = 2 * 1024 * 1024;

pub(crate) enum State {
    Open,
    Completed(omd_credentials::Session),
    Closed,
    Expired,
    Failed(Problem),
}
pub(crate) struct Window {
    state: Arc<Mutex<State>>,
    stop: CancellationToken,
    closed: CancellationToken,
}
impl Drop for Window {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
fn problem(code: &str, message: &str, action: &str) -> Problem {
    Problem {
        code: code.into(),
        message: message.into(),
        retryable: false,
        actions: vec![action.into()],
    }
}
pub(crate) fn unavailable(reason: &str) -> Problem {
    match reason {
        "display_unavailable" => problem(
            "native_sign_in_unavailable",
            "OMD can't open a sign-in window because no desktop session is available to the engine. Sign in on a computer with a desktop, or import the account instead.",
            "import_account",
        ),
        "missing" => problem(
            "native_sign_in_unavailable",
            "The sign-in window component is missing. Reinstall OMD, or import the account instead.",
            "import_account",
        ),
        _ => problem(
            "native_sign_in_unavailable",
            "The system web view needed for the sign-in window is unavailable. On Windows, install the Microsoft Edge WebView2 Runtime. On Linux, install the WebKitGTK 4.1 runtime. Or import the account instead.",
            "import_account",
        ),
    }
}
pub(crate) fn closed_problem() -> Problem {
    problem(
        "sign_in_closed",
        "The sign-in window was closed before signing in finished. Start sign-in again.",
        "restart_sign_in",
    )
}
pub(crate) fn expired_problem() -> Problem {
    problem(
        "sign_in_expired",
        "This sign-in session is no longer available. Start sign-in again.",
        "restart_sign_in",
    )
}
/// Window titles come from untrusted source metadata: keep them short and printable.
pub(crate) fn title(source_name: &str) -> String {
    let name: String = source_name
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    let name = name.trim();
    if name.is_empty() {
        "Sign in".into()
    } else {
        format!("Sign in to {name}")
    }
}

impl Window {
    /// `request.data_directory` is replaced with a new private folder.
    pub(crate) async fn launch(
        helper: &Path,
        work_root: &Path,
        mut request: Request,
        shutdown: &CancellationToken,
    ) -> Result<Self, Problem> {
        if !helper.is_file() {
            return Err(unavailable("missing"));
        }
        // Private runtime files (WebView2 keeps its user-data folder here).
        let work = tempfile::Builder::new()
            .prefix("signin-")
            .tempdir_in(work_root)
            .map_err(|_| unavailable("missing"))?;
        request.data_directory = work.path().into();
        let timeout = Duration::from_secs(request.timeout_seconds);
        let input = serde_json::to_vec(&request).map_err(|_| unavailable("missing"))?;
        Request::parse(&input).map_err(|_| unavailable("missing"))?;
        let mut child = tokio::process::Command::new(helper)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| unavailable("webview_unavailable"))?;
        let mut stdin = child.stdin.take().ok_or_else(|| unavailable("missing"))?;
        stdin
            .write_all(&input)
            .await
            .map_err(|_| unavailable("webview_unavailable"))?;
        drop(stdin);
        let mut stdout = child.stdout.take().ok_or_else(|| unavailable("missing"))?;
        let state = Arc::new(Mutex::new(State::Open));
        let stop = shutdown.child_token();
        let closed = CancellationToken::new();
        let (task_state, task_stop, task_closed) = (state.clone(), stop.clone(), closed.clone());
        tokio::spawn(async move {
            // Owning the child here means cancellation or timeout drops it,
            // and kill_on_drop ends the window.
            let read = async move {
                let mut reply = Zeroizing::new(Vec::new());
                let _ = (&mut stdout)
                    .take(MAX_REPLY + 1)
                    .read_to_end(&mut reply)
                    .await;
                let _ = child.wait().await;
                reply
            };
            // The helper enforces the same limit; this bounds a stuck process.
            let result = tokio::select! {
                _ = task_stop.cancelled() => None,
                _ = tokio::time::sleep(timeout + Duration::from_secs(30)) => Some(State::Expired),
                reply = read => Some(if reply.len() as u64 > MAX_REPLY {
                    State::Failed(unavailable("webview_unavailable"))
                } else {
                    match serde_json::from_slice::<Outcome>(&reply) {
                        Ok(Outcome::Completed { session }) => State::Completed(session),
                        Ok(Outcome::Closed) => State::Closed,
                        Ok(Outcome::Expired) => State::Expired,
                        Ok(Outcome::Failed { code }) => State::Failed(unavailable(&code)),
                        // A helper that cannot load its web-view libraries
                        // exits before writing a reply.
                        Err(_) => State::Failed(unavailable("webview_unavailable")),
                    }
                }),
            };
            if let Some(result) = result {
                *task_state.lock().expect("sign-in state") = result;
            }
            // Removing the work folder also removes any web-view runtime files.
            drop(work);
            task_closed.cancel();
        });
        Ok(Self {
            state,
            stop,
            closed,
        })
    }
    pub(crate) fn cancel(&self) {
        self.stop.cancel();
    }
    pub(crate) async fn closed(&self) {
        self.closed.cancelled().await;
    }
    /// `Ok(true)` once a session is ready to save; terminal failures are problems.
    pub(crate) fn ready(&self) -> Result<bool, Problem> {
        match &*self.state.lock().expect("sign-in state") {
            State::Open => Ok(false),
            State::Completed(_) => Ok(true),
            State::Closed => Err(closed_problem()),
            State::Expired => Err(expired_problem()),
            State::Failed(problem) => Err(problem.clone()),
        }
    }
    pub(crate) fn session(&self) -> Option<omd_credentials::Session> {
        match &*self.state.lock().expect("sign-in state") {
            State::Completed(session) => Some(session.clone()),
            _ => None,
        }
    }
}
