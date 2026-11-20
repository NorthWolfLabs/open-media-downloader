pub mod browsers;
mod catalog;
pub mod checks;
pub mod contract;
pub mod identity;
pub mod maintenance;
mod native_sign_in;
pub mod notifications;
pub mod presentation;
pub mod selections;
pub mod source_removals;
pub mod storage;
pub mod tools;
pub mod update;
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use omd_acquisition::Acquisition;
use omd_domain::*;
use omd_plugins::{Provider, Runtime};
use omd_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct App {
    pub browser_sessions: browsers::Sessions,
    pub source_changes: Arc<Mutex<()>>,
    pub notification_lock: Arc<Mutex<()>>,
    pub notification_adapter: std::path::PathBuf,
    /// Native sign-in window helper (`omd-signin`) next to the engine.
    pub sign_in_helper: std::path::PathBuf,
    pub store: Store,
    pub runtime: Runtime,
    pub acquisition: Acquisition,
    pub profile: PathBuf,
    pub token: String,
    pub admin_token: String,
    pub shutdown: CancellationToken,
    pub providers: Arc<RwLock<BTreeMap<String, Provider>>>,
    pub running: Arc<Mutex<BTreeMap<String, CancellationToken>>>,
    pub clients: Arc<Mutex<Clients>>,
}
/// One attached client: when it attached or last sent a heartbeat, and whether
/// it asked the engine to finish downloads after it leaves.
#[derive(Debug, Clone, Copy)]
pub struct Lease {
    pub seen: tokio::time::Instant,
    pub finish_downloads: bool,
}
impl Lease {
    pub fn live(&self) -> bool {
        self.seen.elapsed() < CLIENT_LEASE
    }
}
/// The attached clients, and what the last one to leave asked for.
#[derive(Debug, Default)]
pub struct Clients {
    pub leases: BTreeMap<String, Lease>,
    /// Whether the last client to leave (detached, or the most recently seen
    /// of the last leases to expire) asked for downloads to finish. False
    /// until a client leaves, so an engine nobody attached to stops as before.
    last_finishes_downloads: bool,
}
impl Clients {
    pub fn attach(&mut self, id: String, finish_downloads: bool) {
        self.leases.insert(
            id,
            Lease {
                seen: tokio::time::Instant::now(),
                finish_downloads,
            },
        );
    }
    /// Renews a lease that has not been pruned yet; false when it is unknown.
    pub fn renew(&mut self, id: &str) -> bool {
        let Some(lease) = self.leases.get_mut(id) else {
            return false;
        };
        lease.seen = tokio::time::Instant::now();
        true
    }
    pub fn detach(&mut self, id: &str) {
        if let Some(lease) = self.leases.remove(id)
            && self.leases.is_empty()
        {
            self.last_finishes_downloads = lease.finish_downloads;
        }
    }
    /// Drops expired leases and returns the ids still live.
    pub fn prune(&mut self) -> BTreeSet<String> {
        let expired: Vec<Lease> = self
            .leases
            .values()
            .filter(|lease| !lease.live())
            .copied()
            .collect();
        self.leases.retain(|_, lease| lease.live());
        if self.leases.is_empty()
            && let Some(last) = expired
                .iter()
                .max_by_key(|lease| (lease.seen, lease.finish_downloads))
        {
            self.last_finishes_downloads = last.finish_downloads;
        }
        self.leases.keys().cloned().collect()
    }
    pub fn is_live(&self, id: &str) -> bool {
        self.leases.get(id).is_some_and(Lease::live)
    }
    pub fn len(&self) -> usize {
        self.leases.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
    /// Whether the client that left last asked for downloads to finish.
    pub fn last_finishes_downloads(&self) -> bool {
        self.last_finishes_downloads
    }
}
/// The macOS helper app that may hold the sign-in window, next to the engine.
/// A bundle gives the window a proper application name and identity; a
/// runtime without one keeps the bare executable.
pub const SIGN_IN_BUNDLE: &str = "OMD Sign-In.app";
/// The native sign-in window helper for the engine executable at `engine`:
/// on macOS the executable inside [`SIGN_IN_BUNDLE`] when that bundle is
/// installed beside the engine, otherwise `omd-signin` (`omd-signin.exe` on
/// Windows) beside it, as before.
pub fn sign_in_helper(engine: &std::path::Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        let bundled = engine
            .with_file_name(SIGN_IN_BUNDLE)
            .join("Contents/MacOS/omd-signin");
        if bundled.is_file() {
            return bundled;
        }
    }
    engine.with_file_name(if cfg!(windows) {
        "omd-signin.exe"
    } else {
        "omd-signin"
    })
}
/// How long a client lease lasts without a heartbeat.
pub const CLIENT_LEASE: Duration = Duration::from_secs(45);
/// How long a new engine waits for its first client before it may stop.
pub const IDLE_GRACE: Duration = Duration::from_secs(60);
/// Prunes expired client leases and reports whether an engine whose
/// background operation is off should stop now. It keeps running while any
/// client holds a lease and during its first minute. Once the last client has
/// left, it stops unless that client attached with `finish_downloads` (the CLI
/// and MCP server do): then it stays up while a download is queued or running
/// and stops at the first check after the queue empties. A client that attaches
/// without it (the desktop) still stops the engine, and its downloads, when it
/// leaves.
pub async fn idle_exit_due(app: &App, uptime: Duration) -> bool {
    let mut clients = app.clients.lock().await;
    let live = clients.prune();
    let finish_downloads = clients.last_finishes_downloads();
    drop(clients);
    let empty = live.is_empty();
    app.browser_sessions.prune(&live).await;
    if !empty || uptime <= IDLE_GRACE {
        return false;
    }
    let background = app
        .store
        .setting("preferences")
        .await
        .ok()
        .flatten()
        .and_then(|v| v["background"].as_bool())
        .unwrap_or(false);
    if background {
        return false;
    }
    if !finish_downloads {
        tracing::info!("no client lease; stopping");
        return true;
    }
    if !app.running.lock().await.is_empty() {
        return false;
    }
    match app.store.has_unfinished_downloads().await {
        Ok(false) => {
            tracing::info!("no client lease and no unfinished download; stopping");
            true
        }
        Ok(true) => false,
        // Never cut a download short on an unreadable queue; the job runner
        // reports the same store failure.
        Err(error) => {
            tracing::warn!(error=%error, "could not read the download queue; staying up");
            false
        }
    }
}
/// After a `selection_changed` failure, ends reuse of the cached enumerations
/// of the collections involved, so a client's refresh lists the source again
/// instead of getting the stale list back. The failure itself is unchanged.
pub(crate) async fn forget_stale_enumerations(app: &App, collections: &[&SourceRef]) {
    let mut seen = BTreeSet::new();
    for collection in collections {
        if !seen.insert(collection.key()) {
            continue;
        }
        if let Err(error) = app.store.invalidate_snapshots(collection).await {
            tracing::warn!(error=%error, "could not invalidate a changed collection's enumeration");
        }
    }
}
#[derive(Debug)]
pub struct ApiError(StatusCode, Problem);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}
impl From<omd_store::StoreError> for ApiError {
    fn from(error: omd_store::StoreError) -> Self {
        match error {
            omd_store::StoreError::Destination => {
                let mut issue = Problem::new(
                    "destination_unavailable",
                    "Reconnect the registered destination, or explicitly choose its new location.",
                );
                issue.actions = vec!["reconnect_destination".into()];
                ApiError(StatusCode::CONFLICT, issue)
            }
            omd_store::StoreError::NotFound => problem(
                StatusCode::NOT_FOUND,
                "not_found",
                "The requested resource was not found.",
            ),
            omd_store::StoreError::StateConflict => problem(
                StatusCode::CONFLICT,
                "state_conflict",
                "The resource changed or the preparation expired. Refresh and prepare again.",
            ),
            omd_store::StoreError::IdempotencyConflict => problem(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "This idempotency key belongs to a different request.",
            ),
            omd_store::StoreError::CursorExpired => problem(
                StatusCode::CONFLICT,
                "resync_required",
                "The event cursor expired. Take a new snapshot and reconnect.",
            ),
            _ => problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_failed",
                "The database operation failed. Check available disk space and diagnostics.",
            ),
        }
    }
}
impl From<omd_plugins::PluginError> for ApiError {
    fn from(e: omd_plugins::PluginError) -> Self {
        if let omd_plugins::PluginError::Credential(error) = e {
            return error.into();
        }
        if let omd_plugins::PluginError::Source(problem) = e {
            return ApiError(StatusCode::BAD_GATEWAY, problem);
        }
        let retryable = matches!(
            e,
            omd_plugins::PluginError::Worker
                | omd_plugins::PluginError::Budget
                | omd_plugins::PluginError::InstallationBudget
                | omd_plugins::PluginError::Canceled
        );
        let mut issue = Problem::new("source_failed", e.to_string());
        issue.retryable = retryable;
        issue.actions = vec![if retryable { "retry" } else { "update_source" }.into()];
        ApiError(StatusCode::BAD_GATEWAY, issue)
    }
}
fn problem(status: StatusCode, code: &str, message: &str) -> ApiError {
    ApiError(status, Problem::new(code, message))
}
type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Clone, Copy, Serialize, schemars::JsonSchema)]
pub struct Operation {
    pub method: &'static str,
    pub path: &'static str,
    pub scope: &'static str,
}
/// Authorization is declared for exact routed operations, never inferred from
/// a URL suffix or HTTP verb. Independent clients can inspect the same table.
pub const OPERATIONS: &[Operation] = &[
    Operation {
        method: "GET",
        path: "/v2/source-catalog",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/destinations/default",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/browser-tools/status",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/browser-tools",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/browser-tools/{id}",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/browser-tools/install",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/browser-tools/{id}/activate",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/browser-tools/{id}/remove",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/browser-tools/{id}/cleanup",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/sources/{id}/sign-ins",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/sign-ins/{id}/actions",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/sign-ins/{id}/status",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/sign-ins/{id}/complete",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/sign-ins/{id}/close",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/tools",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/tools/status",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/tools/{id}",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/tools/install",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/tools/{id}/activate",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/tools/{id}/remove",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/tools/{id}/retry-cleanup",
        scope: "admin",
    },
    Operation {
        method: "GET",
        path: "/v2/notifications",
        scope: "read",
    },
    Operation {
        method: "PUT",
        path: "/v2/notifications",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/notifications/test",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/notifications/history",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/notifications/history/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/sources/{id}/remove",
        scope: "admin",
    },
    Operation {
        method: "GET",
        path: "/v2/source-removals",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/source-removals/{id}",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/source-removals/{id}/entries",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/source-removals/{id}/retry",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/destinations/{id}/check",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/destination-checks",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/destination-checks/{id}",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/destination-checks/{id}/files",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/destination-checks/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/openapi.json",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/acquisitions/status",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/metadata/{kind}/{provider}",
        scope: "read",
    },
    Operation {
        method: "PUT",
        path: "/v2/metadata/{kind}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/naming",
        scope: "read",
    },
    Operation {
        method: "PUT",
        path: "/v2/naming",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/jobs/{id}/file-operations",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/file-operations",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/file-operations/{id}",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/file-operations/{id}/files",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/file-operations/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/sources/{id}/artwork",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/sources/{id}/credentials",
        scope: "read",
    },
    Operation {
        method: "PUT",
        path: "/v2/sources/{id}/credentials/{profile}",
        scope: "manage",
    },
    Operation {
        method: "DELETE",
        path: "/v2/sources/{id}/credentials/{profile}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/operations",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/service",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/summary",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/service/shutdown",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/clients",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/clients/{id}",
        scope: "read",
    },
    Operation {
        method: "DELETE",
        path: "/v2/clients/{id}",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/sources",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/sources/install",
        scope: "admin",
    },
    Operation {
        method: "POST",
        path: "/v2/sources/{id}/invoke",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/sources/{id}/versions",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/sources/{id}/activate",
        scope: "admin",
    },
    Operation {
        method: "GET",
        path: "/v2/destinations",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/destinations",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/destinations/{id}",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/destinations/{id}/relocate",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/relocations",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/relocations/{id}",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/relocations/{id}/files",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/relocations/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/destinations/{id}/reconnect",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/snapshots",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/selections",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/selections/{id}",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/selections/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/snapshots/{id}/releases",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/batches",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/batches/{id}/items",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/preparations",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/groups",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/groups/{id}",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/groups/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/groups/{id}/jobs",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/jobs",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/jobs",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/jobs/{id}",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/jobs/{id}/files",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/jobs/{id}/files/{artifact}",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/jobs/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/events",
        scope: "read",
    },
    Operation {
        method: "GET",
        path: "/v2/settings",
        scope: "read",
    },
    Operation {
        method: "PATCH",
        path: "/v2/settings",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/subscriptions",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/subscriptions",
        scope: "manage",
    },
    Operation {
        method: "PATCH",
        path: "/v2/subscriptions/{id}",
        scope: "manage",
    },
    Operation {
        method: "POST",
        path: "/v2/subscriptions/{id}/{action}",
        scope: "manage",
    },
    Operation {
        method: "GET",
        path: "/v2/inbox",
        scope: "read",
    },
    Operation {
        method: "POST",
        path: "/v2/inbox/{id}/{action}",
        scope: "manage",
    },
];
pub fn scope(method: &str, matched_path: &str) -> &'static str {
    OPERATIONS
        .iter()
        .find(|operation| operation.method == method && operation.path == matched_path)
        .map_or("admin", |operation| operation.scope)
}
async fn operations() -> Json<&'static [Operation]> {
    Json(OPERATIONS)
}
async fn normalize_errors(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status().is_success()
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes().starts_with(b"application/json"))
    {
        return response;
    }
    let status = response.status();
    let (code, message) = match status {
        StatusCode::NOT_FOUND => ("not_found", "This API resource does not exist."),
        StatusCode::METHOD_NOT_ALLOWED => (
            "method_not_allowed",
            "This operation does not accept that HTTP method.",
        ),
        StatusCode::PAYLOAD_TOO_LARGE => (
            "request_too_large",
            "The request exceeds the operation's size limit.",
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            "content_type_required",
            "Send this operation's body as application/json.",
        ),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => (
            "invalid_request",
            "The request does not match the published operation contract. Check required fields, types, and query parameters.",
        ),
        _ => (
            "request_failed",
            "The engine could not process this request.",
        ),
    };
    let mut result = problem(status, code, message).into_response();
    if let Some(allow) = response.headers().get(header::ALLOW) {
        result.headers_mut().insert(header::ALLOW, allow.clone());
    }
    result
}
async fn authorize(State(app): State<App>, request: Request, next: Next) -> Response {
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let matched = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str())
        .unwrap_or("");
    let required = scope(request.method().as_str(), matched);
    let allowed =
        bearer.is_some_and(|s| s == app.admin_token || (s == app.token && required != "admin"));
    if !allowed {
        return problem(
            if bearer.is_none() {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::FORBIDDEN
            },
            "authorization_required",
            "This client does not have the required permission.",
        )
        .into_response();
    }
    let sensitive = matched.contains("/sign-ins") || matched.contains("/credentials");
    let mut response = next.run(request).await;
    if sensitive {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    response
}
async fn request_timing(request: axum::extract::Request, next: middleware::Next) -> Response {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let method = request.method().clone();
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let elapsed_ms = started.elapsed().as_millis();
    // Route templates only: never query strings, account IDs, headers, or bodies.
    if elapsed_ms > 1000 {
        tracing::warn!(route, %method, elapsed_ms, status=response.status().as_u16(), "Slow API request");
    } else {
        tracing::debug!(route, %method, elapsed_ms, status=response.status().as_u16(), "API request timing");
    }
    response
}
pub fn router(app: App, origins: Vec<header::HeaderValue>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
            axum::http::Method::PATCH,
            axum::http::Method::PUT,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("last-event-id"),
            header::HeaderName::from_static("idempotency-key"),
        ]);
    Router::new()
        .route("/v2/operations", get(operations))
        .route(
            "/v2/openapi.json",
            get(|| async { Json(contract::document()) }),
        )
        .route("/v2/service", get(service_info))
        .route("/v2/summary", get(summary))
        .route("/v2/acquisitions/status", post(acquisition_status))
        .route(
            "/v2/metadata/{kind}/{provider}",
            get(presentation::get_metadata),
        )
        .route(
            "/v2/metadata/{kind}",
            axum::routing::put(presentation::put_metadata),
        )
        .route(
            "/v2/naming",
            get(presentation::get_naming).put(presentation::put_naming),
        )
        .route("/v2/service/shutdown", post(shutdown))
        .route("/v2/clients", post(attach))
        .route("/v2/clients/{id}", post(heartbeat).delete(detach))
        .route("/v2/browser-tools/status", get(browsers::status))
        .route("/v2/browser-tools", get(browsers::packages))
        .route("/v2/browser-tools/{id}", get(browsers::package))
        .route("/v2/browser-tools/install", post(browsers::install))
        .route("/v2/browser-tools/{id}/activate", post(browsers::activate))
        .route("/v2/browser-tools/{id}/remove", post(browsers::remove))
        .route("/v2/browser-tools/{id}/cleanup", post(browsers::cleanup))
        .route("/v2/sources/{id}/sign-ins", post(browsers::start))
        .route("/v2/sign-ins/{id}/actions", post(browsers::action))
        .route("/v2/sign-ins/{id}/complete", post(browsers::complete))
        .route("/v2/sign-ins/{id}/status", post(browsers::sign_in_status))
        .route("/v2/sign-ins/{id}/close", post(browsers::close))
        .route("/v2/sources/{id}/credentials", get(credentials))
        .route(
            "/v2/sources/{id}/credentials/{profile}",
            axum::routing::put(save_credentials).delete(revoke_credentials),
        )
        .route("/v2/sources", get(sources))
        .route("/v2/sources/install", post(install))
        .route("/v2/source-catalog", get(catalog::list))
        .route(
            "/v2/destinations/default",
            post(catalog::default_destination),
        )
        .route("/v2/sources/{id}/invoke", post(invoke))
        .route("/v2/sources/{id}/artwork", get(artwork))
        .route("/v2/sources/{id}/versions", get(source_versions))
        .route("/v2/sources/{id}/activate", post(activate_source))
        .route("/v2/destinations", get(destinations).post(add_destination))
        .route("/v2/destinations/{id}", get(destination))
        .route("/v2/destinations/{id}/relocate", post(storage::create))
        .route("/v2/destinations/{id}/check", post(checks::create))
        .route("/v2/destination-checks", get(checks::list))
        .route("/v2/destination-checks/{id}", get(checks::get))
        .route("/v2/destination-checks/{id}/files", get(checks::files))
        .route("/v2/destination-checks/{id}/{action}", post(checks::action))
        .route("/v2/sources/{id}/remove", post(source_removals::remove))
        .route("/v2/source-removals", get(source_removals::list))
        .route(
            "/v2/notifications",
            get(notifications::status).put(notifications::configure),
        )
        .route("/v2/notifications/test", post(notifications::test))
        .route("/v2/notifications/history", get(notifications::history))
        .route(
            "/v2/notifications/history/{id}/{action}",
            post(notifications::control),
        )
        .route("/v2/source-removals/{id}", get(source_removals::get))
        .route(
            "/v2/source-removals/{id}/entries",
            get(source_removals::entries),
        )
        .route(
            "/v2/source-removals/{id}/retry",
            post(source_removals::retry),
        )
        .route("/v2/relocations", get(storage::list))
        .route("/v2/relocations/{id}", get(storage::get))
        .route("/v2/relocations/{id}/files", get(storage::files))
        .route("/v2/relocations/{id}/{action}", post(storage::action))
        .route(
            "/v2/destinations/{id}/reconnect",
            post(reconnect_destination),
        )
        .route("/v2/snapshots", post(selections::create_snapshot))
        .route("/v2/selections", get(selections::tasks))
        .route("/v2/selections/{id}", get(selections::task))
        .route("/v2/selections/{id}/{action}", post(selections::action))
        .route("/v2/snapshots/{id}/releases", get(selections::releases))
        .route("/v2/batches", post(selections::create_batch))
        .route("/v2/batches/{id}/items", get(selections::preview))
        .route("/v2/preparations", post(prepare))
        .route("/v2/groups", get(groups))
        .route("/v2/groups/{id}", get(group))
        .route("/v2/groups/{id}/jobs", get(group_jobs))
        .route("/v2/groups/{id}/{action}", post(group_action))
        .route("/v2/jobs", get(jobs).post(enqueue))
        .route("/v2/jobs/{id}", get(job))
        .route("/v2/jobs/{id}/file-operations", post(maintenance::create))
        .route("/v2/file-operations", get(maintenance::list))
        .route("/v2/file-operations/{id}", get(maintenance::get))
        .route("/v2/file-operations/{id}/files", get(maintenance::files))
        .route(
            "/v2/file-operations/{id}/{action}",
            post(maintenance::action),
        )
        .route("/v2/jobs/{id}/files", get(files))
        .route("/v2/jobs/{id}/files/{artifact}", get(artifact))
        .route("/v2/jobs/{id}/{action}", post(job_action))
        .route("/v2/events", get(events))
        .route("/v2/tools", get(tools::list))
        .route("/v2/tools/status", get(tools::status))
        .route("/v2/tools/install", post(tools::install))
        .route("/v2/tools/{id}", get(tools::get))
        .route("/v2/tools/{id}/activate", post(tools::activate))
        .route("/v2/tools/{id}/remove", post(tools::remove))
        .route("/v2/tools/{id}/retry-cleanup", post(tools::retry))
        .route("/v2/settings", get(settings).patch(update_settings))
        .route("/v2/subscriptions", get(subscriptions).post(subscribe))
        .route(
            "/v2/subscriptions/{id}",
            axum::routing::patch(update_subscription),
        )
        .route("/v2/subscriptions/{id}/{action}", post(subscription_action))
        .route("/v2/inbox", get(inbox))
        .route("/v2/inbox/{id}/{action}", post(inbox_action))
        .layer(middleware::from_fn_with_state(app.clone(), authorize))
        .layer(axum::extract::DefaultBodyLimit::max(70 * 1024 * 1024))
        .layer(middleware::from_fn(normalize_errors))
        .layer(middleware::from_fn(request_timing))
        .layer(cors)
        .with_state(app)
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ArtworkQuery {
    url: String,
    credential_profile: Option<String>,
}
async fn artwork(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(input): Query<ArtworkQuery>,
) -> Result<Response, ApiError> {
    let source = provider(&app, &id).await?;
    app.runtime
        .authorized(
            &source,
            &app.shutdown.child_token(),
            Duration::from_secs(60),
            artwork_inner(&app, &id, input, &source),
        )
        .await?
}
async fn artwork_inner(
    app: &App,
    id: &str,
    input: ArtworkQuery,
    source: &Provider,
) -> Result<Response, ApiError> {
    if input.url.len() > 8192 {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "artwork_url",
            "The artwork URL is too long.",
        ));
    }
    let url = url::Url::parse(&input.url).map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "artwork_url",
            "The artwork URL is invalid.",
        )
    })?;
    let grant = source
        .manifest
        .grants
        .iter()
        .find(|grant| {
            grant.methods.iter().any(|m| m == "GET")
                && omd_network::validate_url(&url, grant).is_ok()
        })
        .ok_or_else(|| {
            problem(
                StatusCode::FORBIDDEN,
                "artwork_permission",
                "The source has no permission for this artwork host.",
            )
        })?;
    let session = app
        .acquisition
        .network
        .session(
            id,
            input.credential_profile.as_deref(),
            &source.manifest.grants,
        )
        .await
        .map_err(|e| acquisition_problem(omd_acquisition::AcquisitionError::Network(e)))
        .map_err(|p| ApiError(StatusCode::CONFLICT, p))?;
    let cancel = app.shutdown.child_token();
    let _slot = app
        .acquisition
        .network
        .artwork_slots
        .acquire()
        .await
        .map_err(|_| {
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "canceled",
                "Artwork loading was interrupted.",
            )
        })?;
    let mut response = app
        .acquisition
        .network
        .open_artwork(
            &omd_network::Request {
                url: input.url,
                permission: grant.id.clone(),
                method: "GET".into(),
                // Image CDNs may require the source's origin as referrer.
                // Use only a declared public source host, never a credential or
                // a caller-supplied header / URL containing an account token.
                headers: source
                    .manifest
                    .source_hosts
                    .first()
                    .filter(|host| !host.contains('*'))
                    .map(|host| BTreeMap::from([("referer".into(), format!("https://{host}/"))]))
                    .unwrap_or_default(),
                body: String::new(),
            },
            std::slice::from_ref(grant),
            session.as_ref(),
            &cancel,
        )
        .await
        .map_err(|_| {
            problem(
                StatusCode::BAD_GATEWAY,
                "artwork_unavailable",
                "Artwork could not be retrieved.",
            )
        })?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|n| n > 4 * 1024 * 1024)
    {
        return Err(problem(
            StatusCode::BAD_GATEWAY,
            "artwork_unavailable",
            "The source did not return bounded artwork.",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        problem(
            StatusCode::BAD_GATEWAY,
            "artwork_unavailable",
            "The artwork transfer failed.",
        )
    })? {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err(problem(
                StatusCode::BAD_GATEWAY,
                "artwork_limit",
                "The artwork exceeds its size limit.",
            ));
        }
        app.acquisition
            .network
            .bandwidth
            .consume(chunk.len(), &cancel)
            .await
            .map_err(|_| {
                problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "canceled",
                    "The artwork request was canceled.",
                )
            })?;
        bytes.extend_from_slice(&chunk);
    }
    let media_type = omd_acquisition::image_type(&bytes).ok_or_else(|| {
        problem(
            StatusCode::BAD_GATEWAY,
            "artwork_type",
            "The source returned unsupported artwork content.",
        )
    })?;
    Ok((
        [
            (header::CONTENT_TYPE, media_type),
            (header::CACHE_CONTROL, "private, max-age=3600"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    )
        .into_response())
}

async fn service_info(State(app): State<App>) -> ApiResult<Value> {
    let identity = identity::current().map_err(|_| {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "identity_unavailable",
            "The running engine identity is unavailable. Restart OMD.",
        )
    })?;
    let mut recipes = vec!["cbz", "image_folder"];
    let mut capabilities = vec![
        "source_operations",
        "manga_acquisition",
        "destinations",
        "resumable_events",
        "subscriptions",
        "credentials",
    ];
    if app.runtime.browser().is_some() {
        capabilities.extend(["source_browser", "isolated_sign_in"]);
    }
    let media = app.runtime.media().map(|media| {
        let complete = media.tools.ffmpeg.is_some() && media.tools.ffprobe.is_some() && media.tools.node.is_some();
        if complete {
            recipes.extend(["mp4","mkv","webm","m4a","mp3","opus"]);
            capabilities.push("media_acquisition");
        }
        json!({"configured":true,"complete":complete,"tools":std::iter::once(("yt_dlp",&media.tools.yt_dlp)).chain(media.tools.node.as_ref().map(|t|("node",t))).chain(media.tools.ffmpeg.as_ref().map(|t|("ffmpeg",t))).chain(media.tools.ffprobe.as_ref().map(|t|("ffprobe",t))).map(|(name,t)|json!({"name":name,"version":t.version,"sha256":t.sha256})).collect::<Vec<_>>()})
    });
    Ok(Json(
        json!({"api":"v2","version":identity.version,"executable_sha256":identity.executable_sha256,"event_cursor":app.store.event_cursor().await?,"scopes":["read","manage"],"capabilities":capabilities,"recipes":recipes,"media_tools":media}),
    ))
}
/// A destination as API responses show it: the stored canonical root (exact,
/// used by every internal consumer) in its ordinary spelling, without a
/// Windows `\\?\` prefix when that names the same folder.
pub(crate) fn shown_destination(mut destination: Destination) -> Destination {
    destination.root = omd_files::display_path(std::path::Path::new(&destination.root));
    destination
}
async fn destination(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Destination> {
    Ok(Json(shown_destination(app.store.destination(&id).await?)))
}
async fn summary(State(app): State<App>) -> ApiResult<Value> {
    Ok(Json(app.store.summary().await?))
}
async fn shutdown(
    State(app): State<App>,
    Query(query): Query<contract::models::ShutdownQuery>,
) -> ApiResult<Value> {
    if query.for_update {
        update::suspend(&app.profile).await.map_err(|_| {
            problem(
                StatusCode::CONFLICT,
                "update_startup_busy",
                "OMD could not suspend its startup registration. Quit OMD and retry the update.",
            )
        })?;
    }
    app.shutdown.cancel();
    Ok(Json(json!({"state":"stopping"})))
}
async fn attach(
    State(app): State<App>,
    Query(query): Query<contract::models::AttachQuery>,
) -> ApiResult<Value> {
    let id = omd_store::id("client");
    app.clients
        .lock()
        .await
        .attach(id.clone(), query.finish_downloads);
    Ok(Json(
        json!({"id":id,"heartbeat_seconds":15,"lease_seconds":CLIENT_LEASE.as_secs(),"finish_downloads":query.finish_downloads}),
    ))
}
async fn heartbeat(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    if !app.clients.lock().await.renew(&id) {
        return Err(problem(
            StatusCode::NOT_FOUND,
            "client_expired",
            "Attach again; the client lease expired.",
        ));
    }
    Ok(Json(json!({"id":id})))
}
async fn detach(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    app.clients.lock().await.detach(&id);
    app.browser_sessions.detach(&id).await;
    Ok(Json(json!({"detached":true})))
}
async fn sources(State(app): State<App>, Query(query): Query<List>) -> ApiResult<Value> {
    let limit = query.limit.unwrap_or(100).clamp(1, 200) as usize;
    let search = query.q.to_lowercase();
    let mut sources: Vec<_> = app
        .providers
        .read()
        .await
        .values()
        .filter(|p| {
            query
                .cursor
                .as_ref()
                .is_none_or(|cursor| &p.manifest.id > cursor)
        })
        .filter(|p| {
            p.manifest.name.to_lowercase().contains(&search) || p.manifest.id.contains(&search)
        })
        .take(limit + 1)
        .map(|p| json!({"manifest":p.manifest,"digest":p.digest}))
        .collect();
    let more = sources.len() > limit;
    sources.truncate(limit);
    let next_cursor = if more {
        sources.last().map(|p| p["manifest"]["id"].clone())
    } else {
        None
    };
    Ok(Json(json!({"items":sources,"next_cursor":next_cursor})))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Install {
    package_path: String,
    approve_digest: Option<String>,
}
async fn install(State(app): State<App>, Json(request): Json<Install>) -> ApiResult<Value> {
    let metadata = tokio::fs::metadata(&request.package_path)
        .await
        .map_err(|_| {
            problem(
                StatusCode::BAD_REQUEST,
                "package_missing",
                "Choose an existing OMD provider package.",
            )
        })?;
    if metadata.len() > 64 * 1024 * 1024 {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "package_size",
            "The source package exceeds its size limit.",
        ));
    }
    let bytes = tokio::fs::read(&request.package_path).await.map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "package_read",
            "The source package could not be read.",
        )
    })?;
    if bytes.len() < 10 || &bytes[..6] != b"OMDP2\0" {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "package_invalid",
            "This is not an OMD v2 package.",
        ));
    }
    let length = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
    if length > 64 * 1024 || length + 10 >= bytes.len() {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "package_invalid",
            "The package manifest is invalid.",
        ));
    }
    let manifest: ProviderManifest =
        serde_json::from_slice(&bytes[10..10 + length]).map_err(|_| {
            problem(
                StatusCode::BAD_REQUEST,
                "manifest_invalid",
                "The package manifest does not match the v2 contract.",
            )
        })?;
    validate_manifest(&manifest)?;
    let component = &bytes[10 + length..];
    let digest = omd_plugins::package_digest(&manifest, component);
    if request.approve_digest.as_deref() != Some(&digest) {
        return Ok(Json(
            json!({"review_required":true,"digest":digest,"manifest":manifest}),
        ));
    }
    let _changes = app.source_changes.lock().await;
    let folder = app.profile.join("providers").join(&digest);
    tokio::fs::create_dir_all(&folder).await.map_err(|_| {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_storage",
            "The package could not be stored.",
        )
    })?;
    let path = folder.join("plugin.wasm");
    if !path.exists() {
        use tokio::io::AsyncWriteExt;
        let temporary = folder.join(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await
            .map_err(|_| {
                problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "package_storage",
                    "The package could not be stored.",
                )
            })?;
        file.write_all(component).await.map_err(|_| {
            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_storage",
                "The package could not be written.",
            )
        })?;
        file.sync_all().await.map_err(|_| {
            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_storage",
                "The package could not be synchronized.",
            )
        })?;
        drop(file);
        // A failed install must never leave a truncated content-addressed component.
        let publish = tokio::fs::hard_link(&temporary, &path).await;
        let _ = tokio::fs::remove_file(&temporary).await;
        if let Err(error) = publish
            && error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_storage",
                "The verified package could not be published.",
            ));
        }
    }
    let provider = Provider {
        manifest: manifest.clone(),
        component: path.clone(),
        digest: digest.clone(),
    };
    app.runtime
        .inspect(&provider, &app.shutdown.child_token())
        .await?;
    app.browser_sessions.revoke_source(&manifest.id).await;
    let mut providers = app.providers.write().await;
    app.store
        .install_provider(&manifest, &digest, &path.to_string_lossy())
        .await?;
    app.runtime.restore(&manifest.id, &digest);
    providers.insert(manifest.id.clone(), provider);
    Ok(Json(
        json!({"installed":true,"digest":digest,"manifest":manifest}),
    ))
}
async fn source_versions(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<Value>> {
    Ok(Json(
        app.store
            .search_provider_versions(
                &id,
                &query.q,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ActivateSource {
    digest: String,
}
async fn activate_source(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(request): Json<ActivateSource>,
) -> ApiResult<Value> {
    let _changes = app.source_changes.lock().await;
    let (manifest, path) = app.store.provider_version(&id, &request.digest).await?;
    let source = Provider {
        manifest,
        component: path.into(),
        digest: request.digest.clone(),
    };
    app.runtime
        .inspect(&source, &app.shutdown.child_token())
        .await?;
    app.browser_sessions.revoke_source(&id).await;
    // Serialize activation with installation so disk and memory agree for every request.
    let mut providers = app.providers.write().await;
    app.store.activate_provider(&id, &request.digest).await?;
    app.runtime.restore(&id, &request.digest);
    providers.insert(id, source);
    Ok(Json(json!({"activated":true,"digest":request.digest})))
}
fn validate_manifest(m: &ProviderManifest) -> Result<(), ApiError> {
    let valid = m.api == PLUGIN_API
        && !m.id.is_empty()
        && m.id.len() < 200
        && m.id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && m.account_mode.is_none_or(|mode| {
            m.grants.iter().any(|grant| grant.credential)
                && (mode != omd_domain::AccountMode::Browser || m.sign_in.is_some())
        })
        && m.grants.len() <= 32
        && m.sign_in.as_ref().is_none_or(|sign_in| {
            sign_in.completion_cookies.len() <= 16
                && sign_in.completion_cookies.iter().all(|name| {
                    !name.is_empty()
                        && name.len() <= 128
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
                && sign_in.grants.len() <= 32
                && m.grants.iter().any(|grant| grant.credential)
                && url::Url::parse(&sign_in.url).is_ok_and(|url| {
                    sign_in.grants.iter().chain(m.grants.iter()).any(|grant| {
                        grant.credential
                            && grant.methods.iter().any(|method| method == "GET")
                            && validate_broker_url(&url, grant).is_ok()
                    })
                })
        })
        && m.capabilities.iter().all(|s| {
            [
                "discovery",
                "details",
                "artwork",
                "related",
                "recommendations",
                "search",
                "browse",
                "identify",
                "collection",
                "releases",
                "resolve",
                // Not an operation: the source reads the hint on `resolve`.
                omd_domain::COLLECTION_HINT_CAPABILITY,
            ]
            .contains(&s.as_str())
        });
    let mut ids = BTreeSet::new();
    if !valid
        || m.grants
            .iter()
            .chain(m.sign_in.iter().flat_map(|s| s.grants.iter()))
            .any(|g| {
                !ids.insert(&g.id)
                    || g.request_intervals.len() > 16
                    || g.request_intervals.iter().any(|(prefix, millis)| {
                        !prefix.starts_with('/')
                            || prefix.len() > 512
                            || prefix.contains(['?', '#'])
                            || !(250..=60_000).contains(millis)
                    })
                    || g.hosts.is_empty()
                    || g.hosts.iter().any(|h| {
                        let h = h.strip_prefix("*.").unwrap_or(h);
                        h.len() > 253
                            || !h.contains('.')
                            || !h.bytes().all(|c| {
                                c.is_ascii_lowercase()
                                    || c.is_ascii_digit()
                                    || c == b'.'
                                    || c == b'-'
                            })
                    })
                    || g.methods
                        .iter()
                        .any(|m| !["GET", "HEAD", "POST"].contains(&m.as_str()))
            })
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "manifest_invalid",
            "The source manifest requests an invalid contract or permission.",
        ));
    }
    Ok(())
}
async fn provider(app: &App, id: &str) -> Result<Provider, ApiError> {
    app.providers.read().await.get(id).cloned().ok_or_else(|| {
        problem(
            StatusCode::NOT_FOUND,
            "source_missing",
            "Install or enable this source first.",
        )
    })
}
async fn invoke(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(request): Json<contract::models::SourceInvocation>,
) -> ApiResult<Value> {
    let provider = provider(&app, &id).await?;
    if !(1..=200).contains(&request.page_size) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "page_size_invalid",
            "Use a source page size between 1 and 200.",
        ));
    }
    if let Some(options) = &request.discovery {
        options.validate().map_err(|_| {
            problem(
                StatusCode::BAD_REQUEST,
                "invalid_filters",
                "The discovery filters exceed their limits.",
            )
        })?;
    }
    let request = request.into_worker();
    let result = app
        .runtime
        .invoke::<Value>(&provider, &request, &app.shutdown.child_token())
        .await?;
    if request.operation == "collection" {
        let collection: Collection = serde_json::from_value(result.clone())
            .map_err(|_| omd_plugins::PluginError::Invalid)?;
        app.store.upsert_collection(&collection).await?;
    }
    Ok(Json(result))
}
async fn destinations(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<Destination>> {
    let page = app
        .store
        .destination_page(
            &query.q,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(Page {
        items: page.items.into_iter().map(shown_destination).collect(),
        next_cursor: page.next_cursor,
    }))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AddDestination {
    label: String,
    root: String,
}
async fn add_destination(
    State(app): State<App>,
    Json(request): Json<AddDestination>,
) -> ApiResult<Destination> {
    let root = tokio::fs::canonicalize(&request.root).await.map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "destination_unavailable",
            "Choose an existing destination folder.",
        )
    })?;
    if !root.is_dir() || request.label.trim().is_empty() {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "destination_invalid",
            "A destination needs a name and an existing folder.",
        ));
    }
    Ok(Json(shown_destination(
        app.store.add_destination(&request.label, &root).await?,
    )))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReconnectDestination {
    root: String,
}
async fn reconnect_destination(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(request): Json<ReconnectDestination>,
) -> ApiResult<Destination> {
    Ok(Json(shown_destination(
        app.store
            .reconnect_destination(&id, std::path::Path::new(&request.root))
            .await?,
    )))
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Prepare {
    #[serde(default)]
    credential_profile: Option<String>,
    releases: Vec<SourceRef>,
    destination_id: String,
    recipe: Recipe,
    policy: SelectionPolicy,
    #[serde(default)]
    duplicate_behavior: DuplicateBehavior,
}
async fn prepare(State(app): State<App>, Json(request): Json<Prepare>) -> ApiResult<Value> {
    if request.releases.is_empty() || request.releases.len() > 2000 {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "selection_size",
            "Select between 1 and 2000 releases.",
        ));
    }
    let dest = app.store.destination(&request.destination_id).await?;
    if !dest.available {
        return Err(problem(
            StatusCode::CONFLICT,
            "destination_unavailable",
            "Reconnect this destination before preparing files.",
        ));
    }
    let request_digest = digest(&serde_json::to_vec(&request).unwrap());
    let mut plans = vec![];
    let mut outcomes = vec![];
    let mut seen = BTreeSet::new();
    for reference in &request.releases {
        if !seen.insert(reference.key()) {
            continue;
        }
        let provider = provider(&app, &reference.provider).await?;
        let input = ProviderRequest {
            release_order: None,
            discovery: None,
            credential_profile: request.credential_profile.clone(),
            operation: "resolve".into(),
            reference: Some(reference.clone()),
            query: None,
            url: None,
            cursor: None,
            page_size: 200,
            policy: request.policy.clone(),
            now: omd_store::now(),
            // A direct preparation names releases only, not where they were listed.
            collection_hint: None,
        };
        let resolved: ResolvedRelease = app
            .runtime
            .invoke(&provider, &input, &app.shutdown.child_token())
            .await?;
        if resolved.release.reference != *reference
            || resolved.collection.reference.provider != provider.manifest.id
            || !request.policy.accepts(&resolved.release)
        {
            let collections = [&resolved.release.collection, &resolved.collection.reference];
            let own: Vec<_> = collections
                .into_iter()
                .filter(|c| c.provider == provider.manifest.id)
                .collect();
            forget_stale_enumerations(&app, &own).await;
            return Err(problem(
                StatusCode::CONFLICT,
                "selection_changed",
                "The resolved release does not match the requested source or selection policy.",
            ));
        }
        let plan = build_plan(
            &app,
            &provider,
            omd_media::Preparation {
                resolved,
                recipe: request.recipe,
                policy: request.policy.clone(),
                provider_digest: provider.digest.clone(),
                credential_profile: request.credential_profile.clone(),
            },
            &app.shutdown.child_token(),
        )
        .await?;
        let (plan, outcome) = app
            .store
            .plan_intent(&plan, &dest.id, request.duplicate_behavior)
            .await?;
        plans.push(plan);
        outcomes.push(outcome);
    }
    let expires = (chrono::Utc::now() + chrono::Duration::minutes(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let data = json!({"plans":plans,"destination_id":dest.id});
    let id = app.store.prepare(&request_digest, &data, &expires).await?;
    Ok(Json(
        json!({"id":id,"expires_at":expires,"destination":shown_destination(dest),"items":plans.iter().zip(outcomes).map(|(p,outcome)|json!({"plan":p,"outcome":outcome,"files":omd_acquisition::final_outputs(p),"estimated_bytes":p.estimated_bytes()})).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Enqueue {
    preparation_id: String,
}
async fn enqueue(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<Enqueue>,
) -> ApiResult<Value> {
    let key = headers
        .get("idempotency-key")
        .and_then(|s| s.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 200)
        .ok_or_else(|| {
            problem(
                StatusCode::BAD_REQUEST,
                "idempotency_required",
                "Supply an Idempotency-Key header.",
            )
        })?;
    let fingerprint = digest(&serde_json::to_vec(&request).unwrap());
    if request.preparation_id.starts_with("batch_") {
        return Ok(Json(
            app.store
                .enqueue_batch(&request.preparation_id, key, &fingerprint)
                .await?,
        ));
    }
    Ok(Json(
        app.store
            .enqueue_prepared(&request.preparation_id, key, &fingerprint)
            .await?,
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
struct List {
    #[serde(default)]
    q: String,
    state: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}
async fn groups(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<omd_store::groups::JobGroup>> {
    Ok(Json(
        app.store
            .filtered_job_groups(
                &query.q,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
                query.state.as_deref() == Some("active"),
            )
            .await?,
    ))
}
async fn group(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<omd_store::groups::JobGroup> {
    Ok(Json(app.store.job_group(&id).await?))
}
async fn group_action(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<omd_store::groups::GroupAction> {
    if !["pause", "cancel", "resume", "retry"].contains(&action.as_str()) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "action_invalid",
            "Use pause, cancel, resume, or retry.",
        ));
    }
    let running = app.running.lock().await;
    let (result, stop) = app
        .store
        .group_action(&id, &action, &running.keys().cloned().collect::<Vec<_>>())
        .await?;
    for id in stop {
        if let Some(token) = running.get(&id) {
            token.cancel();
        }
    }
    Ok(Json(result))
}
async fn group_jobs(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<Job>> {
    Ok(Json(
        app.store
            .group_jobs(
                &id,
                &query.q,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct StatusLookup {
    references: Vec<SourceRef>,
}
async fn acquisition_status(
    State(app): State<App>,
    Json(value): Json<StatusLookup>,
) -> ApiResult<Vec<omd_store::history::AcquisitionStatus>> {
    if value.references.len() > 200
        || value.references.iter().any(|r| r.validate().is_err())
        || value.references.iter().collect::<BTreeSet<_>>().len() != value.references.len()
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "references_invalid",
            "Supply up to 200 unique namespaced release identities.",
        ));
    }
    Ok(Json(app.store.acquisition_status(&value.references).await?))
}
async fn jobs(State(app): State<App>, Query(query): Query<List>) -> ApiResult<Page<Job>> {
    Ok(Json(
        app.store
            .jobs(
                &query.q,
                query.state.as_deref(),
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
async fn job(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Job> {
    ensure_history(&app.store, &id).await?;
    Ok(Json(app.store.job(&id).await?))
}
async fn ensure_history(store: &Store, id: &str) -> Result<(), ApiError> {
    if store.history_removed(id).await? {
        return Err(problem(
            StatusCode::GONE,
            "history_removed",
            "This acquisition was explicitly removed from history.",
        ));
    }
    Ok(())
}
async fn artifact(
    State(app): State<App>,
    Path((job, id)): Path<(String, String)>,
) -> ApiResult<Artifact> {
    ensure_history(&app.store, &job).await?;
    let artifact = app.store.artifact(&id).await?;
    if artifact.job_id != job {
        return Err(omd_store::StoreError::NotFound.into());
    }
    Ok(Json(artifact))
}
async fn files(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<Artifact>> {
    ensure_history(&app.store, &id).await?;
    Ok(Json(
        app.store
            .search_artifacts(
                &id,
                &query.q,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
async fn job_action(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<Job> {
    ensure_history(&app.store, &id).await?;
    let running = app.running.lock().await;
    match action.as_str() {
        "pause" | "cancel" => {
            app.store
                .transition(
                    &id,
                    &["queued", "transferring", "verifying", "failed", "paused"],
                    if action == "pause" {
                        "paused"
                    } else {
                        "canceled"
                    },
                    None,
                )
                .await?;
            if let Some(token) = running.get(&id) {
                token.cancel();
            }
        }
        "resume" | "retry" => {
            if running.contains_key(&id) {
                return Err(problem(
                    StatusCode::CONFLICT,
                    "pausing",
                    "The current transfer is still checkpointing. Retry shortly.",
                ));
            }
            app.store
                .transition(&id, &["paused", "failed", "canceled"], "queued", None)
                .await?;
        }
        _ => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "action_invalid",
                "Use pause, cancel, resume, or retry.",
            ));
        }
    }
    Ok(Json(app.store.job(&id).await?))
}
#[derive(Deserialize, schemars::JsonSchema)]
struct EventQuery {
    cursor: Option<i64>,
}
async fn events(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<SseEvent, Infallible>>>, ApiError> {
    let cursor = headers
        .get("last-event-id")
        .and_then(|h| h.to_str().ok())
        .map(str::parse::<i64>)
        .transpose()
        .map_err(|_| {
            problem(
                StatusCode::BAD_REQUEST,
                "cursor_invalid",
                "The event cursor is invalid.",
            )
        })?
        .or(query.cursor)
        .unwrap_or(app.store.event_cursor().await?);
    if cursor < 0 || cursor > app.store.event_cursor().await? {
        return Err(problem(
            StatusCode::CONFLICT,
            "resync_required",
            "Take a new snapshot and reconnect from its event cursor.",
        ));
    }
    let initial = app.store.events(cursor, 200).await?;
    let stream = futures_util::stream::unfold(
        (app, cursor, initial, false),
        |(app, mut cursor, mut buffered, terminal)| async move {
            if terminal {
                return None;
            }
            loop {
                if !buffered.is_empty() {
                    let event = buffered.remove(0);
                    cursor = event.id;
                    return Some((
                        Ok(SseEvent::default()
                            .id(event.id.to_string())
                            .event(&event.kind)
                            .json_data(&event)
                            .unwrap()),
                        (app, cursor, buffered, false),
                    ));
                }
                match app.store.events(cursor, 200).await {
                    Ok(items) => buffered = items,
                    Err(_) => {
                        return Some((
                            Ok(SseEvent::default()
                                .event("resync_required")
                                .data("The event journal is unavailable or the cursor expired; take a new snapshot.")),
                            (app, cursor, buffered, true),
                        ));
                    }
                }
                if buffered.is_empty() {
                    tokio::select! {_ = app.shutdown.cancelled()=>return None,_=tokio::time::sleep(Duration::from_millis(250))=>{}}
                }
            }
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
async fn settings(State(app): State<App>) -> ApiResult<Value> {
    let mut preferences = app
        .store
        .setting("preferences")
        .await?
        .unwrap_or(json!({"background":false,"languages":["en"]}));
    preferences["startup"] = app
        .store
        .setting("startup_status")
        .await?
        .unwrap_or(json!({"enabled":false,"issue":null}));
    Ok(Json(preferences))
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Preferences {
    #[serde(default)]
    bandwidth_bytes_per_second: u64,
    background: bool,
    languages: Vec<String>,
    #[serde(default)]
    onboarding_complete: bool,
}
async fn update_settings(
    State(app): State<App>,
    Json(value): Json<Preferences>,
) -> ApiResult<Value> {
    if value.bandwidth_bytes_per_second > 1024 * 1024 * 1024
        || value.languages.len() > 50
        || value.languages.iter().any(|s| {
            s.is_empty()
                || s.len() > 35
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "preferences_invalid",
            "Use valid language tags and a bandwidth limit between zero and 1 GiB/s.",
        ));
    }
    app.acquisition
        .network
        .bandwidth
        .set_limit(value.bandwidth_bytes_per_second)
        .await;
    let enabled = value.background;
    let value = serde_json::to_value(value).unwrap();
    // Persist desired behavior before OS registration. If registration fails,
    // background downloads still work now and the failed login startup is visible.
    app.store.set_setting("preferences", &value).await?;
    let launch = omd_lifecycle::Launch::load(&app.profile).map_err(startup_problem)?;
    if let Some(launch) = launch {
        if let Err(error) = launch.set_enabled(enabled).await {
            let issue = startup_problem(error);
            app.store
                .set_setting("startup_status", &json!({"enabled":false,"issue":issue.1}))
                .await?;
            return Err(issue);
        }
        app.store
            .set_setting("startup_status", &json!({"enabled":enabled,"issue":null}))
            .await?;
    } else if enabled {
        return Err(startup_problem(omd_lifecycle::Error::Invalid));
    }
    Ok(Json(value))
}

fn startup_problem(error: omd_lifecycle::Error) -> ApiError {
    ApiError(
        StatusCode::CONFLICT,
        Problem {
            code: "startup_unavailable".into(),
            message: error.to_string(),
            retryable: true,
            actions: vec!["retry_startup".into()],
        },
    )
}

async fn subscriptions(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<Subscription>> {
    Ok(Json(
        omd_subscriptions::search(
            &app.store,
            &query.q,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?,
    ))
}
async fn subscribe(
    State(app): State<App>,
    Json(mut request): Json<SubscribeRequest>,
) -> ApiResult<Subscription> {
    request.normalize_search().map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "invalid_search_subscription",
            "Choose a search query and notifications for new matches.",
        )
    })?;
    let source = provider(&app, &request.target.provider).await?;
    if !source
        .manifest
        .capabilities
        .contains(if request.search.is_some() {
            "search"
        } else {
            "releases"
        })
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "subscription_unsupported",
            "This source does not support this subscription.",
        ));
    }
    if matches!(request.action, ActionPolicy::Download) {
        app.store.destination(&request.destination_id).await?;
    }
    cache_subscription_collection(&app, &source, &request).await?;
    Ok(Json(omd_subscriptions::create(&app.store, request).await?))
}
async fn cache_subscription_collection(
    app: &App,
    source: &Provider,
    request: &SubscribeRequest,
) -> Result<(), ApiError> {
    if request.search.is_some() {
        return Ok(());
    }
    if !source
        .manifest
        .capabilities
        .iter()
        .any(|capability| capability == "collection")
    {
        return Ok(());
    }
    let cached: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM collections WHERE provider_id=? AND source_id=?)",
    )
    .bind(&request.target.provider)
    .bind(&request.target.id)
    .fetch_one(&app.store.pool)
    .await
    .map_err(omd_store::StoreError::from)?;
    if cached {
        return Ok(());
    }
    let input = ProviderRequest {
        release_order: None,
        discovery: None,
        operation: "collection".into(),
        reference: Some(request.target.clone()),
        credential_profile: request.credential_profile.clone(),
        query: None,
        url: None,
        cursor: None,
        page_size: 100,
        policy: request.policy.clone(),
        now: omd_store::now(),
        collection_hint: None,
    };
    let collection: Collection = app
        .runtime
        .invoke(source, &input, &app.shutdown.child_token())
        .await?;
    if collection.reference != request.target {
        return Err(omd_plugins::PluginError::Invalid.into());
    }
    app.store.upsert_collection(&collection).await?;
    Ok(())
}
async fn update_subscription(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(request): Json<SubscribeRequest>,
) -> ApiResult<Subscription> {
    if matches!(request.action, ActionPolicy::Download) {
        app.store.destination(&request.destination_id).await?;
    }
    Ok(Json(
        omd_subscriptions::update(&app.store, &id, request).await?,
    ))
}
async fn subscription_action(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<Subscription> {
    omd_subscriptions::action(&app.store, &id, &action).await?;
    Ok(Json(omd_subscriptions::get(&app.store, &id).await?))
}
async fn inbox(State(app): State<App>, Query(query): Query<List>) -> ApiResult<Page<Value>> {
    Ok(Json(
        omd_subscriptions::search_inbox(
            &app.store,
            &query.q,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await?,
    ))
}
async fn inbox_action(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<Value> {
    omd_subscriptions::inbox_action(&app.store, &id, &action).await?;
    Ok(Json(json!({"updated":true})))
}

pub async fn run_subscriptions(app: App) {
    // Observation scans share the persisted page worker. Downloads have their own
    // loop so a slow source cannot starve already-observed acquisition actions.
    tokio::join!(
        run_subscription_observations(app.clone()),
        run_subscription_actions(app)
    );
}
async fn run_subscription_observations(app: App) {
    loop {
        if app.shutdown.is_cancelled() {
            break;
        }
        if let Err(error) = omd_subscriptions::scans::settle(&app.store).await {
            tracing::error!(error=%error,"subscription scan could not commit");
        }
        match omd_subscriptions::next_due(&app.store).await {
            Ok(Some(subscription)) => {
                match provider(&app, &subscription.request.target.provider).await {
                    Ok(source) => {
                        if let Err(error) =
                            cache_subscription_collection(&app, &source, &subscription.request)
                                .await
                        {
                            let _ =
                                omd_subscriptions::failed(&app.store, &subscription, error.1).await;
                            continue;
                        }
                        if let Err(error) = omd_subscriptions::scans::begin(
                            &app.store,
                            &subscription,
                            &source.digest,
                        )
                        .await
                        {
                            tracing::error!(error=%error,"subscription scan could not start");
                        }
                    }
                    Err(error) => {
                        let _ = omd_subscriptions::failed(&app.store, &subscription, error.1).await;
                    }
                }
            }
            Ok(None) => {}
            Err(error) => tracing::error!(error=%error,"subscription schedule unavailable"),
        }
        tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }
}
async fn run_subscription_actions(app: App) {
    loop {
        if app.shutdown.is_cancelled() {
            break;
        }
        if let Ok(Some((id, subscription, release))) =
            omd_subscriptions::pending_action(&app.store).await
        {
            let request = &subscription.request;
            let effect = async {
                let source = provider(&app, &release.reference.provider).await?;
                let input = ProviderRequest {
                    release_order: None,
                    discovery: None,
                    credential_profile: request.credential_profile.clone(),
                    operation: "resolve".into(),
                    reference: Some(release.reference.clone()),
                    query: None,
                    url: None,
                    cursor: None,
                    page_size: 200,
                    policy: request.policy.clone(),
                    now: omd_store::now(),
                    // The subscribed collection the scan listed this release under.
                    collection_hint: Some(release.collection.clone()),
                };
                let resolved: ResolvedRelease = app
                    .runtime
                    .invoke(&source, &input, &app.shutdown.child_token())
                    .await?;
                // A source that reads the collection hint must, as for a batch,
                // keep the release in the collection it was listed under: the
                // subscribed collection (scans keep only its own releases). A
                // release that resolves as its own item (an image post, or
                // another standalone item) has no parent collection to move to;
                // it keeps that identity, as image snapshots record it. Sources
                // without the capability keep the earlier rule: they may file a
                // followed release under another collection.
                let checks_collection = source.manifest.accepts_collection_hint();
                let own_item = resolved.collection.kind == omd_domain::CollectionKind::Item
                    && resolved.release.collection == resolved.collection.reference;
                if resolved.release.reference != release.reference
                    || (checks_collection
                        && resolved.release.collection != request.target
                        && !own_item)
                    || !request.policy.accepts(&resolved.release)
                {
                    if checks_collection {
                        forget_stale_enumerations(&app, &[&request.target]).await;
                    }
                    return Err(problem(
                        StatusCode::CONFLICT,
                        "subscription_selection_changed",
                        "The new release no longer matches the subscription.",
                    ));
                }
                let plan = build_plan(
                    &app,
                    &source,
                    omd_media::Preparation {
                        resolved,
                        recipe: request.recipe,
                        policy: request.policy.clone(),
                        provider_digest: source.digest.clone(),
                        credential_profile: request.credential_profile.clone(),
                    },
                    &app.shutdown.child_token(),
                )
                .await?;
                let (job, _) = app
                    .store
                    .enqueue(
                        &plan,
                        &request.destination_id,
                        &format!("subscription:{id}"),
                        &id,
                        Some(&subscription.id),
                    )
                    .await?;
                Ok::<_, ApiError>(job.id)
            }
            .await;
            if app.shutdown.is_cancelled() {
                break;
            }
            match effect {
                Ok(job) => {
                    let _ =
                        omd_subscriptions::finish_action(&app.store, &id, Some(&job), None).await;
                }
                Err(error) => {
                    let _ = omd_subscriptions::finish_action(&app.store, &id, None, Some(&error.1))
                        .await;
                }
            }
        }
        tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }
}

async fn execute_job(app: &App, original: &Job, token: &CancellationToken) -> Result<(), Problem> {
    let mut job = original.clone();
    if app
        .acquisition
        .recover_publication(&job)
        .await
        .map_err(acquisition_problem)?
    {
        return Ok(());
    }
    let (manifest, path) = app
        .store
        .provider_version(
            &job.plan.release.reference.provider,
            &job.plan.provider_digest,
        )
        .await
        .map_err(|_| Problem {
            code: "source_unavailable".into(),
            message: "The approved source version is unavailable. Restore it and retry.".into(),
            retryable: false,
            actions: vec!["install_source".into()],
        })?;
    let source = Provider {
        manifest,
        component: path.into(),
        digest: job.plan.provider_digest.clone(),
    };
    source.verify().await.map_err(|e| ApiError::from(e).1)?;
    let journal = app
        .store
        .publication(&job.id)
        .await
        .map_err(|e| ApiError::from(e).1)?;
    // A published journal takes precedence over source/network availability. Otherwise
    // resumed work renews expiring transport locations without changing its approval.
    if journal.is_none()
        && (job.attempt > 1
            || job
                .plan
                .expires_at
                .as_ref()
                .is_some_and(|expiry| expiry < &omd_store::now()))
    {
        let request = ProviderRequest {
            release_order: None,
            discovery: None,
            credential_profile: job.plan.credential_profile.clone(),
            operation: "resolve".into(),
            reference: Some(job.plan.release.reference.clone()),
            query: None,
            url: None,
            cursor: None,
            page_size: 200,
            policy: job.plan.policy.clone(),
            now: omd_store::now(),
            // The approved plan's collection; `refresh` still requires it back.
            collection_hint: Some(job.plan.collection.reference.clone()),
        };
        let resolved = app
            .runtime
            .invoke::<ResolvedRelease>(&source, &request, token)
            .await
            .map_err(|e| ApiError::from(e).1)?;
        let replacement = build_plan_with_tools(
            app,
            &source,
            omd_media::Preparation {
                resolved,
                recipe: job.plan.recipe,
                policy: job.plan.policy.clone(),
                provider_digest: job.plan.provider_digest.clone(),
                credential_profile: job.plan.credential_profile.clone(),
            },
            token,
            job.plan.media.as_ref(),
        )
        .await
        .map_err(|e| e.1)?;
        if job.plan.refresh(&replacement).is_err() {
            forget_stale_enumerations(
                app,
                &[&job.plan.release.collection, &job.plan.collection.reference],
            )
            .await;
            return Err(Problem{code:"selection_changed".into(),message:"The source changed the approved outputs. Prepare this release again before downloading.".into(),retryable:false,actions:vec!["prepare_again".into()]});
        }
        job = app
            .store
            .refresh_job(&job.id, &replacement)
            .await
            .map_err(|e| ApiError::from(e).1)?;
    }
    if let Some(selection) = &job.plan.media {
        let media = app.runtime.media_for(selection).ok_or_else(|| Problem {
            code: "media_tools_unavailable".into(),
            message: "Restore the approved media tools to continue.".into(),
            retryable: false,
            actions: vec!["restore_tool".into()],
        })?;
        app.acquisition
            .execute_media(&job, &source.manifest.grants, &media, token)
            .await
            .map_err(acquisition_problem)
    } else {
        app.acquisition
            .execute(&job, &source.manifest.grants, token)
            .await
            .map_err(acquisition_problem)
    }
}
fn acquisition_problem(error: omd_acquisition::AcquisitionError) -> Problem {
    use omd_acquisition::AcquisitionError as E;
    let (code, action, retryable) = match &error {
        E::Destination | E::Store(omd_store::StoreError::Destination) => {
            ("destination_unavailable", "reconnect_destination", true)
        }
        E::Network(omd_network::NetworkError::Credential(error)) => {
            return ApiError::from(error.clone()).1;
        }
        E::Media(problem) => return problem.clone(),
        E::Collision => ("output_collision", "prepare_again", false),
        E::SourcePage => ("source_challenge", "retry", true),
        E::Integrity => ("integrity_failed", "retry", true),
        E::Canceled => ("paused", "resume", true),
        E::Network(omd_network::NetworkError::Denied) => {
            ("permission_denied", "review_source", false)
        }
        E::Recipe | E::Manifest => ("plan_invalid", "prepare_again", false),
        _ => ("acquisition_failed", "retry", true),
    };
    Problem {
        code: code.into(),
        message: error.to_string(),
        retryable,
        actions: vec![action.into()],
    }
}
pub async fn run_jobs(app: App) {
    let mut last_cleanup = tokio::time::Instant::now() - Duration::from_secs(60);
    loop {
        if app.shutdown.is_cancelled() {
            break;
        }
        if last_cleanup.elapsed() >= Duration::from_secs(60) {
            let _ = app.acquisition.cleanup_completed().await;
            last_cleanup = tokio::time::Instant::now();
        }
        let claimed = {
            let mut running = app.running.lock().await;
            app.store.claim().await.map(|job| {
                job.map(|job| {
                    let token = app.shutdown.child_token();
                    running.insert(job.id.clone(), token.clone());
                    (job, token)
                })
            })
        };
        match claimed {
            Ok(Some((job, token))) => {
                let result = execute_job(&app, &job, &token).await;
                if let Err(mut issue) = result {
                    if token.is_cancelled() {
                        issue.code = "paused".into();
                        issue.actions = vec!["resume".into()];
                    }
                    let _ = app
                        .store
                        .transition(
                            &job.id,
                            &["transferring", "verifying", "publishing"],
                            if token.is_cancelled()
                                || matches!(
                                    issue.code.as_str(),
                                    "destination_unavailable"
                                        | "source_unavailable"
                                        | "source_removed"
                                )
                            {
                                "paused"
                            } else {
                                "failed"
                            },
                            Some(&issue),
                        )
                        .await;
                }
                app.running.lock().await.remove(&job.id);
            }
            Ok(None) => {
                tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(200))=>{}}
            }
            Err(error) => {
                tracing::error!(error=%error,"job queue unavailable");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

impl From<omd_credentials::Error> for ApiError {
    fn from(error: omd_credentials::Error) -> Self {
        ApiError(StatusCode::CONFLICT, error.problem())
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SaveCredentials {
    label: String,
    session: omd_credentials::Session,
}
async fn credentials(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(page): Query<List>,
) -> ApiResult<Value> {
    use sqlx::Row;
    let source = provider(&app, &id).await?;
    let limit = page.limit.unwrap_or(50).clamp(1, 200);
    let rows=sqlx::query("SELECT profile,label,updated_at FROM credential_profiles WHERE provider=? AND profile>? AND instr(lower(label),lower(?))>0 ORDER BY profile LIMIT ?")
        .bind(&id).bind(page.cursor.as_deref().unwrap_or("")).bind(&page.q).bind(i64::from(limit)+1).fetch_all(&app.store.pool).await.map_err(omd_store::StoreError::from)?;
    let next_cursor = if rows.len() > limit as usize {
        Some(rows[limit as usize - 1].get::<String, _>("profile"))
    } else {
        None
    };
    let mut items = Vec::new();
    for row in rows.into_iter().take(limit as usize) {
        let profile: String = row.get("profile");
        let status = app
            .acquisition
            .network
            .session(&id, Some(&profile), &source.manifest.grants)
            .await;
        let issue = match status {
            Ok(_) => None,
            Err(omd_network::NetworkError::Credential(e)) => Some(ApiError::from(e).1),
            Err(_) => Some(Problem::new(
                "credentials_unavailable",
                "The credential store is unavailable.",
            )),
        };
        items.push(json!({"profile":profile,"label":row.get::<String,_>("label"),"updated_at":row.get::<String,_>("updated_at"),"status":if issue.is_none(){"ready"}else{"attention"},"issue":issue}));
    }
    Ok(Json(json!({"items":items,"next_cursor":next_cursor})))
}
async fn save_credentials(
    State(app): State<App>,
    Path((id, profile)): Path<(String, String)>,
    Json(request): Json<SaveCredentials>,
) -> ApiResult<Value> {
    let _changes = app.source_changes.lock().await;
    save_credentials_locked(&app, id, profile, request).await
}
// Caller holds source_changes through source validation and the vault commit.
async fn save_credentials_locked(
    app: &App,
    id: String,
    profile: String,
    request: SaveCredentials,
) -> ApiResult<Value> {
    if profile.is_empty()
        || profile.len() > 128
        || !profile
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        || request.label.trim().is_empty()
        || request.label.len() > 200
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "credential_profile_invalid",
            "Use a short account name and an alphanumeric profile identifier.",
        ));
    }
    let source = provider(app, &id).await?;
    request.session.validate(&source.manifest.grants)?;
    let vault = app
        .acquisition
        .network
        .vault
        .as_ref()
        .ok_or(omd_credentials::Error::Unavailable)?;
    // Record the handle first: interruption leaves an actionable missing session,
    // never an undiscoverable secret or a plaintext recovery copy.
    let mut tx = app
        .store
        .pool
        .begin()
        .await
        .map_err(omd_store::StoreError::from)?;
    sqlx::query("INSERT INTO credential_profiles(provider,profile,label,updated_at) VALUES(?,?,?,?) ON CONFLICT(provider,profile) DO UPDATE SET label=excluded.label,updated_at=excluded.updated_at")
        .bind(&id).bind(&profile).bind(request.label.trim()).bind(omd_store::now()).execute(&mut *tx).await.map_err(omd_store::StoreError::from)?;
    omd_store::emit(&mut tx, "credentials", &id).await?;
    tx.commit().await.map_err(omd_store::StoreError::from)?;
    vault
        .save(&id, &profile, &request.session, &source.manifest.grants)
        .await?;
    // The handle is committed before the secret for crash recovery. Notify again
    // after the vault write: a client may have observed the handle while it still
    // had the old or missing session, especially with a slow OS credential store.
    let mut tx = app
        .store
        .pool
        .begin()
        .await
        .map_err(omd_store::StoreError::from)?;
    omd_store::emit(&mut tx, "credentials", &id).await?;
    tx.commit().await.map_err(omd_store::StoreError::from)?;
    Ok(Json(json!({"profile":profile,"saved":true})))
}
async fn revoke_credentials(
    State(app): State<App>,
    Path((id, profile)): Path<(String, String)>,
) -> ApiResult<Value> {
    let _changes = app.source_changes.lock().await;
    let vault = app
        .acquisition
        .network
        .vault
        .as_ref()
        .ok_or(omd_credentials::Error::Unavailable)?;
    vault.revoke(&id, &profile).await?;
    let mut tx = app
        .store
        .pool
        .begin()
        .await
        .map_err(omd_store::StoreError::from)?;
    // Keep the non-secret account handle so clients can replace credentials at
    // the same identity. Jobs and subscriptions must not become impossible to
    // reauthenticate after revocation.
    sqlx::query("UPDATE credential_profiles SET updated_at=? WHERE provider=? AND profile=?")
        .bind(omd_store::now())
        .bind(&id)
        .bind(&profile)
        .execute(&mut *tx)
        .await
        .map_err(omd_store::StoreError::from)?;
    omd_store::emit(&mut tx, "credentials", &id).await?;
    tx.commit().await.map_err(omd_store::StoreError::from)?;
    Ok(Json(json!({"revoked":true})))
}

async fn build_plan(
    app: &App,
    source: &Provider,
    request: omd_media::Preparation,
    cancel: &CancellationToken,
) -> Result<Plan, ApiError> {
    build_plan_with_tools(app, source, request, cancel, None).await
}
async fn build_plan_with_tools(
    app: &App,
    source: &Provider,
    request: omd_media::Preparation,
    cancel: &CancellationToken,
    selection: Option<&MediaSelection>,
) -> Result<Plan, ApiError> {
    app.runtime
        .authorized(
            source,
            cancel,
            Duration::from_secs(180),
            build_plan_inner(app, source, request, cancel, selection),
        )
        .await?
}
async fn build_plan_inner(
    app: &App,
    source: &Provider,
    request: omd_media::Preparation,
    cancel: &CancellationToken,
    selection: Option<&MediaSelection>,
) -> Result<Plan, ApiError> {
    let mut plan = if matches!(
        request.recipe,
        Recipe::Cbz | Recipe::ImageFolder | Recipe::OriginalImages
    ) {
        let mut plan = omd_acquisition::prepare(
            request.resolved,
            request.recipe,
            request.policy,
            request.provider_digest,
        )
        .map_err(|e| ApiError(StatusCode::CONFLICT, acquisition_problem(e)))?;
        plan.credential_profile = request.credential_profile;
        plan
    } else {
        if !source.manifest.media_tools {
            return Err(problem(
                StatusCode::CONFLICT,
                "source_recipe",
                "This source provides image releases. Choose CBZ or chapter folders.",
            ));
        }
        let media = selection
            .map_or_else(
                || app.runtime.media(),
                |selection| app.runtime.media_for(selection),
            )
            .ok_or_else(|| {
                problem(
                    StatusCode::CONFLICT,
                    "media_tools_unavailable",
                    "Install the approved managed media tools before preparing this source.",
                )
            })?;
        media
            .prepare(request, &source.manifest.grants, cancel)
            .await
            .map_err(|issue| ApiError(StatusCode::CONFLICT, issue))?
    };
    app.store.apply_presentation(&mut plan).await?;
    Ok(plan)
}

#[cfg(test)]
mod account_mode_tests {
    use super::*;
    fn manifest(mode: Value, sign_in: bool, credential: bool) -> Value {
        let mut value = serde_json::json!({"api": PLUGIN_API, "id":"org.example.source", "name":"Example", "version":"1", "description":"Synthetic", "source_hosts":["example.org"], "capabilities":[], "grants":[{"id":"source","hosts":["example.org"],"methods":["GET"],"credential":credential}]});
        if !mode.is_null() {
            value["account_mode"] = mode;
        }
        if sign_in {
            value["sign_in"] = serde_json::json!({"url":"https://example.org/login","completion_cookies":["session"],"grants":[]});
        }
        value
    }
    #[test]
    fn account_modes_validate_against_reviewed_permissions() {
        for mode in ["cookies", "header", "browser"] {
            for sign_in in [false, true] {
                let value = manifest(serde_json::json!(mode), sign_in, true);
                let m: ProviderManifest = serde_json::from_value(value).unwrap();
                assert_eq!(validate_manifest(&m).is_ok(), mode != "browser" || sign_in);
            }
            let m =
                serde_json::from_value(manifest(serde_json::json!(mode), false, false)).unwrap();
            assert!(validate_manifest(&m).is_err());
        }
        let legacy = serde_json::from_value(manifest(Value::Null, false, false)).unwrap();
        assert!(validate_manifest(&legacy).is_ok());
    }
    #[test]
    fn malformed_account_modes_reject() {
        for mode in [
            serde_json::json!("automatic"),
            serde_json::json!({"mode":"cookies"}),
            serde_json::json!(true),
            serde_json::json!(["cookies"]),
        ] {
            assert!(
                serde_json::from_value::<ProviderManifest>(manifest(mode, false, true)).is_err()
            );
        }
    }
}
#[cfg(test)]
mod display_path_tests {
    use super::*;
    #[test]
    fn responses_show_the_ordinary_root_but_keep_other_fields() {
        let stored = Destination {
            id: "dest_1".into(),
            label: "Downloads".into(),
            root: r"\\?\C:\Users\OMD\Downloads\OMD".into(),
            available: true,
            storage_operation: None,
        };
        let shown = shown_destination(stored.clone());
        #[cfg(windows)]
        assert_eq!(shown.root, r"C:\Users\OMD\Downloads\OMD");
        #[cfg(not(windows))]
        assert_eq!(shown.root, stored.root);
        assert_eq!(
            (shown.id, shown.label, shown.available),
            (stored.id, stored.label, stored.available)
        );
    }
}

#[cfg(test)]
mod sign_in_helper_tests {
    #[test]
    fn the_sign_in_helper_is_the_bundled_app_only_on_macos_when_installed() {
        let root = tempfile::tempdir().unwrap();
        let engine = root.path().join("omd-engine");
        let bare = root.path().join(if cfg!(windows) {
            "omd-signin.exe"
        } else {
            "omd-signin"
        });
        assert_eq!(super::sign_in_helper(&engine), bare);
        let bundle = root
            .path()
            .join(super::SIGN_IN_BUNDLE)
            .join("Contents/MacOS");
        // A bundle folder without its executable is not used.
        std::fs::create_dir_all(&bundle).unwrap();
        assert_eq!(super::sign_in_helper(&engine), bare);
        std::fs::write(bundle.join("omd-signin"), b"").unwrap();
        let expected = if cfg!(target_os = "macos") {
            bundle.join("omd-signin")
        } else {
            bare
        };
        assert_eq!(super::sign_in_helper(&engine), expected);
    }
}
