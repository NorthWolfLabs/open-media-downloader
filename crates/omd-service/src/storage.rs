use super::*;
use omd_storage::{FileEntry, Operation, Storage};
impl From<omd_storage::Error> for ApiError {
    fn from(error: omd_storage::Error) -> Self {
        match error {
            omd_storage::Error::Store(error) => error.into(),
            other => ApiError(StatusCode::CONFLICT, other.problem()),
        }
    }
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Relocate {
    target_root: String,
}
pub(crate) async fn create(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(request): Json<Relocate>,
) -> ApiResult<Operation> {
    let storage = Storage {
        store: app.store.clone(),
    };
    let operation = storage
        .create(&id, std::path::Path::new(&request.target_root))
        .await?;
    // The database blocks new claims first. Signal running work so partial bytes
    // checkpoint before the storage worker starts its inventory.
    let running = app.running.lock().await;
    for (job, token) in running.iter() {
        if app.store.job(job).await?.destination_id == id {
            token.cancel();
        }
    }
    Ok(Json(shown(operation)))
}
/// Responses use the ordinary spelling of the stored canonical roots (no
/// Windows `\\?\` prefix when equivalent); stored values stay exact.
fn shown(mut operation: Operation) -> Operation {
    for root in [&mut operation.source_root, &mut operation.target_root] {
        *root = omd_files::display_path(std::path::Path::new(root.as_str()));
    }
    operation
}
pub(crate) async fn list(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<Operation>> {
    let page = Storage { store: app.store }
        .operations(
            query.cursor.as_deref(),
            &query.q,
            query.limit.unwrap_or(100),
        )
        .await?;
    Ok(Json(Page {
        items: page.items.into_iter().map(shown).collect(),
        next_cursor: page.next_cursor,
    }))
}
pub(crate) async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Operation> {
    Ok(Json(shown(
        Storage { store: app.store }.operation(&id).await?,
    )))
}
pub(crate) async fn files(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<FileEntry>> {
    Ok(Json(
        Storage { store: app.store }
            .entries(
                &id,
                query.cursor.as_deref(),
                &query.q,
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
pub(crate) async fn action(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<Operation> {
    Ok(Json(shown(
        Storage { store: app.store }.action(&id, &action).await?,
    )))
}
pub async fn run_storage(app: App) {
    let storage = Storage {
        store: app.store.clone(),
    };
    loop {
        if app.shutdown.is_cancelled() {
            break;
        }
        match storage.next_file_operation().await {
            Ok(Some(operation)) => {
                let token = app.shutdown.child_token();
                let work = storage.step_file_operation(&operation, &token);
                tokio::pin!(work);
                let mut interval = tokio::time::interval(Duration::from_millis(250));
                let result = loop {
                    tokio::select! {
                        result=&mut work=>break result,
                        _=interval.tick()=>{
                            if operation.mode==omd_storage::maintenance::Mode::Reconcile && storage.file_operation(&operation.id).await.is_ok_and(|current|current.state!="working"||current.issue.is_some()){token.cancel();}
                        }
                    }
                };
                if let Err(error) = result {
                    if app.shutdown.is_cancelled() {
                        break;
                    }
                    if !token.is_cancelled() {
                        let _ = storage.fail_file_operation(&operation.id, &error).await;
                    }
                }
                tokio::task::yield_now().await;
                continue;
            }
            Ok(None) => {}
            Err(_) => tracing::warn!("File operation queue temporarily unavailable"),
        }
        match storage.next().await {
            Ok(Some(operation)) => {
                let mut quiescent = true;
                if operation.state == "scanning" {
                    for (id, token) in app.running.lock().await.iter() {
                        if app
                            .store
                            .job(id)
                            .await
                            .is_ok_and(|job| job.destination_id == operation.destination_id)
                        {
                            token.cancel();
                            quiescent = false;
                        }
                    }
                }
                if quiescent {
                    let token = app.shutdown.child_token();
                    let work = storage.step(&operation, &token);
                    tokio::pin!(work);
                    let mut interval = tokio::time::interval(Duration::from_millis(250));
                    let result = loop {
                        tokio::select! {
                            result=&mut work=>break result,
                            _=interval.tick()=>{if storage.operation(&operation.id).await.is_ok_and(|current|current.state=="canceled"){token.cancel();}}
                        }
                    };
                    if let Err(error) = result {
                        if app.shutdown.is_cancelled() {
                            break;
                        }
                        let _ = storage.fail(&operation, &error).await;
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
            }
            Ok(None) => {}
            Err(_) => tracing::warn!("Storage operation queue temporarily unavailable"),
        }
        tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(250))=>{}}
    }
}
