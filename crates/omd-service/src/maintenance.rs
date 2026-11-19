use super::*;
use omd_storage::{
    Storage,
    maintenance::{FileEntry, FileOperation, Mode},
};
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "FileOperationRequest")]
pub(crate) struct Request {
    mode: Mode,
}
pub(crate) async fn create(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(request): Json<Request>,
) -> ApiResult<FileOperation> {
    Ok(Json(
        Storage { store: app.store }
            .create_file_operation(&id, request.mode)
            .await?,
    ))
}
pub(crate) async fn list(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<FileOperation>> {
    Ok(Json(
        Storage { store: app.store }
            .file_operations(
                &query.q,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
pub(crate) async fn get(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<FileOperation> {
    Ok(Json(
        Storage { store: app.store }.file_operation(&id).await?,
    ))
}
pub(crate) async fn files(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<FileEntry>> {
    Ok(Json(
        Storage { store: app.store }
            .file_operation_entries(
                &id,
                &query.q,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
pub(crate) async fn action(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<FileOperation> {
    Ok(Json(
        Storage { store: app.store }
            .file_action(&id, &action)
            .await?,
    ))
}
