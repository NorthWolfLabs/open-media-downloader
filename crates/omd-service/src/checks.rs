use super::*;
use omd_storage::{
    Storage,
    checks::{DestinationCheck, DestinationCheckFile},
};
pub(crate) async fn create(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<DestinationCheck> {
    Ok(Json(
        Storage { store: app.store }
            .create_destination_check(&id)
            .await?,
    ))
}
pub(crate) async fn list(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<DestinationCheck>> {
    Ok(Json(
        Storage { store: app.store }
            .destination_checks(
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
) -> ApiResult<DestinationCheck> {
    Ok(Json(
        Storage { store: app.store }.destination_check(&id).await?,
    ))
}
pub(crate) async fn files(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<DestinationCheckFile>> {
    Ok(Json(
        Storage { store: app.store }
            .destination_check_files(
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
) -> ApiResult<DestinationCheck> {
    Ok(Json(
        Storage { store: app.store }
            .destination_check_action(&id, &action)
            .await?,
    ))
}
