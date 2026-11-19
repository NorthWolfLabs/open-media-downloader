use super::*;
use omd_notifications::{Batch, Message, Settings, Status};
#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct Accepted {
    accepted: bool,
}
pub(crate) async fn status(State(app): State<App>) -> ApiResult<Status> {
    Ok(Json(omd_notifications::status(&app.store).await?))
}
pub(crate) async fn configure(
    State(app): State<App>,
    Json(input): Json<Settings>,
) -> ApiResult<Status> {
    let _guard = app.notification_lock.lock().await;
    Ok(Json(
        omd_notifications::configure(&app.store, &input).await?,
    ))
}
pub(crate) async fn history(
    State(app): State<App>,
    Query(q): Query<List>,
) -> ApiResult<Page<Batch>> {
    Ok(Json(
        omd_notifications::list(
            &app.store,
            &q.q,
            q.cursor.as_deref(),
            q.limit.unwrap_or(100),
        )
        .await?,
    ))
}
pub(crate) async fn test(State(app): State<App>) -> ApiResult<Accepted> {
    let _guard = app.notification_lock.lock().await;
    omd_notifications::deliver(
        &app.notification_adapter,
        &Message {
            count: 1,
            test: true,
        },
        &app.shutdown,
    )
    .await
    .map_err(|p| ApiError(StatusCode::SERVICE_UNAVAILABLE, p))?;
    Ok(Json(Accepted { accepted: true }))
}
pub(crate) async fn control(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<Status> {
    let _guard = app.notification_lock.lock().await;
    let batch = omd_notifications::control(&app.store, &id, &action).await?;
    if action == "retry" {
        let result = omd_notifications::deliver(
            &app.notification_adapter,
            &Message {
                count: batch.count.min(u32::MAX as i64) as u32,
                test: false,
            },
            &app.shutdown,
        )
        .await;
        omd_notifications::finish(&app.store, &id, result).await?;
    }
    Ok(Json(omd_notifications::status(&app.store).await?))
}
pub async fn run(app: App) {
    loop {
        tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(5))=>{}}
        let _guard = app.notification_lock.lock().await;
        match omd_notifications::claim(&app.store).await {
            Ok(Some(batch)) => {
                let result = omd_notifications::deliver(
                    &app.notification_adapter,
                    &Message {
                        count: batch.count.min(u32::MAX as i64) as u32,
                        test: false,
                    },
                    &app.shutdown,
                )
                .await;
                if omd_notifications::finish(&app.store, &batch.id, result)
                    .await
                    .is_err()
                {
                    tracing::warn!("Notification delivery journal requires restart recovery");
                }
            }
            Ok(None) => {}
            Err(_) => tracing::warn!("Notification queue is temporarily unavailable"),
        }
    }
}
