use super::*;
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetadataQuery {
    source_id: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetadataWrite {
    reference: SourceRef,
    overrides: MetadataOverride,
}
fn validate(kind: &str, reference: &SourceRef) -> Result<(), ApiError> {
    if !["collection", "release"].contains(&kind) || reference.validate().is_err() {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "metadata_reference_invalid",
            "Choose a collection or release with a namespaced source identity.",
        ));
    }
    Ok(())
}
pub(crate) async fn get_metadata(
    State(app): State<App>,
    Path((kind, provider)): Path<(String, String)>,
    Query(query): Query<MetadataQuery>,
) -> ApiResult<MetadataOverride> {
    let reference = SourceRef {
        provider,
        id: query.source_id,
    };
    validate(&kind, &reference)?;
    Ok(Json(app.store.metadata_override(&kind, &reference).await?))
}
pub(crate) async fn put_metadata(
    State(app): State<App>,
    Path(kind): Path<String>,
    Json(value): Json<MetadataWrite>,
) -> ApiResult<MetadataOverride> {
    validate(&kind, &value.reference)?;
    value
        .overrides
        .validate(kind == "collection")
        .map_err(|e| problem(StatusCode::BAD_REQUEST, "metadata_invalid", &e.to_string()))?;
    app.store
        .set_metadata_override(&kind, &value.reference, &value.overrides)
        .await?;
    Ok(Json(value.overrides))
}
pub(crate) async fn get_naming(State(app): State<App>) -> ApiResult<NamingTemplates> {
    Ok(Json(
        app.store
            .setting("naming")
            .await?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| {
                problem(
                    StatusCode::CONFLICT,
                    "naming_invalid",
                    "Saved naming templates require correction.",
                )
            })?
            .unwrap_or_default(),
    ))
}
pub(crate) async fn put_naming(
    State(app): State<App>,
    Json(value): Json<NamingTemplates>,
) -> ApiResult<NamingTemplates> {
    value
        .validate()
        .map_err(|e| problem(StatusCode::BAD_REQUEST, "naming_invalid", &e.to_string()))?;
    app.store
        .set_setting("naming", &serde_json::to_value(&value).unwrap())
        .await?;
    Ok(Json(value))
}
