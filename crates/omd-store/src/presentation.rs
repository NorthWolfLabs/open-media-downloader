use super::*;
impl Store {
    pub async fn metadata_override(
        &self,
        kind: &str,
        reference: &SourceRef,
    ) -> Result<MetadataOverride> {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT data_json FROM metadata_overrides WHERE kind=? AND source_key=?",
        )
        .bind(kind)
        .bind(reference.key())
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(|v| serde_json::from_str(&v))
            .transpose()
            .map(|v| v.unwrap_or_default())
            .map_err(Into::into)
    }
    pub async fn set_metadata_override(
        &self,
        kind: &str,
        reference: &SourceRef,
        value: &MetadataOverride,
    ) -> Result<()> {
        if !["collection", "release"].contains(&kind)
            || value.validate(kind == "collection").is_err()
        {
            return Err(StoreError::StateConflict);
        }
        let mut tx = self.pool.begin().await?;
        if value == &MetadataOverride::default() {
            sqlx::query("DELETE FROM metadata_overrides WHERE kind=? AND source_key=?")
                .bind(kind)
                .bind(reference.key())
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("INSERT INTO metadata_overrides VALUES(?,?,?,?,?) ON CONFLICT(kind,source_key) DO UPDATE SET reference_json=excluded.reference_json,data_json=excluded.data_json,updated_at=excluded.updated_at").bind(kind).bind(reference.key()).bind(serde_json::to_string(reference)?).bind(serde_json::to_string(value)?).bind(now()).execute(&mut *tx).await?;
        }
        emit(&mut tx, "metadata.changed", &reference.key()).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn apply_presentation(&self, plan: &mut Plan) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for (kind, reference, value) in [
            (
                "collection",
                &plan.collection.reference,
                &mut plan.metadata.collection,
            ),
            (
                "release",
                &plan.release.reference,
                &mut plan.metadata.release,
            ),
        ] {
            let data: Option<String> = sqlx::query_scalar(
                "SELECT data_json FROM metadata_overrides WHERE kind=? AND source_key=?",
            )
            .bind(kind)
            .bind(reference.key())
            .fetch_optional(&mut *tx)
            .await?;
            *value = data
                .map(|v| serde_json::from_str(&v))
                .transpose()?
                .unwrap_or_default();
        }
        let data: Option<String> =
            sqlx::query_scalar("SELECT value_json FROM settings WHERE key='naming'")
                .fetch_optional(&mut *tx)
                .await?;
        let naming: NamingTemplates = data
            .map(|v| serde_json::from_str(&v))
            .transpose()?
            .unwrap_or_default();
        plan.final_relative_path = naming.path(plan).map_err(|_| StoreError::StateConflict)?;
        tx.commit().await?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn overrides_survive_restart_without_mutating_provider_data_or_confirmed_jobs() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        let base: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let source = base.collection.clone();
        store.upsert_collection(&source).await.unwrap();
        store
            .set_metadata_override(
                "collection",
                &source.reference,
                &MetadataOverride {
                    title: Some("My series".into()),
                    description: Some("Custom description".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        store
            .set_metadata_override(
                "release",
                &base.release.reference,
                &MetadataOverride {
                    title: Some("My special".into()),
                    chapter: Some("12.5a".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        store
            .set_setting(
                "naming",
                &serde_json::to_value(NamingTemplates {
                    collection: "{title}".into(),
                    release: "{chapter} - {title}".into(),
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let mut first = base.clone();
        store.apply_presentation(&mut first).await.unwrap();
        let (first, _) = store
            .plan_intent(&first, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        let (job, _) = store
            .enqueue(&first, &dest.id, "first", "first", None)
            .await
            .unwrap();
        assert_eq!(job.title, "My special");
        assert!(first.final_relative_path.contains("12.5a - My special"));
        let provider: Collection = serde_json::from_str(
            &sqlx::query_scalar::<_, String>("SELECT data_json FROM collections WHERE key=?")
                .bind(source.reference.key())
                .fetch_one(&store.pool)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(provider, source);
        store
            .set_metadata_override(
                "release",
                &base.release.reference,
                &MetadataOverride {
                    title: Some("Later title".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        store.pool.close().await;
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let mut next = base.clone();
        store.apply_presentation(&mut next).await.unwrap();
        assert_eq!(next.release_title(), "Later title");
        assert_eq!(next.collection_title(), "My series");
        let (saved, outcome) = store
            .plan_intent(&next, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(outcome, "existing_job");
        assert_eq!(saved.release_title(), "My special");
        assert_eq!(saved.final_relative_path, first.final_relative_path);
        let (new, _) = store
            .plan_intent(&next, &dest.id, DuplicateBehavior::NewVersion)
            .await
            .unwrap();
        assert_eq!(new.generation, 2);
        assert!(new.final_relative_path.contains("Later title"));
        assert_ne!(new.final_relative_path, first.final_relative_path);
        store
            .set_metadata_override(
                "release",
                &base.release.reference,
                &MetadataOverride::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .metadata_override("release", &base.release.reference)
                .await
                .unwrap(),
            MetadataOverride::default()
        );
    }
}
