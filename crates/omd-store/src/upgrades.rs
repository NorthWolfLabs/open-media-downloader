//! Consistent private snapshots before applying migrations to existing profiles.
use crate::{Result, StoreError};
use sqlx::{SqlitePool, migrate::Migrator};
use std::path::Path;

pub async fn protect(pool: &SqlitePool, path: &Path, migrator: &Migrator) -> Result<()> {
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations'",
    )
    .fetch_one(pool)
    .await?;
    if present == 0 {
        return Ok(());
    }
    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success=1")
            .fetch_all(pool)
            .await?;
    let supported: Vec<i64> = migrator.iter().map(|m| m.version).collect();
    if applied.iter().any(|v| !supported.contains(v)) {
        return Err(StoreError::Migration("This profile was migrated by a newer or incompatible OMD build. Reinstall that build; restore a pre-migration backup into a separate profile before attempting a downgrade.".into()));
    }
    if supported.iter().all(|v| applied.contains(v)) {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        StoreError::Migration("The profile database needs a parent directory.".into())
    })?;
    let name = format!(
        "pre-migration-{}-{}",
        supported.last().copied().unwrap_or(0),
        uuid::Uuid::new_v4().simple()
    );
    let partial = parent.join(format!("{name}.partial"));
    let backup = parent.join(format!("{name}.sqlite3"));
    drop(omd_files::create_private_file(&partial).map_err(|_|StoreError::Migration("Could not create a private pre-migration backup. Free disk space and check profile permissions before retrying.".into()))?);
    // Includes committed WAL data. Copying an open .sqlite3 alone does not.
    let result =
        sqlx::query("VACUUM INTO ?")
            .bind(partial.to_str().ok_or_else(|| {
                StoreError::Migration("The backup path is not valid Unicode.".into())
            })?)
            .execute(pool)
            .await;
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
        return Err(StoreError::Migration("Could not complete the pre-migration backup. Free disk space and retry; migrations have not started.".into()));
    }
    std::fs::rename(&partial, &backup).map_err(|_| {
        StoreError::Migration(
            "Could not finalize the pre-migration backup; migrations have not started.".into(),
        )
    })?;
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|p| p.sync_all())
        .map_err(|_| {
            StoreError::Migration(
                "Could not sync the pre-migration backup; migrations have not started.".into(),
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::Store;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    #[tokio::test]
    async fn upgrade_keeps_wal_data_in_a_private_snapshot_and_does_not_repeat_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.sqlite3");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
            )
            .await
            .unwrap();
        let mut old = sqlx::migrate!();
        old.migrations =
            std::borrow::Cow::Owned(old.iter().take(old.iter().len() - 1).cloned().collect());
        old.run(&pool).await.unwrap();
        sqlx::query("INSERT INTO settings VALUES('preferences','{\"languages\":[\"en\"]}')")
            .execute(&pool)
            .await
            .unwrap();
        // The older connection remains open, so its data may still be in WAL.
        let current = Store::open(&path).await.unwrap();
        assert_eq!(
            current.setting("preferences").await.unwrap().unwrap()["languages"][0],
            "en"
        );
        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|p| p.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("pre-migration-")
            })
            .collect();
        assert_eq!(backups.len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&backups[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let snapshot = SqlitePoolOptions::new()
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&backups[0])
                    .read_only(true),
            )
            .await
            .unwrap();
        let value: String =
            sqlx::query_scalar("SELECT value_json FROM settings WHERE key='preferences'")
                .fetch_one(&snapshot)
                .await
                .unwrap();
        assert!(value.contains("languages"));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&snapshot)
            .await
            .unwrap();
        assert_eq!(count, old.iter().len() as i64);
        snapshot.close().await;
        pool.close().await;
        current.pool.close().await;
        let reopened = Store::open(&path).await.unwrap();
        reopened.pool.close().await;
        assert_eq!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter(|p| p
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("pre-migration-"))
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn newer_database_is_refused_without_removing_its_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.sqlite3");
        let store = Store::open(&path).await.unwrap();
        sqlx::query("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(9999,'future',1,X'00',0)").execute(&store.pool).await.unwrap();
        store.pool.close().await;
        let error = Store::open(&path).await.err().unwrap();
        assert!(error.to_string().contains("newer or incompatible"));
        let pool = SqlitePoolOptions::new()
            .connect_with(SqliteConnectOptions::new().filename(&path).read_only(true))
            .await
            .unwrap();
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version=9999")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
        pool.close().await;
    }
}
