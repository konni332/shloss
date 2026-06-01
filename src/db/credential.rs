use chrono::{DateTime, Utc};
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{crypto::generate_uuid, error::ShlossResult};

// Dead code is allowed, because we want a consistent in memory model of the DB data even if some
// or all fields are never read!
#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct PasswordCredential {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) username: String,
    pub(crate) hash: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

// Dead code is allowed, because we want a consistent in memory model of the DB data even if some
// or all fields are never read!
#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct ApiKey {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) name: String,
    pub(crate) key_prefix: String,
    pub(crate) hash: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) last_used_at: Option<DateTime<Utc>>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) revoked_at: Option<DateTime<Utc>>,
}

impl PasswordCredential {
    pub async fn create(
        pool: &PgPool,
        user_id: &Uuid,
        username: &str,
        hash: &str,
    ) -> ShlossResult<Self> {
        let id = generate_uuid();
        let cred = sqlx::query_as!(
            PasswordCredential,
            r#"INSERT INTO password_credentials (id, user_id, username, hash) VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, username, hash, created_at, updated_at"#,
            id, user_id, username, hash,
            ).fetch_one(pool).await?;
        Ok(cred)
    }
    pub async fn delete(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!("DELETE FROM password_credentials WHERE id = $1", id)
            .execute(pool)
            .await?;
        Ok(())
    }
    pub async fn update_password(
        pool: &PgPool,
        user_id: &Uuid,
        new_hash: &str,
    ) -> ShlossResult<bool> {
        let result = sqlx::query!(
            "UPDATE password_credentials SET hash = $2, updated_at = NOW() WHERE user_id = $1",
            user_id,
            new_hash,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
    pub async fn update_username(
        pool: &PgPool,
        user_id: &Uuid,
        new_username: &str,
    ) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE password_credentials SET username = $2, updated_at = NOW() WHERE user_id = $1",
            user_id,
            new_username,
        )
        .execute(pool)
        .await?;

        Ok(())
    }
    pub async fn fetch_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<Option<Self>> {
        let cred = sqlx::query_as!(
            PasswordCredential,
            "SELECT * FROM password_credentials WHERE user_id = $1",
            user_id
        )
        .fetch_optional(pool)
        .await?;
        Ok(cred)
    }
    pub async fn get_hash_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<Option<String>> {
        let hash = sqlx::query_scalar!(
            "SELECT hash FROM password_credentials WHERE user_id = $1",
            user_id
        )
        .fetch_optional(pool)
        .await?;
        Ok(hash)
    }
}

impl ApiKey {
    pub async fn create(
        pool: &PgPool,
        user_id: &Uuid,
        name: &str,
        key_prefix: &str,
        hash: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> ShlossResult<Self> {
        let id = generate_uuid();
        let api_key = sqlx::query_as!(
            ApiKey,
            r#"INSERT INTO api_keys (id, user_id, name, key_prefix, hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *"#,
            id, user_id, name, key_prefix, hash, expires_at
        ).fetch_one(pool).await?;

        Ok(api_key)
    }
    pub async fn revoke(pool: &PgPool, hash: &str, user_id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE api_keys SET revoked_at = NOW() WHERE hash = $1 AND user_id = $2",
            hash,
            user_id
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn fetch_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<Vec<ApiKey>> {
        let api_keys =
            sqlx::query_as!(ApiKey, "SELECT * FROM api_keys WHERE user_id = $1", user_id)
                .fetch_all(pool)
                .await?;
        Ok(api_keys)
    }
    pub async fn revoke_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE api_keys SET revoked_at = NOW() WHERE user_id = $1",
            user_id
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn update_used(pool: &PgPool, hash: &str) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE api_keys SET last_used_at = NOW() WHERE hash = $1",
            hash
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
