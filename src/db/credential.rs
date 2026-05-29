use chrono::{DateTime, Utc};
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{crypto::generate_uuid, error::ShlossResult};

#[derive(Debug, Clone, FromRow)]
pub struct PasswordCredential {
    id: Uuid,
    user_id: Uuid,
    username: String,
    hash: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ApiKey {
    id: Uuid,
    user_id: Uuid,
    name: String,
    key_prefix: String,
    hash: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
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
    ) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE password_credentials SET hash = $2, updated_at = NOW() WHERE user_id = $1",
            user_id,
            new_hash,
        )
        .execute(pool)
        .await?;

        Ok(())
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
    pub async fn update_used(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
