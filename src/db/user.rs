use chrono::{DateTime, Utc};
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{crypto, error::ShlossResult};

// Dead code is allowed, because we want a consistent in memory model of the DB data even if some
// or all fields are never read!
#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub(crate) id: Uuid,
    pub(crate) vault_id: Uuid,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

impl User {
    pub async fn create(pool: &PgPool, vault_id: &Uuid) -> ShlossResult<Self> {
        let id = crypto::generate_uuid();
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users (id, vault_id) VALUES ($1, $2) RETURNING id, vault_id, created_at, updated_at",
            id, vault_id
        )
        .fetch_one(pool)
        .await?;
        Ok(user)
    }
    pub async fn delete(pool: &PgPool, id: &Uuid, vault_id: &Uuid) -> ShlossResult<bool> {
        let rows = sqlx::query!(
            "DELETE FROM users WHERE id = $1 AND vault_id = $2",
            id,
            vault_id
        )
        .execute(pool)
        .await?
        .rows_affected();
        Ok(rows > 0)
    }
    pub async fn get_username(
        pool: &PgPool,
        id: &Uuid,
        vault_id: &Uuid,
    ) -> ShlossResult<Option<String>> {
        let username = sqlx::query_scalar!(
            "SELECT pc.username FROM users u JOIN password_credentials pc ON u.id = pc.user_id WHERE u.id = $1 AND u.vault_id = $2",
            id,
            vault_id
        )
        .fetch_optional(pool)
        .await?;

        Ok(username)
    }
    pub async fn get_from_username(
        pool: &PgPool,
        username: &str,
        vault_id: &Uuid,
    ) -> ShlossResult<Option<Self>> {
        let user = sqlx::query_as!(
            User,
            "SELECT u.* FROM users u JOIN password_credentials pc ON u.id = pc.user_id  WHERE u.vault_id = $2 AND pc.username = $1",
            username,
            vault_id,
        )
            .fetch_optional(pool).await?;
        Ok(user)
    }
    pub async fn get_from_api_key(
        pool: &PgPool,
        hash: &str,
        vault_id: &Uuid,
    ) -> ShlossResult<Option<Self>> {
        let user = sqlx::query_as!(
            User,
            "SELECT u.*
            FROM users u JOIN api_keys a ON u.id = a.user_id
            WHERE u.vault_id = $2 AND a.hash = $1 AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > NOW())",
            hash,
            vault_id,
        ).fetch_optional(pool).await?;
        Ok(user)
    }
}
