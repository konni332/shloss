use chrono::{DateTime, Utc};
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{
    crypto::{GeneratedToken, generate_uuid},
    error::ShlossResult,
};

// Dead code is allowed, because we want a consistent in memory model of the DB data even if some
// or all fields are never read!
#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct OpaqueToken {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) session_id: Uuid,
    pub(crate) hash: String,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) revoked_at: Option<DateTime<Utc>>,
}

// Dead code is allowed, because we want a consistent in memory model of the DB data even if some
// or all fields are never read!
#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
pub struct RefreshToken {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) session_id: Uuid,
    pub(crate) hash: String,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) revoked_at: Option<DateTime<Utc>>,
}

impl OpaqueToken {
    pub async fn create(
        pool: &PgPool,
        generated_token: GeneratedToken,
        user_id: &Uuid,
        session_id: &Uuid,
        expires_at: DateTime<Utc>,
    ) -> ShlossResult<Self> {
        let id = generate_uuid();
        let hash = generated_token.hash;
        let token = sqlx::query_as!(
            OpaqueToken,
            r#"INSERT INTO opaque_tokens (id, user_id, session_id, hash, expires_at) VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, session_id, hash, issued_at, expires_at, revoked_at"#,
            id, user_id, session_id, hash, expires_at
            )
            .fetch_one(pool)
            .await?;

        Ok(token)
    }
    pub async fn revoke_for_user(
        pool: &PgPool,
        user_id: &Uuid,
        vault_id: &Uuid,
    ) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE opaque_tokens SET revoked_at = NOW() WHERE user_id = (SELECT id FROM users WHERE id = $1 AND vault_id = $2)",
            user_id,
            vault_id,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn find_valid_by_hash(
        pool: &PgPool,
        hash: &str,
        vault_id: &Uuid,
    ) -> ShlossResult<Option<Self>> {
        let token = sqlx::query_as!(
            OpaqueToken,
            "SELECT o.* FROM opaque_tokens o
            JOIN users u ON o.user_id = u.id
            WHERE o.hash = $1
            AND o.revoked_at IS NULL
            AND o.expires_at > NOW()
            AND u.vault_id = $2",
            hash,
            vault_id,
        )
        .fetch_optional(pool)
        .await?;
        Ok(token)
    }
}

impl RefreshToken {
    pub async fn create(
        pool: &PgPool,
        generated_token: GeneratedToken,
        user_id: &Uuid,
        session_id: &Uuid,
        expires_at: DateTime<Utc>,
    ) -> ShlossResult<Self> {
        let id = generate_uuid();
        let hash = generated_token.hash;
        let token = sqlx::query_as!(
            RefreshToken,
            r#"INSERT INTO refresh_tokens (id, user_id, session_id, hash, expires_at) VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, session_id, hash, issued_at, expires_at, revoked_at"#,
            id, user_id, session_id, hash, expires_at
            )
            .fetch_one(pool)
            .await?;

        Ok(token)
    }
    pub async fn rotate(
        pool: &PgPool,
        id: &Uuid,
        generated_token: GeneratedToken,
    ) -> ShlossResult<Option<Self>> {
        let record = sqlx::query!(
            "SELECT issued_at, expires_at FROM refresh_tokens WHERE id = $1",
            id
        )
        .fetch_one(pool)
        .await?;
        let now = Utc::now();
        // compute the time to live of last refresh token + now
        let expires_at = now + (record.expires_at - record.issued_at);

        let hash = generated_token.hash;

        let new_refresh = sqlx::query_as!(
            RefreshToken,
            r#"UPDATE refresh_tokens 
            SET hash = $2, issued_at = $3, expires_at = $4 
            WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            RETURNING *"#,
            id,
            hash,
            now,
            expires_at
        )
        .fetch_optional(pool)
        .await?;

        Ok(new_refresh)
    }
    pub async fn revoke_for_user(
        pool: &PgPool,
        user_id: &Uuid,
        vault_id: &Uuid,
    ) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = (SELECT id FROM users WHERE id = $1 AND vault_id = $2)",
            user_id,
            vault_id,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn find_valid_by_hash(
        pool: &PgPool,
        hash: &str,
        vault_id: &Uuid,
    ) -> ShlossResult<Option<Self>> {
        let token = sqlx::query_as!(
            RefreshToken,
            "SELECT rt.* FROM refresh_tokens rt
            JOIN users u ON rt.user_id = u.id
            WHERE rt.hash = $1
            AND rt.revoked_at IS NULL
            AND rt.expires_at > NOW()
            AND u.vault_id = $2",
            hash,
            vault_id,
        )
        .fetch_optional(pool)
        .await?;
        Ok(token)
    }
}
