use chrono::{DateTime, Utc};
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{
    crypto::{GeneratedToken, generate_uuid},
    error::ShlossResult,
};

#[derive(Debug, Clone, FromRow)]
pub struct OpaqueToken {
    id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
    hash: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, FromRow)]
pub struct RefreshToken {
    id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
    hash: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Jwt {}

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
    pub async fn delete(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!("DELETE FROM opaque_tokens WHERE id = $1", id)
            .execute(pool)
            .await?;
        Ok(())
    }
    pub async fn revoke(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE opaque_tokens SET revoked_at = NOW() WHERE id = $1",
            id,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn revoke_for_session(pool: &PgPool, session_id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE opaque_tokens SET revoked_at = NOW() WHERE session_id = $1",
            session_id,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn revoke_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE opaque_tokens SET revoked_at = NOW() WHERE user_id = $1",
            user_id,
        )
        .execute(pool)
        .await?;
        Ok(())
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
    pub async fn delete(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!("DELETE FROM refresh_tokens WHERE id = $1", id)
            .execute(pool)
            .await?;
        Ok(())
    }
    pub async fn revoke(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1",
            id,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn revoke_for_session(pool: &PgPool, session_id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE session_id = $1",
            session_id,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
    pub async fn revoke_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1",
            user_id,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
