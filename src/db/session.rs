use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{crypto::generate_uuid, error::ShlossResult};

const SESSION_TTL: Duration = Duration::from_hours(24 * 7);

#[derive(Debug, Clone, FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip_address: Option<ipnetwork::IpNetwork>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_agent: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revoked_at: Option<DateTime<Utc>>,
}

impl Session {
    pub async fn create(
        pool: &PgPool,
        user_id: &Uuid,
        ip_address: Option<ipnetwork::IpNetwork>,
        user_agent: Option<String>,
    ) -> ShlossResult<Self> {
        let id = generate_uuid();
        let expires_at = Utc::now() + SESSION_TTL;
        let session = sqlx::query_as!(
            Session,
            r#"INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5) 
            RETURNING id, user_id, ip_address, user_agent, created_at, expires_at, revoked_at"#,
            id,
            user_id,
            ip_address,
            user_agent,
            expires_at,
        )
        .fetch_one(pool)
        .await?;

        Ok(session)
    }
    pub async fn revoke(
        pool: &PgPool,
        id: &Uuid,
        user_id: &Uuid,
        vault_id: &Uuid,
    ) -> ShlossResult<()> {
        let id = sqlx::query_scalar!(
            "UPDATE sessions SET revoked_at = NOW()
            WHERE id = $1 AND user_id = (SELECT id FROM users WHERE id = $2 AND vault_id = $3)
            RETURNING id",
            id,
            user_id,
            vault_id,
        )
        .fetch_one(pool)
        .await?;
        // there is no need to scope the tokens using vault_id because `fetch_one()` will fail if
        // the session does not belong to the given vault!
        sqlx::query!(
            "UPDATE opaque_tokens SET revoked_at = NOW() WHERE session_id = $1",
            &id
        )
        .execute(pool)
        .await?;
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE session_id = $1",
            &id
        )
        .execute(pool)
        .await?;

        Ok(())
    }
    pub async fn find_for_user(
        pool: &PgPool,
        user_id: &Uuid,
        vault_id: &Uuid,
    ) -> ShlossResult<Vec<Session>> {
        let sessions = sqlx::query_as!(
            Session,
            "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE id = $1 AND vault_id = $2)",
            user_id,
            vault_id,
        )
        .fetch_all(pool)
        .await?;
        Ok(sessions)
    }
    pub async fn active_user_sessions(
        pool: &PgPool,
        user_id: &Uuid,
        vault_id: &Uuid,
    ) -> ShlossResult<usize> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(s.id) FROM sessions s WHERE s.user_id = (SELECT id FROM users WHERE id = $1 AND vault_id = $2)",
            user_id,
            vault_id,
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) as usize)
    }
    pub async fn revoke_all_for_user(
        pool: &PgPool,
        user_id: &Uuid,
        vault_id: &Uuid,
    ) -> ShlossResult<()> {
        let ids = sqlx::query_scalar!(
            "UPDATE sessions SET revoked_at = NOW()
            WHERE user_id = (SELECT id FROM users WHERE id = $1 AND vault_id = $2)
            RETURNING id",
            user_id,
            vault_id,
        )
        .fetch_all(pool)
        .await?;

        for id in ids {
            sqlx::query!(
                "UPDATE opaque_tokens SET revoked_at = NOW() WHERE session_id = $1",
                &id
            )
            .execute(pool)
            .await?;
            sqlx::query!(
                "UPDATE refresh_tokens SET revoked_at = NOW() WHERE session_id = $1",
                &id
            )
            .execute(pool)
            .await?;
        }

        Ok(())
    }
}
