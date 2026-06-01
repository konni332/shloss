use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{crypto::generate_uuid, error::ShlossResult};

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Session {
    pub(crate) id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) ip_address: Option<ipnetwork::IpNetwork>,
    pub(crate) user_agent: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
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
        let session = sqlx::query_as!(
            Session,
            r#"INSERT INTO sessions (id, user_id, ip_address, user_agent) VALUES ($1, $2, $3, $4) 
            RETURNING id, user_id, ip_address, user_agent, created_at, expires_at, revoked_at"#,
            id,
            user_id,
            ip_address,
            user_agent
        )
        .fetch_one(pool)
        .await?;

        Ok(session)
    }
    pub async fn delete(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!("DELETE FROM sessions WHERE id = $1", id)
            .execute(pool)
            .await?;

        Ok(())
    }
    pub async fn revoke(pool: &PgPool, id: &Uuid) -> ShlossResult<bool> {
        let rows = sqlx::query!("UPDATE sessions SET revoked_at = NOW() WHERE id = $1", id)
            .execute(pool)
            .await?
            .rows_affected();
        Ok(rows > 0)
    }
    pub async fn find_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<Vec<Session>> {
        let sessions = sqlx::query_as!(
            Session,
            "SELECT * FROM sessions WHERE user_id = $1",
            user_id
        )
        .fetch_all(pool)
        .await?;
        Ok(sessions)
    }
    pub async fn active_user_sessions(pool: &PgPool, user_id: &Uuid) -> ShlossResult<usize> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(s.id) FROM sessions s WHERE s.user_id = $1",
            user_id
        )
        .fetch_one(pool)
        .await?;

        Ok(count.unwrap_or(0) as usize)
    }
    pub async fn revoke_all_for_user(pool: &PgPool, user_id: &Uuid) -> ShlossResult<()> {
        sqlx::query!(
            "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1",
            user_id
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
