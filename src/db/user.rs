use chrono::{DateTime, Utc};
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{crypto, error::ShlossResult};

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub(crate) id: Uuid,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

impl User {
    pub async fn create(pool: &PgPool) -> ShlossResult<Self> {
        let id = crypto::generate_uuid();
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users (id) VALUES ($1) RETURNING id, created_at, updated_at",
            id
        )
        .fetch_one(pool)
        .await?;
        Ok(user)
    }
    pub async fn delete(pool: &PgPool, id: &Uuid) -> ShlossResult<()> {
        sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(pool)
            .await?;
        Ok(())
    }
    pub async fn get_username(pool: &PgPool, id: &Uuid) -> ShlossResult<Option<String>> {
        let username = sqlx::query_scalar!(
            "SELECT pc.username FROM users u JOIN password_credentials pc ON u.id = pc.user_id WHERE u.id = $1",
            id
        )
        .fetch_optional(pool)
        .await?;

        Ok(username)
    }
}
