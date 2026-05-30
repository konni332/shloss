use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::{generate_api_key, hash_password},
    db::{ApiKey, PasswordCredential, User},
    error::ShlossResult,
};

pub enum RegisterCredentials {
    Password {
        username: String,
        password: String,
    },
    ApiKey {
        name: String,
        key_prefix: String,
        expires_at: Option<DateTime<Utc>>,
    },
}

pub enum RegisterResult {
    Password { user_id: Uuid },
    ApiKey { user_id: Uuid, raw_key: String },
}

pub(crate) async fn register(
    pool: &PgPool,
    credential: RegisterCredentials,
) -> ShlossResult<RegisterResult> {
    let user = User::create(pool).await?;
    match credential {
        RegisterCredentials::Password { username, password } => {
            let hash = hash_password(&password)?;
            PasswordCredential::create(pool, &user.id, &username, &hash).await?;
            Ok(RegisterResult::Password { user_id: user.id })
        }
        RegisterCredentials::ApiKey {
            name,
            key_prefix,
            expires_at,
        } => {
            let api_key = generate_api_key(key_prefix.clone());
            ApiKey::create(
                pool,
                &user.id,
                &name,
                &key_prefix,
                &api_key.hash,
                expires_at,
            )
            .await?;
            Ok(RegisterResult::ApiKey {
                user_id: user.id,
                raw_key: api_key.full_key,
            })
        }
    }
}
