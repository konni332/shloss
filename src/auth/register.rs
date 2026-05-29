use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::{generate_api_key, hash_password},
    db::{ApiKey, PasswordCredential, User},
    error::ShlossResult,
};

pub enum Credential {
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

pub(crate) async fn register(pool: &PgPool, credential: Credential) -> ShlossResult<Uuid> {
    let user = User::create(pool).await?;
    match credential {
        Credential::Password { username, password } => {
            let hash = hash_password(&password)?;
            PasswordCredential::create(pool, &user.id, &username, &hash).await?;
        }
        Credential::ApiKey {
            name,
            key_prefix,
            expires_at,
        } => {
            let api_key = generate_api_key(key_prefix.to_owned());
            ApiKey::create(
                pool,
                &user.id,
                &name,
                &key_prefix,
                &api_key.hash,
                expires_at,
            )
            .await?;
        }
    }
    Ok(user.id)
}
