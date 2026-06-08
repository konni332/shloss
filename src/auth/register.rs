use shloss_types::{RegisterRequest, RegisterResponse};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::{generate_api_key, hash_password},
    db::{ApiKey, PasswordCredential, User},
    error::ShlossResult,
};

pub async fn register(
    pool: &PgPool,
    credential: RegisterRequest,
    vault_id: &Uuid,
) -> ShlossResult<RegisterResponse> {
    let user = User::create(pool, vault_id).await?;
    match credential {
        RegisterRequest::Password { username, password } => {
            let hash = hash_password(&password)?;
            PasswordCredential::create(pool, &user.id, vault_id, &username, &hash).await?;
            Ok(RegisterResponse::Password { user_id: user.id })
        }
        RegisterRequest::ApiKey {
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
                vault_id,
            )
            .await?;
            Ok(RegisterResponse::ApiKey {
                user_id: user.id,
                raw_key: api_key.full_key,
            })
        }
    }
}
