use sqlx::PgPool;

use crate::{
    api::register::{RegisterRequest, RegisterResponse},
    crypto::{generate_api_key, hash_password},
    db::{ApiKey, PasswordCredential, User},
    error::ShlossResult,
};

pub(crate) async fn register(
    pool: &PgPool,
    credential: RegisterRequest,
) -> ShlossResult<RegisterResponse> {
    let user = User::create(pool).await?;
    match credential {
        RegisterRequest::Password { username, password } => {
            let hash = hash_password(&password)?;
            PasswordCredential::create(pool, &user.id, &username, &hash).await?;
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
            )
            .await?;
            Ok(RegisterResponse::ApiKey {
                user_id: user.id,
                raw_key: api_key.full_key,
            })
        }
    }
}
