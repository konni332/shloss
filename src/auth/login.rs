use jsonwebtoken::EncodingKey;
use shloss_types::{
    Credentials, IssuedToken, LoginContext, LoginResult, RefreshTokenRequest, TokenType,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::{generate_token, hash_secret, verify_password},
    db::{self, OpaqueToken, PasswordCredential, RefreshToken, Session, User},
    error::ShlossResult,
    jwt::generate_jwt,
};

pub async fn login(
    pool: &PgPool,
    encoding_key: &EncodingKey,
    context: LoginContext,
    vault_id: &Uuid,
) -> ShlossResult<Option<LoginResult>> {
    let user = match context.credentials {
        Credentials::Password { username, password } => {
            verify_password_credentials(pool, &username, &password, vault_id).await?
        }
        Credentials::ApiKey { full_key } => {
            let user = verify_api_key_credentials(pool, &full_key, vault_id).await?;
            if user.is_some() {
                let hash = hash_secret(&full_key);
                db::ApiKey::update_used(pool, &hash).await?;
            }
            user
        }
    };

    let Some(user) = user else {
        return Ok(None);
    };

    let session = Session::create(pool, &user.id, context.ip_address, context.user_agent).await?;

    let token = match context.token {
        TokenType::Jwt { claims } => {
            let jwt = generate_jwt(user.id, claims, encoding_key)?;
            IssuedToken::Jwt(jwt)
        }
        TokenType::Opaque { expires_at } => {
            let generated = generate_token();
            OpaqueToken::create(pool, generated.clone(), &user.id, &session.id, expires_at).await?;
            IssuedToken::Opaque(generated.raw)
        }
    };

    let refresh_token = match context.refresh {
        Some(RefreshTokenRequest { expires_at }) => {
            let generated = generate_token();
            RefreshToken::create(pool, generated.clone(), &user.id, &session.id, expires_at)
                .await?;
            Some(generated.raw)
        }
        None => None,
    };

    Ok(Some(LoginResult {
        user_id: user.id,
        token,
        refresh_token,
    }))
}

async fn verify_password_credentials(
    pool: &PgPool,
    username: &str,
    password: &str,
    vault_id: &Uuid,
) -> ShlossResult<Option<User>> {
    let Some(user) = User::get_from_username(pool, username, vault_id).await? else {
        return Ok(None);
    };
    let Some(hash) = PasswordCredential::get_hash_for_user(pool, &user.id, vault_id).await? else {
        return Ok(None);
    };
    if verify_password(password, &hash)? {
        Ok(Some(user))
    } else {
        Ok(None)
    }
}
async fn verify_api_key_credentials(
    pool: &PgPool,
    key: &str,
    vault_id: &Uuid,
) -> ShlossResult<Option<User>> {
    let hash = hash_secret(key);
    User::get_from_api_key(pool, &hash, vault_id).await
}
