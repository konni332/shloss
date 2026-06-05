use std::collections::HashMap;

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use jsonwebtoken::EncodingKey;
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::{generate_token, hash_secret, verify_password},
    db::{self, OpaqueToken, PasswordCredential, RefreshToken, Session, User},
    error::ShlossResult,
    jwt::generate_jwt,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Credentials {
    #[serde(rename = "password", rename_all = "camelCase")]
    Password { username: String, password: String },
    #[serde(rename = "apiKey", rename_all = "camelCase")]
    ApiKey { full_key: String },
}

impl std::fmt::Display for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => write!(f, "password"),
            Self::ApiKey { .. } => write!(f, "api-key"),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum TokenType {
    #[serde(rename = "jwt", rename_all = "camelCase")]
    Jwt { claims: HashMap<String, Value> },
    #[serde(rename = "opaque", rename_all = "camelCase")]
    Opaque { expires_at: DateTime<Utc> },
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jwt { .. } => write!(f, "jwt"),
            Self::Opaque { .. } => write!(f, "opaque"),
        }
    }
}

pub struct RefreshTokenRequest {
    pub expires_at: DateTime<Utc>,
}

pub struct LoginContext {
    pub credentials: Credentials,
    pub ip_address: Option<IpNetwork>,
    pub user_agent: Option<String>,
    pub token: TokenType,
    pub refresh: Option<RefreshTokenRequest>,
}

pub enum IssuedToken {
    Jwt(String),
    Opaque(String),
}

pub struct LoginResult {
    pub user_id: Uuid,
    pub token: IssuedToken,
    pub refresh_token: Option<String>,
}

pub async fn login(
    pool: &PgPool,
    encoding_key: &EncodingKey,
    context: LoginContext,
) -> ShlossResult<Option<LoginResult>> {
    let user = match context.credentials {
        Credentials::Password { username, password } => {
            verify_password_credentials(pool, &username, &password).await?
        }
        Credentials::ApiKey { full_key } => {
            let user = verify_api_key_credentials(pool, &full_key).await?;
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
) -> ShlossResult<Option<User>> {
    let Some(user) = User::get_from_username(pool, username).await? else {
        return Ok(None);
    };
    let Some(hash) = PasswordCredential::get_hash_for_user(pool, &user.id).await? else {
        return Ok(None);
    };
    if verify_password(password, &hash)? {
        Ok(Some(user))
    } else {
        Ok(None)
    }
}
async fn verify_api_key_credentials(pool: &PgPool, key: &str) -> ShlossResult<Option<User>> {
    let hash = hash_secret(key);
    User::get_from_api_key(pool, &hash).await
}
