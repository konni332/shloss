use std::collections::HashMap;

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenValidateRequest {
    pub token: String,
    pub kind: TokenKind,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum TokenValidateResponse {
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "valid", rename_all = "camelCase")]
    Valid { user_id: Uuid },
}

#[derive(Deserialize)]
pub enum TokenKind {
    #[serde(rename = "jwt")]
    Jwt,
    #[serde(rename = "opaque")]
    Opaque,
}

impl std::fmt::Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jwt => write!(f, "jwt"),
            Self::Opaque => write!(f, "opaque"),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub credentials: Credentials,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<IpNetwork>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub token_kind: TokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_expiry: Option<DateTime<Utc>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
    pub token_type: TokenType,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum RefreshResponse {
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "valid", rename_all = "camelCase")]
    Valid {
        new_refresh: String,
        new_token: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginServiceRequest {
    pub raw_key: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginServiceResponse {
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum RegisterRequest {
    #[serde(rename = "password", rename_all = "camelCase")]
    Password { username: String, password: String },
    #[serde(rename = "apiKey", rename_all = "camelCase")]
    ApiKey {
        name: String,
        key_prefix: String,
        expires_at: Option<DateTime<Utc>>,
    },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum RegisterResponse {
    #[serde(rename = "password", rename_all = "camelCase")]
    Password { user_id: Uuid },
    #[serde(rename = "apiKey", rename_all = "camelCase")]
    ApiKey { user_id: Uuid, raw_key: String },
}

// used for logging, so we only display the type, no secrets
impl std::fmt::Display for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => write!(f, "password"),
            Self::ApiKey { .. } => write!(f, "api-key"),
        }
    }
}

// used for logging, so we only display the user_id, no secrets
impl std::fmt::Display for RegisterResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { user_id } => write!(f, "{user_id}"),
            Self::ApiKey { user_id, .. } => write!(f, "{user_id}"),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddApiKeyRequest {
    pub name: String,
    pub key_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddApiKeyResponse {
    pub key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeApiKeyRequest {
    pub key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeUsernameRequest {
    pub new_username: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub new_password: String,
}

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
