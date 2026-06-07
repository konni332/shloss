use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    auth,
    error::ShlossError,
    server::{AppState, AuthService},
};

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

#[instrument(skip(state, vault_id, body))]
pub async fn api_register(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    tracing::info!(credential_kind = %body, "user registration attempt");
    match auth::register(&state.pool, body, &vault_id).await {
        Ok(resp) => {
            tracing::info!(user_id = %resp, "user registered successfully");
            Ok(Json(resp))
        }
        Err(ShlossError::Database(sqlx::Error::Database(db_e)))
            if db_e.code().map(|c| c.as_ref() == "23505").unwrap_or(false) =>
        {
            tracing::warn!("username already taken");
            Err(StatusCode::CONFLICT)
        }
        Err(e) => {
            tracing::error!(error = %e, "user registration failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
