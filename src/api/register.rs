use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    auth,
    server::{AppState, AuthService},
};

#[derive(Debug, Deserialize)]
pub enum RegisterRequest {
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
#[derive(Serialize)]
pub enum RegisterResponse {
    Password { user_id: Uuid },
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

#[instrument(skip(state, _service, body))]
pub async fn api_register(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    tracing::info!(credential_kind = %body, "user registration attempt");
    match auth::register(&state.pool, body).await {
        Ok(resp) => {
            tracing::info!(user_id = %resp, "user registered successfully");
            Ok(Json(resp))
        }
        Err(e) => {
            tracing::error!(error = %e, "user registration failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
