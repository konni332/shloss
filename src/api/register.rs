use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

pub async fn api_register(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    auth::register(&state.pool, body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        .map(Json)
}
