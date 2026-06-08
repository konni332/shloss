use axum::{Json, extract::State, http::StatusCode};
use shloss_types::{RegisterRequest, RegisterResponse};
use tracing::instrument;

use crate::{
    auth,
    error::ShlossError,
    server::{AppState, AuthService},
};

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
