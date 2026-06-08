use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use shloss_types::ChangePasswordRequest;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    crypto::hash_password,
    db,
    server::{AppState, AuthService},
};

#[instrument(skip(state, vault_id, body))]
pub async fn api_change_password(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
    Json(body): Json<ChangePasswordRequest>,
) -> StatusCode {
    tracing::info!("changing password");
    let new_hash = match hash_password(&body.new_password) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "error hashing password");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    match db::PasswordCredential::update_password(&state.pool, &user_id, &new_hash, &vault_id).await
    {
        Ok(true) => {
            tracing::info!("password updated");
            StatusCode::OK
        }
        Ok(false) => {
            tracing::warn!("no password credentials found");
            StatusCode::NOT_FOUND
        }
        Err(e) => {
            tracing::error!(error = %e, "error updating password");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
