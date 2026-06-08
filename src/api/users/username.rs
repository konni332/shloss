use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use shloss_types::ChangeUsernameRequest;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    db,
    error::ShlossError,
    server::{AppState, AuthService},
};

#[instrument(skip(state, vault_id, body))]
pub async fn api_change_username(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
    Json(body): Json<ChangeUsernameRequest>,
) -> StatusCode {
    tracing::info!("changing username");
    match db::PasswordCredential::update_username(
        &state.pool,
        &user_id,
        &body.new_username,
        &vault_id,
    )
    .await
    {
        Ok(true) => {
            tracing::info!("username updated successfully");
            StatusCode::OK
        }
        Ok(false) => {
            tracing::info!("user not found");
            StatusCode::NOT_FOUND
        }
        Err(ShlossError::Database(sqlx::Error::Database(db_e)))
            if db_e.code().map(|c| c.as_ref() == "23505").unwrap_or(false) =>
        {
            tracing::warn!("username already taken");
            StatusCode::CONFLICT
        }
        Err(e) => {
            tracing::error!(error = %e, "error updating username");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
