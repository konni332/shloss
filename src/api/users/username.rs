use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    db,
    error::ShlossError,
    server::{AppState, AuthService},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeUsernameRequest {
    new_username: String,
}

#[instrument(skip(state, _service, body))]
pub async fn api_change_username(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
    Json(body): Json<ChangeUsernameRequest>,
) -> StatusCode {
    tracing::info!("changing username");
    match db::PasswordCredential::update_username(&state.pool, &user_id, &body.new_username).await {
        Ok(_) => {
            tracing::info!("username updated successfully");
            StatusCode::OK
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
