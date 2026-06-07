use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use tracing::instrument;
use uuid::Uuid;

pub mod api_key;
pub mod password;
pub mod sessions;
pub mod username;

use crate::{
    db,
    server::{AppState, AuthService},
};

#[instrument(skip(state, vault_id))]
pub async fn api_delete_user(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    match db::User::delete(&state.pool, &user_id, &vault_id).await {
        Ok(succ) if succ => {
            tracing::info!("user deleted");
            StatusCode::OK
        }
        Ok(_) => {
            tracing::info!("user not found");
            StatusCode::NOT_FOUND
        }
        Err(e) => {
            tracing::error!(error = %e, "error deleting user");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
