use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    db::{self, Session},
    error::ShlossError,
    server::{AppState, AuthService},
};

#[instrument(skip(state, vault_id))]
pub async fn api_revoke_session_for_user(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path((user_id, session_id)): Path<(Uuid, Uuid)>,
) -> StatusCode {
    tracing::info!("revoking sessions");
    match Session::revoke(&state.pool, &session_id, &user_id, &vault_id).await {
        Ok(_) => {
            tracing::info!("sessions revoked successfully");
            StatusCode::OK
        }
        Err(ShlossError::Database(sqlx::Error::RowNotFound)) => {
            tracing::info!("sessions not found");
            StatusCode::NOT_FOUND
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking session");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[instrument(skip(state, vault_id))]
pub async fn api_revoke_tokens_and_sessions_for_user(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    tracing::info!("attempting to revoke all sessions and tokens for user");
    let pool = &state.pool;
    match db::OpaqueToken::revoke_for_user(pool, &user_id, &vault_id).await {
        Ok(_) => {
            tracing::info!("all opaque tokens revoked");
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking opaque tokens");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    match db::RefreshToken::revoke_for_user(pool, &user_id, &vault_id).await {
        Ok(_) => {
            tracing::info!("all refresh tokens revoked");
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking refresh tokens");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    match db::Session::revoke_all_for_user(pool, &user_id, &vault_id).await {
        Ok(_) => {
            tracing::info!("all sessions tokens revoked");
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking sessions");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    StatusCode::OK
}

#[instrument(skip(state, vault_id))]
pub async fn api_list_sessions(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Session>>, StatusCode> {
    tracing::info!("listing sessions");
    let sessions = Session::find_for_user(&state.pool, &user_id, &vault_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "error finding sessions for user");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(sessions))
}
