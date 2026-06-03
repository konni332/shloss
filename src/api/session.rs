use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    db::Session,
    error::ShlossError,
    server::{AppState, AuthService},
};

#[instrument(skip(state, _service))]
pub async fn api_revoke_session(
    State(state): State<AppState>,
    _service: AuthService,
    Path(session_id): Path<Uuid>,
) -> StatusCode {
    tracing::info!("revoking sessions");
    match Session::revoke(&state.pool, &session_id).await {
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
