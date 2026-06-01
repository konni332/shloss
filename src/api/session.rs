use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    db::Session,
    server::{AppState, AuthService},
};

#[derive(Serialize)]
pub struct GetSessionsResponse {
    sessions: Vec<Session>,
}

#[instrument(skip(state, _service))]
pub async fn api_list_sessions(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> Result<Json<GetSessionsResponse>, StatusCode> {
    tracing::info!("listing sessions");
    let sessions = Session::find_for_user(&state.pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "error finding sessions for user");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(GetSessionsResponse { sessions }))
}

#[instrument(skip(state, _service))]
pub async fn api_revoke_session(
    State(state): State<AppState>,
    _service: AuthService,
    Path(session_id): Path<Uuid>,
) -> StatusCode {
    tracing::info!("revoking sessions");
    match Session::revoke(&state.pool, &session_id).await {
        Ok(succ) if succ => {
            tracing::info!("sessions revoked successfully");
            StatusCode::OK
        }
        Ok(_) => {
            tracing::info!("sessions not found");
            StatusCode::NOT_FOUND
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking session");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
