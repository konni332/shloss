use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    db::Session,
    server::{AppState, AuthService},
};

#[derive(Serialize)]
pub struct GetSessionsResponse {
    sessions: Vec<Session>,
}

pub async fn api_list_sessions(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> Result<Json<GetSessionsResponse>, StatusCode> {
    let sessions = Session::find_for_user(&state.pool, &user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(GetSessionsResponse { sessions }))
}

pub async fn api_revoke_session(
    State(state): State<AppState>,
    _service: AuthService,
    Path(session_id): Path<Uuid>,
) -> StatusCode {
    if Session::revoke(&state.pool, &session_id).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}
