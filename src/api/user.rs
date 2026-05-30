use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    db,
    server::{AppState, AuthService},
};

pub async fn api_delete_user(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    match db::User::delete(&state.pool, &user_id).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn api_revoke_tokens_and_sessions_for_user(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    let pool = &state.pool;
    if db::OpaqueToken::revoke_for_user(pool, &user_id)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    if db::RefreshToken::revoke_for_user(pool, &user_id)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    if db::Session::revoke_all_for_user(pool, &user_id)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    StatusCode::OK
}

pub async fn api_revoke_all_api_keys(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    if db::ApiKey::revoke_for_user(&state.pool, &user_id)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}
