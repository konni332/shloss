use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    crypto::{generate_api_key, hash_password, hash_secret},
    db,
    error::ShlossError,
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

#[derive(Deserialize)]
pub struct AddApiKeyRequest {
    user_id: Uuid,
    name: String,
    key_prefix: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct AddApiKeyResponse {
    key: String,
}

pub async fn api_add_api_key(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<AddApiKeyRequest>,
) -> Result<Json<AddApiKeyResponse>, StatusCode> {
    let generated_key = generate_api_key(body.key_prefix.clone());
    db::ApiKey::create(
        &state.pool,
        &body.user_id,
        &body.name,
        &body.key_prefix,
        &generated_key.hash,
        body.expires_at,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AddApiKeyResponse {
        key: generated_key.full_key,
    }))
}

#[derive(Deserialize)]
pub struct RevokeApiKeyRequest {
    user_id: Uuid,
    key: String,
}

pub async fn api_revoke_api_key(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<RevokeApiKeyRequest>,
) -> StatusCode {
    let hash = hash_secret(&body.key);
    if db::ApiKey::revoke(&state.pool, &hash, &body.user_id)
        .await
        .is_err()
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    user_id: Uuid,
    new_password: String,
}

pub async fn api_change_password(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<ChangePasswordRequest>,
) -> StatusCode {
    let Ok(new_hash) = hash_password(&body.new_password) else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    match db::PasswordCredential::update_password(&state.pool, &body.user_id, &new_hash).await {
        Ok(true) => StatusCode::OK,
        Ok(false) => StatusCode::NOT_FOUND, // no rows updated = user has no password credential
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
pub struct ChangeUsernameRequest {
    user_id: Uuid,
    new_username: String,
}

pub async fn api_change_username(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<ChangeUsernameRequest>,
) -> StatusCode {
    match db::PasswordCredential::update_username(&state.pool, &body.user_id, &body.new_username)
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(ShlossError::Database(sqlx::Error::Database(db_e)))
            if db_e.code().map(|c| c.as_ref() == "23505").unwrap_or(false) =>
        {
            StatusCode::CONFLICT
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
