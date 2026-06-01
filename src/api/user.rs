use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    crypto::{generate_api_key, hash_password, hash_secret},
    db,
    error::ShlossError,
    server::{AppState, AuthService},
};

#[instrument(skip(state, _service))]
pub async fn api_delete_user(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    match db::User::delete(&state.pool, &user_id).await {
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

#[instrument(skip(state, _service))]
pub async fn api_revoke_tokens_and_sessions_for_user(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    tracing::info!("attempting to revoke all sessions and tokens for user");
    let pool = &state.pool;
    match db::OpaqueToken::revoke_for_user(pool, &user_id).await {
        Ok(_) => {
            tracing::info!("all opaque tokens revoked");
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking opaque tokens");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    match db::RefreshToken::revoke_for_user(pool, &user_id).await {
        Ok(_) => {
            tracing::info!("all refresh tokens revoked");
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking refresh tokens");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    match db::Session::revoke_all_for_user(pool, &user_id).await {
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

#[instrument(skip(state, _service))]
pub async fn api_revoke_all_api_keys(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    match db::ApiKey::revoke_for_user(&state.pool, &user_id).await {
        Ok(_) => {
            tracing::info!("all api keys revoked successfully");
            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking api keys");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
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

#[instrument(skip(state, _service, body), fields(user_id = %body.user_id, key_prefix = %body.key_prefix))]
pub async fn api_add_api_key(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<AddApiKeyRequest>,
) -> Result<Json<AddApiKeyResponse>, StatusCode> {
    tracing::info!("adding api key");
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
    .map_err(|e| {
        tracing::error!(error = %e, "error adding api key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    tracing::info!("api added successfully");
    Ok(Json(AddApiKeyResponse {
        key: generated_key.full_key,
    }))
}

#[derive(Deserialize)]
pub struct RevokeApiKeyRequest {
    user_id: Uuid,
    key: String,
}

#[instrument(skip(state, _service, body), fields(user_id = %body.user_id))]
pub async fn api_revoke_api_key(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<RevokeApiKeyRequest>,
) -> StatusCode {
    tracing::info!("revoking api key");
    let hash = hash_secret(&body.key);
    match db::ApiKey::revoke(&state.pool, &hash, &body.user_id).await {
        Ok(_) => {
            tracing::info!("api key revoked successfully");
            StatusCode::OK
        }
        Err(e) => {
            tracing::error!(error = %e, "error revoking api key");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    user_id: Uuid,
    new_password: String,
}

#[instrument(skip(state, _service, body), fields(user_id = %body.user_id))]
pub async fn api_change_password(
    State(state): State<AppState>,
    _service: AuthService,
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
    match db::PasswordCredential::update_password(&state.pool, &body.user_id, &new_hash).await {
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

#[derive(Deserialize)]
pub struct ChangeUsernameRequest {
    user_id: Uuid,
    new_username: String,
}

#[instrument(skip(state, _service, body), fields(user_id = %body.user_id))]
pub async fn api_change_username(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<ChangeUsernameRequest>,
) -> StatusCode {
    tracing::info!("changing username");
    match db::PasswordCredential::update_username(&state.pool, &body.user_id, &body.new_username)
        .await
    {
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
