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
    crypto::generate_api_key,
    db, hash_secret,
    server::{AppState, AuthService},
};

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
#[serde(rename_all = "camelCase")]
pub struct AddApiKeyRequest {
    name: String,
    key_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddApiKeyResponse {
    key: String,
}

#[instrument(skip(state, _service, body), fields(key_prefix = %body.key_prefix))]
pub async fn api_add_api_key(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AddApiKeyRequest>,
) -> Result<Json<AddApiKeyResponse>, StatusCode> {
    tracing::info!("adding api key");
    let generated_key = generate_api_key(body.key_prefix.clone());
    db::ApiKey::create(
        &state.pool,
        &user_id,
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
#[serde(rename_all = "camelCase")]
pub struct RevokeApiKeyRequest {
    key: String,
}

#[instrument(skip(state, _service, body))]
pub async fn api_revoke_api_key(
    State(state): State<AppState>,
    _service: AuthService,
    Path(user_id): Path<Uuid>,
    Json(body): Json<RevokeApiKeyRequest>,
) -> StatusCode {
    tracing::info!("revoking api key");
    let hash = hash_secret(&body.key);
    match db::ApiKey::revoke(&state.pool, &hash, &user_id).await {
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
