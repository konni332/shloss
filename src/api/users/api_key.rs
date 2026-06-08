use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use shloss_types::{AddApiKeyRequest, AddApiKeyResponse, RevokeApiKeyRequest};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    crypto::generate_api_key,
    db, hash_secret,
    server::{AppState, AuthService},
};

#[instrument(skip(state, vault_id))]
pub async fn api_revoke_all_api_keys(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
) -> StatusCode {
    match db::ApiKey::revoke_for_user(&state.pool, &user_id, &vault_id).await {
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

#[instrument(skip(state, vault_id, body), fields(key_prefix = %body.key_prefix))]
pub async fn api_add_api_key(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AddApiKeyRequest>,
) -> Result<Json<AddApiKeyResponse>, StatusCode> {
    tracing::info!("adding api key");
    let generated_key = generate_api_key(body.key_prefix.clone());
    let inserted = db::ApiKey::create(
        &state.pool,
        &user_id,
        &body.name,
        &body.key_prefix,
        &generated_key.hash,
        body.expires_at,
        &vault_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "error adding api key");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .is_some();
    if !inserted {
        return Err(StatusCode::NOT_FOUND);
    }
    tracing::info!("api added successfully");
    Ok(Json(AddApiKeyResponse {
        key: generated_key.full_key,
    }))
}

#[instrument(skip(state, vault_id, body))]
pub async fn api_revoke_api_key(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Path(user_id): Path<Uuid>,
    Json(body): Json<RevokeApiKeyRequest>,
) -> StatusCode {
    tracing::info!("revoking api key");
    let hash = hash_secret(&body.key);
    match db::ApiKey::revoke(&state.pool, &hash, &user_id, &vault_id).await {
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
