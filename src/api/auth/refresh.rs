use axum::{Json, extract::State, http::StatusCode};
use shloss_types::{RefreshRequest, RefreshResponse, TokenType};
use tracing::instrument;

use crate::{
    auth::validate_refresh_token,
    crypto::generate_token,
    db,
    jwt::generate_jwt,
    server::{AppState, AuthService},
};

#[instrument(skip(state, vault_id, body))]
pub async fn api_refresh_token(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, StatusCode> {
    let pool = &state.pool;

    let result = validate_refresh_token(pool, &body.refresh_token, &vault_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "error validating refresh token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let Some(r_token_id) = result else {
        tracing::warn!("invalid refresh token");
        return Ok(Json(RefreshResponse::Invalid));
    };

    let generated_refresh = generate_token();
    let result = db::RefreshToken::rotate(pool, &r_token_id, generated_refresh.clone())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "error rotating refresh token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let Some(new_refresh) = result else {
        tracing::warn!("invalid refresh token");
        tracing::error!(
            "the refresh token is invalid even tho validity was already checked and confirmed. This is likely a race condition or some inconsistency, please report this immediatly"
        );
        return Ok(Json(RefreshResponse::Invalid));
    };

    let new_token = match body.token_type {
        TokenType::Opaque { expires_at } => {
            let generated_token = generate_token();
            let _ = db::OpaqueToken::create(
                pool,
                generated_token.clone(),
                &new_refresh.user_id,
                &new_refresh.session_id,
                expires_at,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "error trying to create a new opaque token");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            generated_token.raw
        }
        TokenType::Jwt { claims } => generate_jwt(new_refresh.user_id, claims, &state.encoding_key)
            .map_err(|e| {
                tracing::error!(error = %e, "error generating JWT");
                StatusCode::INTERNAL_SERVER_ERROR
            })?,
    };
    tracing::info!("refresh token successfully rotated");
    Ok(Json(RefreshResponse::Valid {
        new_refresh: generated_refresh.raw,
        new_token,
    }))
}
