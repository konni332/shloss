use axum::{Json, extract::State, http::StatusCode};
use shloss_types::{TokenKind, TokenValidateRequest, TokenValidateResponse};
use tracing::instrument;

use crate::{
    auth::{validate_jwt, validate_opaque_token},
    server::{AppState, AuthService},
};
#[instrument(skip(state, vault_id, body), fields(token_kind = %body.kind))]
pub async fn api_validate_token(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
    Json(body): Json<TokenValidateRequest>,
) -> Result<Json<TokenValidateResponse>, StatusCode> {
    tracing::debug!("validating token");

    let pool = &state.pool;
    let decoding_key = &state.decoding_key;
    let token = &body.token;

    let result = match match body.kind {
        TokenKind::Opaque => validate_opaque_token(pool, token, &vault_id).await,
        TokenKind::Jwt => validate_jwt(decoding_key, token).await,
    } {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(error = %e, "error validating token");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let Some(user_id) = result else {
        tracing::warn!("token invalid");
        return Ok(Json(TokenValidateResponse::Invalid));
    };
    tracing::info!("token valid");
    Ok(Json(TokenValidateResponse::Valid { user_id }))
}
