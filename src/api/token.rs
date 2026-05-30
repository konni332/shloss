use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{validate_jwt, validate_opaque_token},
    server::{AppState, AuthService},
};

#[derive(Deserialize)]
enum TokenKind {
    Jwt,
    Opaque,
}

#[derive(Deserialize)]
pub struct TokenValidateRequest {
    token: String,
    kind: TokenKind,
}

#[derive(Serialize)]
pub enum TokenValidateResponse {
    Invalid,
    Valid(Uuid),
}

pub async fn api_validate_token(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<TokenValidateRequest>,
) -> Result<Json<TokenValidateResponse>, StatusCode> {
    let pool = &state.pool;
    let decoding_key = &state.decoding_key;
    let token = &body.token;

    let Ok(result) = (match body.kind {
        TokenKind::Opaque => validate_opaque_token(pool, token).await,
        TokenKind::Jwt => validate_jwt(decoding_key, token).await,
    }) else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some(user_id) = result else {
        return Ok(Json(TokenValidateResponse::Invalid));
    };
    Ok(Json(TokenValidateResponse::Valid(user_id)))
}
