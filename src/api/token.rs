use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    auth::{validate_jwt, validate_opaque_token},
    server::{AppState, AuthService},
};

#[derive(Deserialize)]
enum TokenKind {
    #[serde(rename = "jwt")]
    Jwt,
    #[serde(rename = "opaque")]
    Opaque,
}

impl std::fmt::Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jwt => write!(f, "jwt"),
            Self::Opaque => write!(f, "opaque"),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenValidateRequest {
    token: String,
    kind: TokenKind,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum TokenValidateResponse {
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "valid", rename_all = "camelCase")]
    Valid { user_id: Uuid },
}

#[instrument(skip(state, _service, body), fields(token_kind = %body.kind))]
pub async fn api_validate_token(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<TokenValidateRequest>,
) -> Result<Json<TokenValidateResponse>, StatusCode> {
    tracing::debug!("validating token");

    let pool = &state.pool;
    let decoding_key = &state.decoding_key;
    let token = &body.token;

    let result = match match body.kind {
        TokenKind::Opaque => validate_opaque_token(pool, token).await,
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
