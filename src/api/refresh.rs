use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{TokenType, validate_refresh_token},
    crypto::generate_token,
    db,
    jwt::generate_jwt,
    server::{AppState, AuthService},
};

#[derive(Deserialize)]
pub struct RefreshRequest {
    refresh_token: String,
    token_type: TokenType,
}

#[derive(Serialize)]
pub enum RefreshResponse {
    Invalid,
    Valid {
        new_refresh: String,
        new_token: String,
    },
}

pub async fn api_refresh_token(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, StatusCode> {
    let pool = &state.pool;

    let Ok(result) = validate_refresh_token(pool, &body.refresh_token).await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some(r_token_id) = result else {
        return Ok(Json(RefreshResponse::Invalid));
    };

    let generated_refresh = generate_token();
    let Ok(result) = db::RefreshToken::rotate(pool, &r_token_id, generated_refresh.clone()).await
    else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some(new_refresh) = result else {
        return Ok(Json(RefreshResponse::Invalid));
    };

    let new_token = match body.token_type {
        TokenType::Opaque { expires_at } => {
            let generated_token = generate_token();
            let Ok(_) = db::OpaqueToken::create(
                pool,
                generated_token.clone(),
                &new_refresh.user_id,
                &new_refresh.session_id,
                expires_at,
            )
            .await
            else {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            };
            generated_token.raw
        }
        TokenType::Jwt { claims } => {
            let Ok(jwt) = generate_jwt(new_refresh.user_id, claims, &state.encoding_key) else {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            };
            jwt
        }
    };
    Ok(Json(RefreshResponse::Valid {
        new_refresh: generated_refresh.raw,
        new_token,
    }))
}
