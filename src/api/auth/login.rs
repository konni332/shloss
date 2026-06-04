use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
    auth::{self, Credentials, IssuedToken, LoginContext, RefreshTokenRequest, TokenType},
    server::{AppState, AuthService},
};

#[derive(Deserialize)]
pub struct LoginRequest {
    credentials: Credentials,
    ip_address: Option<IpNetwork>,
    user_agent: Option<String>,
    token_kind: TokenType,
    refresh: Option<DateTime<Utc>>,
}
#[derive(Serialize)]
pub struct LoginResponse {
    user_id: Uuid,
    token: String,
    refresh: Option<String>,
}

#[instrument(
    skip(state, _service, body),
    fields(
        credential_kind = %body.credentials,
        token_kind = %body.token_kind,
        refresh = body.refresh.is_some()
        )
    )]
pub async fn api_login(
    State(state): State<AppState>,
    _service: AuthService,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    tracing::info!("user login");

    let pool = &state.pool;
    let encoding_key = &state.encoding_key;

    let ctx = LoginContext {
        credentials: body.credentials,
        ip_address: body.ip_address,
        user_agent: body.user_agent,
        token: body.token_kind,
        refresh: body
            .refresh
            .map(|expires_at| RefreshTokenRequest { expires_at }),
    };

    let result = auth::login(pool, encoding_key, ctx).await.map_err(|e| {
        tracing::error!(error = %e, "error trying to login user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(result) = result else {
        tracing::warn!(ip_address = ?body.ip_address, "user login unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    };
    tracing::info!("user logged in");
    Ok(Json(LoginResponse {
        user_id: result.user_id,
        token: match result.token {
            IssuedToken::Jwt(t) => t,
            IssuedToken::Opaque(t) => t,
        },
        refresh: result.refresh_token,
    }))
}
