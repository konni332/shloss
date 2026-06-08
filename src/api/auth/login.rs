use axum::{Json, extract::State, http::StatusCode};
use shloss_types::{IssuedToken, LoginContext, LoginRequest, LoginResponse, RefreshTokenRequest};
use tracing::instrument;

use crate::{
    auth,
    server::{AppState, AuthService},
};

#[instrument(
    skip(state, vault_id, body),
    fields(
        credential_kind = %body.credentials,
        token_kind = %body.token_kind,
        refresh = body.refresh_expiry.is_some()
        )
    )]
pub async fn api_login(
    State(state): State<AppState>,
    AuthService(vault_id): AuthService,
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
            .refresh_expiry
            .map(|expires_at| RefreshTokenRequest { expires_at }),
    };

    let result = auth::login(pool, encoding_key, ctx, &vault_id)
        .await
        .map_err(|e| {
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
        refresh_token: result.refresh_token,
    }))
}
