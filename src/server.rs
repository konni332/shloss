use std::sync::Arc;

use axum::{
    Router,
    extract::FromRequestParts,
    http::StatusCode,
    routing::{delete, get, post},
};
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::{
    api::{
        jwt::api_jwks,
        login::api_login,
        refresh::api_refresh_token,
        register::api_register,
        service_auth::api_login_service,
        session::{api_list_sessions, api_revoke_session},
        token::api_validate_token,
        user::{
            api_add_api_key, api_change_password, api_change_username, api_delete_user,
            api_revoke_api_key, api_revoke_tokens_and_sessions_for_user,
        },
    },
    auth::{ServiceKeyStore, validate_service_token},
    jwt::Jwks,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub store: Arc<RwLock<ServiceKeyStore>>,
    pub encoding_key: Arc<jsonwebtoken::EncodingKey>,
    pub decoding_key: Arc<jsonwebtoken::DecodingKey>,
    pub jwks: Arc<Jwks>,
}

pub struct AuthService;

impl FromRequestParts<AppState> for AuthService {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let store = state.store.read().await;
        if validate_service_token(&store, token) {
            Ok(AuthService)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let v1 = Router::new()
        // public
        .route("/.well-known/jwks.json", get(api_jwks))
        // service auth
        .route("/services/login", post(api_login_service))
        // user auth
        .route("/users/register", post(api_register))
        .route("/users/login", post(api_login))
        // tokens
        .route("/tokens/validate", post(api_validate_token))
        .route("/tokens/refresh", post(api_refresh_token))
        .route(
            "/tokens/revoke",
            post(api_revoke_tokens_and_sessions_for_user),
        )
        // sessions
        .route("/sessions/{user_id}", get(api_list_sessions))
        .route("/sessions/{session_id}/revoke", post(api_revoke_session))
        // users
        .route("/users/{user_id}", delete(api_delete_user))
        .route(
            "/users/{user_id}/revoke",
            post(api_revoke_tokens_and_sessions_for_user),
        )
        .route("/users/{user_id}/password", post(api_change_password))
        .route("/users/{user_id}/username", post(api_change_username))
        .route("/users/{user_id}/api-keys", post(api_add_api_key))
        .route("/users/{user_id}/api-keys/revoke", post(api_revoke_api_key));

    Router::new().nest("/v1", v1).with_state(state)
}
