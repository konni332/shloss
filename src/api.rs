use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::server::AppState;

pub mod jwt;
pub mod login;
pub mod refresh;
pub mod register;
pub mod service_auth;
pub mod session;
pub mod token;
pub mod user;

use crate::api::{
    jwt::api_jwks,
    login::api_login,
    refresh::api_refresh_token,
    register::api_register,
    service_auth::api_login_service,
    session::api_revoke_session,
    token::api_validate_token,
    user::{
        api_add_api_key, api_change_password, api_change_username, api_delete_user,
        api_list_sessions, api_revoke_all_api_keys, api_revoke_api_key,
        api_revoke_tokens_and_sessions_for_user,
    },
};

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
        // sessions
        .route("/sessions/{session_id}/revoke", post(api_revoke_session))
        // users
        .route("/users/{user_id}", delete(api_delete_user))
        .route(
            "/users/{user_id}/sessions/revoke-all",
            post(api_revoke_tokens_and_sessions_for_user),
        )
        .route("/users/{user_id}/sessions", get(api_list_sessions))
        .route("/users/{user_id}/password", post(api_change_password))
        .route("/users/{user_id}/username", post(api_change_username))
        .route("/users/{user_id}/api-keys", post(api_add_api_key))
        .route("/users/{user_id}/api-keys/revoke", post(api_revoke_api_key))
        .route(
            "/users/{user_id}/api-keys/revoke-all",
            post(api_revoke_all_api_keys),
        );

    Router::new().nest("/v1", v1).with_state(state)
}
