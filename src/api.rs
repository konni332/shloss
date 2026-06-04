use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{
    api::{
        auth::{
            login::api_login, refresh::api_refresh_token, register::api_register,
            service::api_login_service,
        },
        token::api_validate_token,
        users::{
            api_delete_user,
            api_key::{api_add_api_key, api_revoke_all_api_keys, api_revoke_api_key},
            password::api_change_password,
            sessions::{
                api_list_sessions, api_revoke_session_for_user,
                api_revoke_tokens_and_sessions_for_user,
            },
            username::api_change_username,
        },
        well_known::api_jwks,
    },
    server::AppState,
};

pub mod auth;
pub mod token;
pub mod users;
pub mod well_known;

pub fn build_router(state: AppState) -> Router {
    Router::new().nest("/v1", build_v1()).with_state(state)
}

fn build_v1() -> Router<AppState> {
    Router::new()
        .nest("/.well-known", build_well_known())
        .nest("/auth", build_auth())
        .nest("/tokens", build_tokens())
        .nest("/users/{user_id}", build_users())
}

fn build_well_known() -> Router<AppState> {
    Router::new().route("/jwks.json", get(api_jwks))
}

fn build_auth() -> Router<AppState> {
    Router::new()
        .route("/service", post(api_login_service))
        .route("/login", post(api_login))
        .route("/register", post(api_register))
        .route("/refresh", post(api_refresh_token))
}

fn build_tokens() -> Router<AppState> {
    Router::new().route("/validate", post(api_validate_token))
}

fn build_users() -> Router<AppState> {
    Router::new()
        .route("/", delete(api_delete_user))
        .route(
            "/sessions",
            get(api_list_sessions).delete(api_revoke_tokens_and_sessions_for_user),
        )
        .route(
            "/sessions/{session_id}",
            delete(api_revoke_session_for_user),
        )
        .route("/password", post(api_change_password))
        .route("/username", post(api_change_username))
        .route("/api-key", post(api_add_api_key).delete(api_revoke_api_key))
        .route("/api-key/all", delete(api_revoke_all_api_keys))
}
