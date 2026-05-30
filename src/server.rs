use std::sync::Arc;

use axum::{extract::FromRequestParts, http::StatusCode};
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::auth::{ServiceKeyStore, validate_service_token};

pub struct AppState {
    pub pool: PgPool,
    pub store: Arc<RwLock<ServiceKeyStore>>,
    pub encoding_key: Arc<jsonwebtoken::EncodingKey>,
    pub decoding_key: Arc<jsonwebtoken::DecodingKey>,
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
