use crate::{jwt::Jwks, server::AppState};
use axum::{Json, extract::State};

pub async fn api_jwks(State(state): State<AppState>) -> Json<Jwks> {
    Json((*state.jwks).clone())
}
