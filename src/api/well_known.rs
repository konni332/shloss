use crate::server::AppState;
use axum::{Json, extract::State};
use shloss_types::Jwks;

pub async fn api_jwks(State(state): State<AppState>) -> Json<Jwks> {
    Json((*state.jwks).clone())
}
