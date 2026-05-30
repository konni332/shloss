use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::{auth, server::AppState};

#[derive(Debug, Deserialize)]
pub struct LoginServiceRequest {
    raw_key: String,
}
#[derive(Debug, Serialize)]
pub struct LoginServiceResponse {
    token: String,
}

pub async fn api_login_service(
    State(state): State<AppState>,
    Json(body): Json<LoginServiceRequest>,
) -> Result<Json<LoginServiceResponse>, StatusCode> {
    let mut store = state.store.write().await;
    if let Some(token) = auth::login_service(&mut store, &body.raw_key) {
        return Ok(Json(LoginServiceResponse { token: token.raw }));
    }
    Err(StatusCode::UNAUTHORIZED)
}
