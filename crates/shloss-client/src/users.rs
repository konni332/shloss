use chrono::{DateTime, Utc};
use shloss_types::{
    AddApiKeyRequest, AddApiKeyResponse, ChangePasswordRequest, ChangeUsernameRequest,
    RevokeApiKeyRequest, Session,
};
use uuid::Uuid;

use crate::error::ClientError;

pub async fn delete_user(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
) -> Result<(), ClientError> {
    let res = reqwest::Client::new()
        .delete(format!("{base_url}/v1/users/{user_id}"))
        .bearer_auth(service_token)
        .send()
        .await?;

    match res.status().as_u16() {
        200 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        404 => Err(ClientError::NotFound),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn revoke_session_for_user(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<(), ClientError> {
    let res = reqwest::Client::new()
        .delete(format!(
            "{base_url}/v1/users/{user_id}/sessions/{session_id}"
        ))
        .bearer_auth(service_token)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        404 => Err(ClientError::NotFound),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn revoke_sessions_and_tokens_for_user(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
) -> Result<(), ClientError> {
    let res = reqwest::Client::new()
        .delete(format!("{base_url}/v1/users/{user_id}/sessions"))
        .bearer_auth(service_token)
        .send()
        .await?;

    match res.status().as_u16() {
        200 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn list_sessions(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
) -> Result<Vec<Session>, ClientError> {
    let res = reqwest::Client::new()
        .get(format!("{base_url}/v1/users/{user_id}/sessions"))
        .bearer_auth(service_token)
        .send()
        .await?;

    match res.status().as_u16() {
        200 => Ok(res.json().await?),
        401 => Err(ClientError::Unauthorized),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn change_username(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
    new_username: impl Into<String>,
) -> Result<(), ClientError> {
    let body = ChangeUsernameRequest {
        new_username: new_username.into(),
    };
    let res = reqwest::Client::new()
        .post(format!("{base_url}/v1/users/{user_id}/username"))
        .bearer_auth(service_token)
        .json(&body)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        404 => Err(ClientError::NotFound),
        409 => Err(ClientError::Conflict),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn change_user_password(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
    new_password: impl Into<String>,
) -> Result<(), ClientError> {
    let body = ChangePasswordRequest {
        new_password: new_password.into(),
    };
    let res = reqwest::Client::new()
        .post(format!("{base_url}/v1/users/{user_id}/password"))
        .bearer_auth(service_token)
        .json(&body)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        404 => Err(ClientError::NotFound),
        409 => Err(ClientError::Conflict),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn revoke_all_api_keys(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
) -> Result<(), ClientError> {
    let res = reqwest::Client::new()
        .delete(format!("{base_url}/v1/users/{user_id}/api-key/all"))
        .bearer_auth(service_token)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn add_api_key(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
    name: impl Into<String>,
    key_prefix: impl Into<String>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<String, ClientError> {
    let body = AddApiKeyRequest {
        name: name.into(),
        key_prefix: key_prefix.into(),
        expires_at,
    };
    let res = reqwest::Client::new()
        .post(format!("{base_url}/v1/users/{user_id}/api-key"))
        .bearer_auth(service_token)
        .json(&body)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(res.json::<AddApiKeyResponse>().await?.key),
        401 => Err(ClientError::Unauthorized),
        404 => Err(ClientError::NotFound),
        _ => Err(ClientError::ServerError),
    }
}

pub async fn revoke_api_key(
    base_url: &str,
    service_token: &str,
    user_id: Uuid,
    key: impl Into<String>,
) -> Result<(), ClientError> {
    let body = RevokeApiKeyRequest { key: key.into() };
    let res = reqwest::Client::new()
        .delete(format!("{base_url}/v1/users/{user_id}/api-key"))
        .bearer_auth(service_token)
        .json(&body)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        _ => Err(ClientError::ServerError),
    }
}
