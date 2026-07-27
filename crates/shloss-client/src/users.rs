use chrono::{DateTime, Utc};
use shloss_types::{
    AddApiKeyRequest, AddApiKeyResponse, ChangePasswordRequest, ChangeUsernameRequest,
    RevokeApiKeyRequest, Session,
};
use uuid::Uuid;

use crate::error::ClientError;

pub struct DeleteUser {
    user_id: Uuid,
}

impl DeleteUser {
    pub fn new(user_id: Uuid) -> Self {
        Self { user_id }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<(), ClientError> {
        let res = reqwest::Client::new()
            .delete(format!("{base_url}/v1/users/{}", self.user_id))
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
}

pub struct RevokeSession {
    user_id: Uuid,
    session_id: Uuid,
}

impl RevokeSession {
    pub fn new(user_id: Uuid, session_id: Uuid) -> Self {
        Self {
            user_id,
            session_id,
        }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<(), ClientError> {
        let res = reqwest::Client::new()
            .delete(format!(
                "{base_url}/v1/users/{}/sessions/{}",
                self.user_id, self.session_id
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
}

pub struct RevokeAllSessions {
    user_id: Uuid,
}

impl RevokeAllSessions {
    pub fn new(user_id: Uuid) -> Self {
        Self { user_id }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<(), ClientError> {
        let res = reqwest::Client::new()
            .delete(format!("{base_url}/v1/users/{}/sessions", self.user_id))
            .bearer_auth(service_token)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(()),
            401 => Err(ClientError::Unauthorized),
            _ => Err(ClientError::ServerError),
        }
    }
}

pub struct ListSessions {
    user_id: Uuid,
}

impl ListSessions {
    pub fn new(user_id: Uuid) -> Self {
        Self { user_id }
    }

    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<Vec<Session>, ClientError> {
        let res = reqwest::Client::new()
            .get(format!("{base_url}/v1/users/{}/sessions", self.user_id))
            .bearer_auth(service_token)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(res.json().await?),
            401 => Err(ClientError::Unauthorized),
            _ => Err(ClientError::ServerError),
        }
    }
}

pub struct ChangeUsername {
    user_id: Uuid,
    new_username: String,
}

impl ChangeUsername {
    pub fn new(user_id: Uuid, new_username: impl Into<String>) -> Self {
        Self {
            user_id,
            new_username: new_username.into(),
        }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<(), ClientError> {
        let body = ChangeUsernameRequest {
            new_username: self.new_username,
        };
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/users/{}/username", self.user_id))
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
}

pub struct ChangePassword {
    user_id: Uuid,
    new_password: String,
}

impl ChangePassword {
    pub fn new(user_id: Uuid, new_password: impl Into<String>) -> Self {
        Self {
            user_id,
            new_password: new_password.into(),
        }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<(), ClientError> {
        let body = ChangePasswordRequest {
            new_password: self.new_password,
        };
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/users/{}/password", self.user_id))
            .bearer_auth(service_token)
            .json(&body)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(()),
            401 => Err(ClientError::Unauthorized),
            404 => Err(ClientError::NotFound),
            _ => Err(ClientError::ServerError),
        }
    }
}

pub struct RevokeAllApiKeys {
    user_id: Uuid,
}

impl RevokeAllApiKeys {
    pub fn new(user_id: Uuid) -> Self {
        Self { user_id }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<(), ClientError> {
        let res = reqwest::Client::new()
            .delete(format!("{base_url}/v1/users/{}/api-key/all", self.user_id))
            .bearer_auth(service_token)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(()),
            401 => Err(ClientError::Unauthorized),
            _ => Err(ClientError::ServerError),
        }
    }
}

pub struct AddApiKey {
    user_id: Uuid,
    name: String,
    key_prefix: String,
    expires_at: Option<DateTime<Utc>>,
}

impl AddApiKey {
    pub fn new(
        user_id: Uuid,
        name: impl Into<String>,
        key_prefix: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            user_id,
            name: name.into(),
            key_prefix: key_prefix.into(),
            expires_at,
        }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<String, ClientError> {
        let body = AddApiKeyRequest {
            name: self.name,
            key_prefix: self.key_prefix,
            expires_at: self.expires_at,
        };
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/users/{}/api-key", self.user_id))
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
}

pub struct RevokeApiKey {
    user_id: Uuid,
    key: String,
}

impl RevokeApiKey {
    pub fn new(user_id: Uuid, key: impl Into<String>) -> Self {
        Self {
            user_id,
            key: key.into(),
        }
    }

    pub async fn send(self, base_url: &str, service_token: &str) -> Result<(), ClientError> {
        let body = RevokeApiKeyRequest { key: self.key };
        let res = reqwest::Client::new()
            .delete(format!("{base_url}/v1/users/{}/api-key", self.user_id))
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
}
