use std::{collections::HashMap, str::FromStr};

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde_json::Value;
use shloss_types::{
    Credentials, LoginResponse, RefreshRequest, RefreshResponse, RegisterRequest, RegisterResponse,
    TokenType,
};

use crate::error::ClientError;

pub struct NoCredentials;
pub struct NoTokenKind;
pub struct WithCredentials(pub Credentials);
pub struct WithTokenKind(pub TokenType);

#[derive(Default)]
pub struct LoginBuilder<C, T> {
    credentials: C,
    token_kind: T,
    ip_address: Option<String>,
    user_agent: Option<String>,
    refresh_expiry: Option<DateTime<Utc>>,
}

impl LoginBuilder<NoCredentials, NoTokenKind> {
    pub fn new() -> Self {
        Self {
            credentials: NoCredentials,
            token_kind: NoTokenKind,
            ip_address: None,
            user_agent: None,
            refresh_expiry: None,
        }
    }
    pub fn with_password(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> LoginBuilder<WithCredentials, NoTokenKind> {
        LoginBuilder {
            credentials: WithCredentials(Credentials::Password {
                username: username.into(),
                password: password.into(),
            }),
            token_kind: NoTokenKind,
            ip_address: None,
            user_agent: None,
            refresh_expiry: None,
        }
    }
    pub fn with_api_key(
        self,
        full_key: impl Into<String>,
    ) -> LoginBuilder<WithCredentials, NoTokenKind> {
        LoginBuilder {
            credentials: WithCredentials(Credentials::ApiKey {
                full_key: full_key.into(),
            }),
            token_kind: NoTokenKind,
            ip_address: None,
            user_agent: None,
            refresh_expiry: None,
        }
    }
}

impl LoginBuilder<WithCredentials, NoTokenKind> {
    pub fn opaque_token(
        self,
        expires_at: DateTime<Utc>,
    ) -> LoginBuilder<WithCredentials, WithTokenKind> {
        LoginBuilder {
            credentials: self.credentials,
            token_kind: WithTokenKind(TokenType::Opaque { expires_at }),
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            refresh_expiry: self.refresh_expiry,
        }
    }

    pub fn jwt_token(
        self,
        claims: HashMap<String, Value>,
    ) -> LoginBuilder<WithCredentials, WithTokenKind> {
        LoginBuilder {
            credentials: self.credentials,
            token_kind: WithTokenKind(TokenType::Jwt { claims }),
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            refresh_expiry: self.refresh_expiry,
        }
    }
}

impl<T> LoginBuilder<WithCredentials, T> {
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    pub fn with_refresh(mut self, expires_at: DateTime<Utc>) -> Self {
        self.refresh_expiry = Some(expires_at);
        self
    }
}

impl LoginBuilder<WithCredentials, WithTokenKind> {
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<LoginResponse, ClientError> {
        let body = shloss_types::LoginRequest {
            credentials: self.credentials.0,
            ip_address: self
                .ip_address
                .map(|ip| IpNetwork::from_str(&ip))
                .transpose()?,
            user_agent: self.user_agent,
            token_kind: self.token_kind.0,
            refresh_expiry: self.refresh_expiry,
        };
        let res = reqwest::Client::new()
            .post(format!("{}/v1/auth/login", base_url))
            .bearer_auth(service_token)
            .json(&body)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(res.json().await?),
            401 => Err(ClientError::Unauthorized),
            _ => Err(ClientError::ServerError),
        }
    }
}

pub struct NoKind;
pub struct PasswordKind {
    username: String,
    password: String,
}
pub struct ApiKeyKind {
    name: String,
    key_prefix: String,
    expires_at: Option<DateTime<Utc>>,
}
#[derive(Default)]
pub struct RegisterBuilder<K> {
    kind: K,
}

impl RegisterBuilder<NoKind> {
    pub fn new() -> Self {
        Self { kind: NoKind }
    }

    pub fn password(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> RegisterBuilder<PasswordKind> {
        RegisterBuilder {
            kind: PasswordKind {
                username: username.into(),
                password: password.into(),
            },
        }
    }

    pub fn api_key(
        self,
        name: impl Into<String>,
        key_prefix: impl Into<String>,
    ) -> RegisterBuilder<ApiKeyKind> {
        RegisterBuilder {
            kind: ApiKeyKind {
                name: name.into(),
                key_prefix: key_prefix.into(),
                expires_at: None,
            },
        }
    }
}

impl RegisterBuilder<ApiKeyKind> {
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.kind.expires_at = Some(expires_at);
        self
    }

    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<RegisterResponse, ClientError> {
        let body = RegisterRequest::ApiKey {
            name: self.kind.name,
            key_prefix: self.kind.key_prefix,
            expires_at: self.kind.expires_at,
        };
        send_register(base_url, service_token, &body).await
    }
}

impl RegisterBuilder<PasswordKind> {
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<RegisterResponse, ClientError> {
        let body = RegisterRequest::Password {
            username: self.kind.username,
            password: self.kind.password,
        };
        send_register(base_url, service_token, &body).await
    }
}

async fn send_register(
    base_url: &str,
    service_token: &str,
    body: &RegisterRequest,
) -> Result<RegisterResponse, ClientError> {
    let res = reqwest::Client::new()
        .post(format!("{}/v1/auth/register", base_url))
        .bearer_auth(service_token)
        .json(body)
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(res.json().await?),
        401 => Err(ClientError::Unauthorized),
        409 => Err(ClientError::Conflict),
        _ => Err(ClientError::ServerError),
    }
}

#[derive(Default)]
pub struct RefreshBuilder<T> {
    pub refresh_token: String,
    pub token_kind: T,
}

impl RefreshBuilder<NoTokenKind> {
    pub fn new(refresh_token: impl Into<String>) -> RefreshBuilder<NoTokenKind> {
        Self {
            refresh_token: refresh_token.into(),
            token_kind: NoTokenKind,
        }
    }
    pub fn opaque_token(self, expires_at: DateTime<Utc>) -> RefreshBuilder<WithTokenKind> {
        RefreshBuilder {
            refresh_token: self.refresh_token,
            token_kind: WithTokenKind(TokenType::Opaque { expires_at }),
        }
    }

    pub fn jwt_token(self, claims: HashMap<String, Value>) -> RefreshBuilder<WithTokenKind> {
        RefreshBuilder {
            refresh_token: self.refresh_token,
            token_kind: WithTokenKind(TokenType::Jwt { claims }),
        }
    }
}

impl RefreshBuilder<WithTokenKind> {
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<RefreshResponse, ClientError> {
        let body = RefreshRequest {
            refresh_token: self.refresh_token,
            token_type: self.token_kind.0,
        };
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/auth/refresh"))
            .bearer_auth(service_token)
            .json(&body)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(res.json().await?),
            _ => Err(ClientError::ServerError),
        }
    }
}
