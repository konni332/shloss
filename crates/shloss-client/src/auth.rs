use std::{collections::HashMap, str::FromStr};

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde_json::Value;
use shloss_types::{
    Credentials, LoginResponse, LoginServiceRequest, LoginServiceResponse, RefreshRequest,
    RefreshResponse, RegisterRequest, RegisterResponse, TokenType,
};
use stave::{builder, methods};

use crate::error::ClientError;

#[builder]
pub struct LoginBuilder {
    #[stave(required)]
    credentials: Credentials,
    #[stave(required)]
    token_kind: TokenType,
    ip_address: String,
    user_agent: String,
    refresh_expiry: DateTime<Utc>,
}

#[methods]
impl LoginBuilder {
    #[sets(credentials)]
    pub fn with_password(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Credentials {
        Credentials::Password {
            username: username.into(),
            password: password.into(),
        }
    }
    #[sets(credentials)]
    pub fn with_api_key(self, full_key: impl Into<String>) -> Credentials {
        Credentials::ApiKey {
            full_key: full_key.into(),
        }
    }
    #[sets(token_kind)]
    #[requires(credentials)]
    pub fn opaque_token(self, expires_at: DateTime<Utc>) -> TokenType {
        TokenType::Opaque { expires_at }
    }

    #[sets(token_kind)]
    #[requires(credentials)]
    pub fn jwt_token(self, claims: HashMap<String, Value>) -> TokenType {
        TokenType::Jwt { claims }
    }

    #[sets(ip_address)]
    #[requires(credentials)]
    pub fn set_ip_address(mut self, ip: impl Into<String>) -> String {
        ip.into()
    }
    #[sets(user_agent)]
    #[requires(credentials)]
    pub fn set_user_agent(mut self, user_agent: impl Into<String>) -> String {
        user_agent.into()
    }
    #[sets(refresh_expiry)]
    #[requires(credentials)]
    pub fn with_refresh(mut self, expires_at: DateTime<Utc>) -> DateTime<Utc> {
        expires_at
    }

    #[requires(credentials, token_kind)]
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<LoginResponse, ClientError> {
        let credentials = self.credentials().clone();
        let token_kind = self.token_kind().clone();
        let body = shloss_types::LoginRequest {
            credentials,
            ip_address: self
                .ip_address
                .map(|ip| IpNetwork::from_str(&ip))
                .transpose()?,
            user_agent: self.user_agent,
            token_kind,
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

#[derive(Clone)]
pub enum RegisterCredentials {
    Password {
        username: String,
        password: String,
    },
    ApiKey {
        name: String,
        key_prefix: String,
        expires_at: Option<DateTime<Utc>>,
    },
}

#[builder]
pub struct RegisterBuilder {
    #[stave(required)]
    credentials: RegisterCredentials,
}

#[methods]
impl RegisterBuilder {
    #[sets(credentials)]
    pub fn with_password(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> RegisterCredentials {
        RegisterCredentials::Password {
            username: username.into(),
            password: password.into(),
        }
    }
    #[sets(credentials)]
    pub fn with_api_key(
        self,
        name: impl Into<String>,
        key_prefix: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Credentials {
        RegisterCredentials::ApiKey {
            name: name.into(),
            key_prefix: key_prefix.into(),
            expires_at,
        }
    }

    #[requires(credentials)]
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<RegisterResponse, ClientError> {
        let body = match self.credentials() {
            RegisterCredentials::Password { username, password } => RegisterRequest::Password {
                username: username.into(),
                password: password.into(),
            },
            RegisterCredentials::ApiKey {
                name,
                key_prefix,
                expires_at,
            } => RegisterRequest::ApiKey {
                name: name.into(),
                key_prefix: key_prefix.into(),
                expires_at: *expires_at,
            },
        };

        let res = reqwest::Client::new()
            .post(format!("{}/v1/auth/register", base_url))
            .bearer_auth(service_token)
            .json(&body)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(res.json().await?),
            401 => Err(ClientError::Unauthorized),
            409 => Err(ClientError::Conflict),
            _ => Err(ClientError::ServerError),
        }
    }
}

#[builder]
pub struct RefreshBuilder {
    #[stave(required)]
    pub refresh_token: String,
    #[stave(required)]
    pub token_kind: TokenType,
}

#[methods]
impl RefreshBuilder {
    #[sets(token_kind)]
    pub fn with_opaque_token(self, expires_at: DateTime<Utc>) -> TokenType {
        TokenType::Opaque { expires_at }
    }
    #[sets(token_kind)]
    pub fn with_jwt(self, claims: HashMap<String, Value>) -> TokenType {
        TokenType::Jwt { claims }
    }

    #[sets(refresh_token)]
    pub fn set_refresh_token(self, token: impl Into<String>) -> String {
        token.into()
    }

    #[requires(refresh_token, token_kind)]
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<RefreshResponse, ClientError> {
        let body = RefreshRequest {
            refresh_token: self.refresh_token().clone(),
            token_type: self.token_kind().clone(),
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

pub struct ServiceLoginBuilder {
    raw_key: String,
}

impl ServiceLoginBuilder {
    pub fn new(raw_key: impl Into<String>) -> Self {
        Self {
            raw_key: raw_key.into(),
        }
    }

    pub async fn send(self, base_url: &str) -> Result<LoginServiceResponse, ClientError> {
        let body = LoginServiceRequest {
            raw_key: self.raw_key,
        };
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/auth/service"))
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
