use shloss_types::{TokenValidateRequest, TokenValidateResponse};

use crate::error::ClientError;

pub struct NoToken;
pub enum WithToken {
    Jwt(String),
    Opaque(String),
}

#[derive(Default)]
pub struct ValidateBuilder<T> {
    kind: T,
}

impl ValidateBuilder<NoToken> {
    pub fn new() -> ValidateBuilder<NoToken> {
        ValidateBuilder { kind: NoToken }
    }
    pub fn jwt_token(self, token: impl Into<String>) -> ValidateBuilder<WithToken> {
        ValidateBuilder {
            kind: WithToken::Jwt(token.into()),
        }
    }
    pub fn opaque_token(self, token: impl Into<String>) -> ValidateBuilder<WithToken> {
        ValidateBuilder {
            kind: WithToken::Opaque(token.into()),
        }
    }
}

impl ValidateBuilder<WithToken> {
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<TokenValidateResponse, ClientError> {
        let body = match self.kind {
            WithToken::Jwt(t) => TokenValidateRequest {
                token: t,
                kind: shloss_types::TokenKind::Jwt,
            },
            WithToken::Opaque(t) => TokenValidateRequest {
                token: t,
                kind: shloss_types::TokenKind::Opaque,
            },
        };
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/tokens/validate"))
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
