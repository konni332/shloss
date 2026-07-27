use shloss_types::{TokenValidateRequest, TokenValidateResponse};
use stave::{builder, methods};

use crate::error::ClientError;

pub enum TokenType {
    Jwt(String),
    Opaque(String),
}

#[builder]
pub struct ValidateBuilder {
    #[stave(required)]
    kind: TokenType,
}

#[methods]
impl ValidateBuilder {
    #[sets(kind)]
    pub fn with_jwt(self, token: impl Into<String>) -> TokenType {
        TokenType::Jwt(token.into())
    }
    #[sets(kind)]
    pub fn with_opaque(self, token: impl Into<String>) -> TokenType {
        TokenType::Opaque(token.into())
    }
    #[requires(kind)]
    pub async fn send(
        self,
        base_url: &str,
        service_token: &str,
    ) -> Result<TokenValidateResponse, ClientError> {
        let body = match self.kind() {
            TokenType::Jwt(t) => TokenValidateRequest {
                token: t.into(),
                kind: shloss_types::TokenKind::Jwt,
            },
            TokenType::Opaque(t) => TokenValidateRequest {
                token: t.into(),
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
