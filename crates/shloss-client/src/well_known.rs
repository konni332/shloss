use shloss_types::Jwks;

use crate::error::ClientError;

pub struct JwksBuilder;

impl JwksBuilder {
    pub async fn send(base_url: &str) -> Result<Jwks, ClientError> {
        let res = reqwest::Client::new()
            .post(format!("{base_url}/v1/.well-known/jwks"))
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(res.json().await?),
            _ => Err(ClientError::ServerError),
        }
    }
}
