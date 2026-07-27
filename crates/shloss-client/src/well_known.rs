use shloss_types::Jwks;

use crate::error::ClientError;

#[derive(Default)]
pub struct GetJwks;

impl GetJwks {
    pub fn new() -> Self {
        Self
    }

    pub async fn send(self, base_url: &str) -> Result<Jwks, ClientError> {
        let res = reqwest::Client::new()
            .get(format!("{base_url}/v1/.well-known/jwks.json"))
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(res.json().await?),
            _ => Err(ClientError::ServerError),
        }
    }
}
