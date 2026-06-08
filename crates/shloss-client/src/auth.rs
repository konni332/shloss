use crate::{error::ClientError, types::ServiceLoginResponse};

pub async fn login_service(
    base_url: &str,
    raw_key: &str,
) -> Result<ServiceLoginResponse, ClientError> {
    let res = reqwest::Client::new()
        .post(format!("{base_url}/v1/auth/service"))
        .json(&serde_json::json!({ "rawKey": raw_key }))
        .send()
        .await?;
    match res.status().as_u16() {
        200 => Ok(res.json().await?),
        401 => Err(ClientError::Unauthorized),
        _ => Err(ClientError::ServerError),
    }
}
