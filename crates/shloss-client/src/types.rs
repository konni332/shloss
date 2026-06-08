use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct ServiceLoginResponse {
    pub token: String,
}

pub struct LoginRequestBuilder {}
