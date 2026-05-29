use std::collections::{HashMap, HashSet};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::CryptoError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

pub fn generate_jwt(
    user_id: Uuid,
    custom_claims: HashMap<String, Value>,
    encoding_key: &EncodingKey,
) -> Result<String, CryptoError> {
    let claims = Claims {
        sub: user_id,
        custom: custom_claims,
    };
    encode(&Header::new(Algorithm::RS256), &claims, encoding_key).map_err(|_| CryptoError::Jwt)
}

pub fn verify_jwt(token: &str, decoding_key: &DecodingKey) -> Result<Claims, CryptoError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims = HashSet::new();

    decode::<Claims>(token, decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|_| CryptoError::Jwt)
}
