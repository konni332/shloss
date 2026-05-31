use std::collections::{HashMap, HashSet};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
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

#[derive(Serialize, Clone)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize, Clone)]
pub struct Jwk {
    kty: String, // key type, always "RSA"
    alg: String, // always "RS256"
    #[serde(rename = "use")]
    use_: String, // always "sig"
    n: String,   // modulus base64url
    e: String,   // exponent base64url
    kid: String, // key id, so services can identify which key to use
}

impl Jwks {
    pub fn from_private_pem(pem: &str) -> anyhow::Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)?;
        let n = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());

        Ok(Self {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                alg: "RS256".to_string(),
                use_: "sig".to_string(),
                n,
                e,
                kid: "1".to_string(),
            }],
        })
    }
}
