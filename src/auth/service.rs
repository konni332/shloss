use chrono::{DateTime, Duration, Utc};

use crate::{
    config::ClientConfig,
    crypto::{GeneratedToken, generate_token, hash_secret, verify_token},
};

pub const SERVICE_TOKEN_TTL: Duration = Duration::days(1);

#[derive(Debug, Clone, Default)]
pub struct ServiceKeyStore {
    key_hashes: Vec<String>,
    service_tokens: Vec<ServiceToken>,
}

#[derive(Debug, Clone)]
pub struct ServiceToken {
    hash: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl ServiceKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn verify_key(&self, key: &str) -> bool {
        let hash = hash_secret(key);
        self.key_hashes.iter().any(|h| h == &hash)
    }
}

pub(crate) fn register_service(store: &mut ServiceKeyStore, raw_key: &str) {
    let hash = hash_secret(raw_key);
    store.key_hashes.push(hash);
}

pub(crate) fn login_service(store: &mut ServiceKeyStore, raw_key: &str) -> Option<GeneratedToken> {
    let hash = hash_secret(raw_key);
    if !store.key_hashes.iter().any(|kh| kh == &hash) {
        return None;
    }

    let generated_token = generate_token();
    let created_at = Utc::now();
    let expires_at = created_at + SERVICE_TOKEN_TTL;
    let token = ServiceToken {
        hash: generated_token.hash.clone(),
        created_at,
        expires_at,
    };
    store.service_tokens.push(token);
    Some(generated_token)
}

pub(crate) fn validate_service_token(store: &ServiceKeyStore, raw_token: &str) -> bool {
    let hash = hash_secret(raw_token);
    let now = Utc::now();
    store
        .service_tokens
        .iter()
        .any(|t| t.hash == hash && t.expires_at > now)
}

impl From<&ClientConfig> for ServiceKeyStore {
    fn from(value: &ClientConfig) -> Self {
        let hashes = value.keys.iter().map(|k| k.hash.clone()).collect();
        Self {
            key_hashes: hashes,
            service_tokens: vec![],
        }
    }
}
