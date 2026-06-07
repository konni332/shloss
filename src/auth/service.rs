use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::{
    config::ClientConfig,
    crypto::{GeneratedToken, generate_token, hash_secret},
};

pub const SERVICE_TOKEN_TTL: Duration = Duration::days(1);

#[derive(Debug, Clone, Default)]
pub struct ServiceKeyStore {
    key_hashes: HashMap<String, Uuid>,
    pub service_tokens: Vec<ServiceToken>,
}
// Dead code is allowed, because we want a consistent in memory model of the DB data even if some
// or all fields are never read!
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ServiceToken {
    pub hash: String,
    pub vault_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ServiceKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn verify_key(&self, key: &str) -> Option<Uuid> {
        let hash = hash_secret(key);
        self.key_hashes.get(&hash).cloned()
    }
    pub fn with_test_keys(raw_keys: &[&'static str]) -> Self {
        let mut store = Self::new();
        for (id, raw_key) in raw_keys.iter().enumerate() {
            let hash = hash_secret(raw_key);
            let vault_id = Uuid::from_u128(id as u128);
            store.key_hashes.insert(hash, vault_id);
        }
        store
    }
}

pub fn login_service(store: &mut ServiceKeyStore, raw_key: &str) -> Option<GeneratedToken> {
    let hash = hash_secret(raw_key);
    let vault_id = *store.key_hashes.get(&hash)?;

    let generated_token = generate_token();
    let created_at = Utc::now();
    let expires_at = created_at + SERVICE_TOKEN_TTL;
    let token = ServiceToken {
        hash: generated_token.hash.clone(),
        created_at,
        expires_at,
        vault_id,
    };
    store.service_tokens.push(token);
    Some(generated_token)
}

pub fn validate_service_token(store: &ServiceKeyStore, raw_token: &str) -> Option<Uuid> {
    let hash = hash_secret(raw_token);
    let now = Utc::now();
    store
        .service_tokens
        .iter()
        .find(|t| t.hash == hash && t.expires_at > now)
        .map(|t| t.vault_id)
}

impl From<&ClientConfig> for ServiceKeyStore {
    fn from(value: &ClientConfig) -> Self {
        let mut key_hashes = HashMap::with_capacity(value.keys.len());
        for key in value.keys.iter() {
            key_hashes.insert(key.hash.clone(), key.vault_id);
        }
        Self {
            key_hashes,
            service_tokens: vec![],
        }
    }
}
