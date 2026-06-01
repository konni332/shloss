use std::{collections::HashMap, path::Path};

use serde::Deserialize;

use crate::error::ClientConfigError;

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub keys: Vec<ServiceKey>,
}
#[derive(Debug, Deserialize)]
pub struct ServiceKey {
    pub name: String,
    pub hash: String,
}

impl ClientConfig {
    pub(crate) fn load() -> anyhow::Result<Self> {
        let path = Path::new("./client_credentials.toml");
        let toml_str = std::fs::read_to_string(path)?;
        let toml: Self = toml::from_str(&toml_str)?;
        Ok(toml)
    }
    pub(crate) fn validate(&self) -> Result<(), ClientConfigError> {
        if self.keys.is_empty() {
            return Err(ClientConfigError::EmptyServiceKeys);
        }
        let mut seen_hashes: HashMap<&str, &str> = HashMap::new();
        for key in self.keys.iter() {
            let last = &key.name;
            if let Some(dup) = seen_hashes.insert(&key.hash, &key.name) {
                return Err(ClientConfigError::KeyCollision(
                    last.to_string(),
                    dup.to_string(),
                ));
            }
        }
        Ok(())
    }
}
