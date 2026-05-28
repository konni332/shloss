use std::path::Path;

use serde::Deserialize;

use crate::error::ClientConfigError;

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    credentials: Vec<ClientCredentials>,
}
#[derive(Debug, Deserialize)]
pub struct ClientCredentials {
    username: String,
    password: String,
}

impl ClientConfig {
    pub(crate) fn load() -> anyhow::Result<Self> {
        let path = Path::new("./client_credentials.toml");
        let toml_str = std::fs::read_to_string(path)?;
        let toml: Self = toml::from_str(&toml_str)?;
        Ok(toml)
    }
    pub(crate) fn validate(&self) -> Result<(), ClientConfigError> {
        if self.credentials.is_empty() {
            return Err(ClientConfigError::EmptyClientCredentials);
        }

        for cred in self.credentials.iter() {
            if !username_valid(&cred.username) {
                return Err(ClientConfigError::InvalidUsername {
                    username: cred.username.clone(),
                });
            }
            if !password_valid(&cred.password) {
                return Err(ClientConfigError::InvalidPassword {
                    username: cred.username.clone(),
                });
            }
        }

        Ok(())
    }
}

fn username_valid(username: &str) -> bool {
    !username.is_empty()
}

fn password_valid(password: &str) -> bool {
    !password.is_empty()
}
