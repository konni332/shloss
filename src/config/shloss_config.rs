use config::Config;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

#[derive(Debug, Deserialize)]
pub struct ShlossConfig {
    pub database_url: String,
    pub host: String,
    pub port: usize,
    pub credentials: Vec<CredentialKind>,
    pub tokens: Vec<TokenKind>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TokenKind {
    Opague,
    Jwt,
    Refresh,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    ApiKey,
    Password,
}

impl Default for ShlossConfig {
    fn default() -> Self {
        let database_url = "postgresql:///shloss".to_owned();
        let credentials = vec![CredentialKind::ApiKey, CredentialKind::Password];
        let tokens = vec![TokenKind::Opague, TokenKind::Jwt];
        Self {
            port: 3000,
            host: "127.0.0.1".to_string(),
            database_url,
            credentials,
            tokens,
        }
    }
}

impl ShlossConfig {
    pub(crate) fn load() -> anyhow::Result<Self> {
        let defaults = Self::default();
        Config::builder()
            .set_default("database_url", defaults.database_url)?
            .set_default("credentials", vec!["api-key", "password"])?
            .set_default("tokens", vec!["opague", "jwt"])?
            .add_source(config::File::with_name("shloss").required(false))
            .add_source(
                config::Environment::with_prefix("SHLOSS")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?
            .try_deserialize()
            .map_err(Into::into)
    }
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.credentials.is_empty() {
            return Err(ConfigError::EmptyCredentials);
        }

        if self.tokens.is_empty() {
            return Err(ConfigError::EmptyTokens);
        }

        Ok(())
    }
}
