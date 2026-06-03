use config::Config;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ShlossConfig {
    pub database_url: String,
    pub host: String,
    pub port: usize,
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
        Self {
            port: 3000,
            host: "127.0.0.1".to_string(),
            database_url,
        }
    }
}

impl ShlossConfig {
    pub(crate) fn load() -> anyhow::Result<Self> {
        let defaults = Self::default();
        Config::builder()
            .set_default("database_url", defaults.database_url)?
            .set_default("port", defaults.port.to_string())?
            .set_default("host", defaults.host)?
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
}
