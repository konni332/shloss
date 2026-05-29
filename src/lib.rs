use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod jwt;

pub use config::{CredentialKind, ShlossConfig, TokenKind};

use crate::config::ClientConfig;

/// Initialize logging. This should only ever be called once, on program start
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

pub fn load_config() -> anyhow::Result<ShlossConfig> {
    let config = ShlossConfig::load()?;
    config.validate()?;
    Ok(config)
}

pub fn load_client_credentials() -> anyhow::Result<ClientConfig> {
    let config = ClientConfig::load()?;
    config.validate()?;
    Ok(config)
}
