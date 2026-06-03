use anyhow::Context;
use tracing_subscriber::EnvFilter;

mod api;
pub mod auth;
mod config;
pub mod crypto;
pub mod db;
mod error;
pub mod jwt;
pub mod server;

pub use crate::config::ClientConfig;
pub use api::build_router;
pub use config::{CredentialKind, ShlossConfig, TokenKind};
pub use crypto::{GeneratedToken, hash_secret};

/// Initialize logging. This should only ever be called once, on program start
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

pub fn load_config() -> anyhow::Result<ShlossConfig> {
    ShlossConfig::load()
}

pub fn load_client_credentials() -> anyhow::Result<ClientConfig> {
    let config = ClientConfig::load()?;
    config
        .validate()
        .context("failed to validate client config")?;
    Ok(config)
}
