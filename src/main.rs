use std::sync::Arc;

use anyhow::Context;
use shloss::{db, init_logging, load_client_credentials, load_config};
use tokio::sync::RwLock;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    info!("shloss startup");

    let config = load_config()?;
    info!(host = %config.host, port = %config.port, "config loaded");

    let client_config = load_client_credentials()?;
    info!(num_service_keys = %client_config.keys.len(), "client config loaded");

    let private_key_pem =
        std::env::var("SHLOSS_PRIVATE_KEY").context("SHLOSS_PRIVATE_KEY not set")?;

    info!("private key pem loaded");

    let pool = db::init(&config.database_url)
        .await
        .context("failed to initialize DB connection")?;

    info!("database connection established");

    let encoding_key = Arc::new(
        jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .context("invalid private key")?,
    );
    let decoding_key = Arc::new(
        jsonwebtoken::DecodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .context("invalid private key")?,
    );
    let jwks = Arc::new(
        shloss::jwt::Jwks::from_private_pem(&private_key_pem).context("failed to build JWKS")?,
    );

    let state = shloss::server::AppState {
        pool,
        store: Arc::new(RwLock::new((&client_config).into())),
        encoding_key,
        decoding_key,
        jwks,
    };

    let app = shloss::build_router(state);
    let listener =
        tokio::net::TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;

    info!("shloss startup complete");
    info!(host = %config.host, port = %config.port, "listening...");
    axum::serve(listener, app).await?;

    Ok(())
}
