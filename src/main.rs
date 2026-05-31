use std::sync::Arc;

use anyhow::Context;
use shloss::{db, init_logging, load_client_credentials, load_config};
use tokio::sync::RwLock;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    info!("shloss: begin startup");

    let config = load_config()?;
    let client_config = load_client_credentials()?;
    let private_key_pem =
        std::env::var("SHLOSS_PRIVATE_KEY").context("SHLOSS_PRIVATE_KEY not set")?;

    let pool = db::init(&config.database_url)
        .await
        .context("failed to initialize DB connection")?;

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

    let app = shloss::server::build_router(state);
    let listener =
        tokio::net::TcpListener::bind(&format!("{}:{}", config.host, config.port)).await?;

    info!("shloss: ready");
    axum::serve(listener, app).await?;

    Ok(())
}
