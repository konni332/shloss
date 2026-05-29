use sqlx::PgPool;

mod credential;
mod session;
mod token;
mod user;

pub use credential::{ApiKey, PasswordCredential};
pub use session::Session;
pub use token::OpaqueToken;
pub use token::RefreshToken;
pub use user::User;

pub async fn init(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}
