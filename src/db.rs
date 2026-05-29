use sqlx::PgPool;

mod credential;
mod session;
mod token;
mod user;

pub async fn init(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}
