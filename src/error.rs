use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShlossError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("client config error: {0}")]
    ClientConfig(#[from] ClientConfigError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
}

pub type ShlossResult<T> = Result<T, ShlossError>;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("empty list of allowed credential kinds")]
    EmptyCredentials,

    #[error("empty list of allowed token kinds")]
    EmptyTokens,
}

#[derive(Debug, Error)]
pub enum ClientConfigError {
    #[error("empty list of service keys")]
    EmptyServiceKeys,

    #[error("key collision: services '{0}' and '{1}' have the same key")]
    KeyCollision(String, String),
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password hashing failed")]
    PasswordHash,
    #[error("password verification failed")]
    PasswordVerify,
    #[error("token verification failed")]
    TokenVerify,
    #[error("jwt error")]
    Jwt,
}
