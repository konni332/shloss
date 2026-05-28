use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShlossError {
    #[error("config error: {0}")]
    ConfigError(#[from] ConfigError),

    #[error("client config error: {0}")]
    ClientConfigError(#[from] ClientConfigError),

    #[error("crypto error: {0}")]
    CryptoError(#[from] CryptoError),
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
    #[error("empty list of credentials")]
    EmptyClientCredentials,

    #[error("invalid username: {username}")]
    InvalidUsername { username: String },

    #[error("invalid password for user: {username}")]
    InvalidPassword { username: String },
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password hashing failed")]
    PasswordHashError,
    #[error("password verification failed")]
    PasswordVerifyError,
}
