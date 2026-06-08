#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("server error")]
    ServerError,
    #[error("ipnetwork parsing error: {0}")]
    IpNetworkParsing(#[from] ipnetwork::IpNetworkError),
}
