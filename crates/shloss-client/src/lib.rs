use crate::{
    auth::{LoginBuilder, NoCredentials, NoKind, NoTokenKind, RefreshBuilder, RegisterBuilder},
    well_known::JwksBuilder,
};

pub mod auth;
pub mod error;
pub mod token;
mod types;
pub mod well_known;

pub struct Request;

impl Request {
    pub fn login() -> LoginBuilder<NoCredentials, NoTokenKind> {
        LoginBuilder::new()
    }
    pub fn register() -> RegisterBuilder<NoKind> {
        RegisterBuilder::new()
    }
    pub fn refresh(refresh_token: impl Into<String>) -> RefreshBuilder<NoTokenKind> {
        RefreshBuilder::new(refresh_token)
    }
    pub fn jwks() -> JwksBuilder {
        JwksBuilder
    }
    pub fn validate_jwt() -> 
}
