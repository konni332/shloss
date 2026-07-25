use crate::{
    auth::{
        __LoginBuilderCredentialsUnset, __LoginBuilderTokenKindUnset,
        __RefreshBuilderRefreshTokenSet, __RefreshBuilderTokenKindUnset,
        __RegisterBuilderCredentialsUnset, LoginBuilder, RefreshBuilder, RegisterBuilder,
    },
    token::{NoToken, ValidateBuilder},
    well_known::JwksBuilder,
};

pub mod auth;
pub mod error;
pub mod token;
mod types;
pub mod well_known;

pub struct Request;

impl Request {
    pub fn login() -> LoginBuilder<__LoginBuilderCredentialsUnset, __LoginBuilderTokenKindUnset> {
        LoginBuilder::new()
    }
    pub fn register() -> RegisterBuilder<__RegisterBuilderCredentialsUnset> {
        RegisterBuilder::new()
    }
    pub fn refresh(
        refresh_token: impl Into<String>,
    ) -> RefreshBuilder<__RefreshBuilderRefreshTokenSet, __RefreshBuilderTokenKindUnset> {
        RefreshBuilder::new().set_refresh_token(refresh_token)
    }
    pub fn jwks() -> JwksBuilder {
        JwksBuilder
    }
    pub fn validate_jwt() -> ValidateBuilder<NoToken> {
        ValidateBuilder::new()
    }
}
