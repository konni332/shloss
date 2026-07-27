use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    auth::{
        __LoginBuilderCredentialsUnset, __LoginBuilderTokenKindUnset,
        __RefreshBuilderRefreshTokenSet, __RefreshBuilderTokenKindUnset,
        __RegisterBuilderCredentialsUnset, LoginBuilder, RefreshBuilder, RegisterBuilder,
    },
    token::{__ValidateBuilderKindUnset, ValidateBuilder},
    users::{
        AddApiKey, ChangePassword, ChangeUsername, DeleteUser, ListSessions, RevokeAllApiKeys,
        RevokeAllSessions, RevokeApiKey, RevokeSession,
    },
    well_known::GetJwks,
};

pub mod auth;
pub mod error;
pub mod token;
pub mod users;
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
    pub fn validate_jwt() -> ValidateBuilder<__ValidateBuilderKindUnset> {
        ValidateBuilder::new()
    }

    pub fn delete_user(user_id: Uuid) -> DeleteUser {
        DeleteUser::new(user_id)
    }
    pub fn revoke_session(user_id: Uuid, session_id: Uuid) -> RevokeSession {
        RevokeSession::new(user_id, session_id)
    }
    pub fn revoke_all_sessions(user_id: Uuid) -> RevokeAllSessions {
        RevokeAllSessions::new(user_id)
    }
    pub fn list_sessions(user_id: Uuid) -> ListSessions {
        ListSessions::new(user_id)
    }
    pub fn change_username(user_id: Uuid, new_username: impl Into<String>) -> ChangeUsername {
        ChangeUsername::new(user_id, new_username)
    }
    pub fn change_password(user_id: Uuid, new_password: impl Into<String>) -> ChangePassword {
        ChangePassword::new(user_id, new_password)
    }
    pub fn revoke_all_api_keys(user_id: Uuid) -> RevokeAllApiKeys {
        RevokeAllApiKeys::new(user_id)
    }
    pub fn add_api_key(
        user_id: Uuid,
        name: impl Into<String>,
        key_prefix: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> AddApiKey {
        AddApiKey::new(user_id, name, key_prefix, expires_at)
    }
    pub fn revoke_api_key(user_id: Uuid, key: impl Into<String>) -> RevokeApiKey {
        RevokeApiKey::new(user_id, key)
    }
    pub fn get_jwks() -> GetJwks {
        GetJwks::new()
    }
}
