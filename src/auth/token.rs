use std::collections::HashSet;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    TokenKind,
    crypto::hash_secret,
    db::{OpaqueToken, RefreshToken},
    error::ShlossResult,
    jwt::Claims,
};

pub struct TokenToValidate {
    pub raw: String,
    pub kind: TokenKind,
}

pub async fn validate_token(
    pool: &PgPool,
    decoding_key: &DecodingKey,
    token: TokenToValidate,
) -> ShlossResult<Option<Uuid>> {
    match token.kind {
        TokenKind::Opague => validate_opaque_token(pool, &token.raw).await,
        TokenKind::Refresh => validate_refresh_token(pool, &token.raw).await,
        TokenKind::Jwt => validate_jwt(decoding_key, &token.raw).await,
    }
}

async fn validate_jwt(decoding_key: &DecodingKey, token: &str) -> ShlossResult<Option<Uuid>> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims = HashSet::new();

    let claims = decode::<Claims>(token, decoding_key, &validation)
        .map(|data| data.claims)
        .ok();
    Ok(claims.map(|c| c.sub))
}

async fn validate_refresh_token(pool: &PgPool, raw: &str) -> ShlossResult<Option<Uuid>> {
    let hash = hash_secret(raw);
    let token = RefreshToken::find_valid_by_hash(pool, &hash).await?;
    Ok(token.map(|t| t.user_id))
}

async fn validate_opaque_token(pool: &PgPool, raw: &str) -> ShlossResult<Option<Uuid>> {
    let hash = hash_secret(raw);
    let token = OpaqueToken::find_valid_by_hash(pool, &hash).await?;
    Ok(token.map(|t| t.user_id))
}
