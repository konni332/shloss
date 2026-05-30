use std::collections::HashSet;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    crypto::hash_secret,
    db::{OpaqueToken, RefreshToken},
    error::ShlossResult,
    jwt::Claims,
};

/// Validates a given JWT.
/// Uses the `AppState` decoding_key to verify the claims and returns the user_id of contained in
/// the token
pub async fn validate_jwt(decoding_key: &DecodingKey, token: &str) -> ShlossResult<Option<Uuid>> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims = HashSet::new();

    let claims = decode::<Claims>(token, decoding_key, &validation)
        .map(|data| data.claims)
        .ok();
    Ok(claims.map(|c| c.sub))
}

/// Validates a given refresh token against the DB and returns the tokens internal id.
pub async fn validate_refresh_token(pool: &PgPool, raw: &str) -> ShlossResult<Option<Uuid>> {
    let hash = hash_secret(raw);
    let token = RefreshToken::find_valid_by_hash(pool, &hash).await?;
    Ok(token.map(|t| t.id))
}

/// Validates a given refresh token against the DB and returns the tokens user_id.
pub async fn validate_opaque_token(pool: &PgPool, raw: &str) -> ShlossResult<Option<Uuid>> {
    let hash = hash_secret(raw);
    let token = OpaqueToken::find_valid_by_hash(pool, &hash).await?;
    Ok(token.map(|t| t.user_id))
}
