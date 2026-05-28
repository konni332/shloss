use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand_core::OsRng;
use uuid::Uuid;

use crate::error::CryptoError;

pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| CryptoError::PasswordHashError)?
        .to_string();

    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|_| CryptoError::PasswordVerifyError)?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn generate_uuid() -> Uuid {
    Uuid::new_v4()
}
