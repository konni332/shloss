// tests/vaults.rs
mod common;

use axum::http::StatusCode;
use common::{TestApp, register_password_user};
use serde_json::{Value, json};
use uuid::Uuid;

// username uniqueness is per-vault

#[tokio::test]
async fn same_username_can_exist_in_different_vaults() {
    let app = TestApp::new().await;
    // register "alice" in vault 0
    register_password_user(&app, "alice", "hunter2", 0).await;
    // register "alice" in vault 1 — should succeed, not conflict
    let res = register_password_user(&app, "alice", "hunter2", 1).await;
    assert!(res["userId"].as_str().is_some());
}

#[tokio::test]
async fn username_conflict_is_within_vault_only() {
    let app = TestApp::new().await;
    register_password_user(&app, "bob", "hunter2", 0).await;
    // duplicate in same vault — conflict
    let token = app.service_token(0).await;
    app.server
        .post("/v1/auth/register")
        .add_header("Authorization", &token)
        .json(&json!({ "kind": "password", "username": "bob", "password": "hunter2" }))
        .await
        .assert_status(StatusCode::CONFLICT);
    // same username in other vault — ok
    let token2 = app.service_token(1).await;
    app.server
        .post("/v1/auth/register")
        .add_header("Authorization", &token2)
        .json(&json!({ "kind": "password", "username": "bob", "password": "hunter2" }))
        .await
        .assert_status_ok();
}

// cross-vault login

#[tokio::test]
async fn service_cannot_login_user_from_another_vault() {
    let app = TestApp::new().await;
    register_password_user(&app, "vaultuser", "hunter2", 0).await;
    // vault 1 tries to login vault 0's user
    let token = app.service_token(1).await;
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "vaultuser", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn same_username_different_vaults_login_independently() {
    let app = TestApp::new().await;
    register_password_user(&app, "shared", "pass_vault0", 0).await;
    register_password_user(&app, "shared", "pass_vault1", 1).await;
    // vault 0 cannot login with vault 1's password
    let token0 = app.service_token(0).await;
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token0)
        .json(&json!({
            "credentials": { "kind": "password", "username": "shared", "password": "pass_vault1" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // vault 1 cannot login with vault 0's password
    let token1 = app.service_token(1).await;
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token1)
        .json(&json!({
            "credentials": { "kind": "password", "username": "shared", "password": "pass_vault0" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// cross-vault token validation

#[tokio::test]
async fn opaque_token_from_vault_a_is_invalid_in_vault_b() {
    let app = TestApp::new().await;
    let (token, _) = app
        .register_and_login_opaque("tokenuser", "hunter2", 0)
        .await;
    // vault 1 tries to validate vault 0's token
    let service_token1 = app.service_token(1).await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token1)
        .json(&json!({ "token": token, "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["status"].as_str().unwrap(), "invalid");
}

#[tokio::test]
async fn refresh_token_from_vault_a_cannot_be_rotated_by_vault_b() {
    let app = TestApp::new().await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("refreshvaultuser", "hunter2", 0)
        .await;
    // vault 1 tries to rotate vault 0's refresh token
    let service_token1 = app.service_token(1).await;
    let res: Value = app
        .server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token1)
        .json(&json!({
            "refreshToken": refresh,
            "tokenType": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["status"].as_str().unwrap(), "invalid");
}

// cross-vault user management

#[tokio::test]
async fn service_cannot_delete_user_from_another_vault() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "deletevaultuser", "hunter2", 0).await;
    let user_id = reg["userId"].as_str().unwrap();
    // vault 1 tries to delete vault 0's user
    let token1 = app.service_token(1).await;
    app.server
        .delete(&format!("/v1/users/{}", user_id))
        .add_header("Authorization", &token1)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    // vault 0's user still exists and can login
    let token0 = app.service_token(0).await;
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token0)
        .json(&json!({
            "credentials": { "kind": "password", "username": "deletevaultuser", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn service_cannot_change_password_for_user_in_another_vault() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "passchangevault", "original", 0).await;
    let user_id = reg["userId"].as_str().unwrap();
    let token1 = app.service_token(1).await;
    app.server
        .post(&format!("/v1/users/{}/password", user_id))
        .add_header("Authorization", &token1)
        .json(&json!({ "newPassword": "hacked" }))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    // original password still works
    let token0 = app.service_token(0).await;
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token0)
        .json(&json!({
            "credentials": { "kind": "password", "username": "passchangevault", "password": "original" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn service_cannot_change_username_for_user_in_another_vault() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "usernamechangevault", "hunter2", 0).await;
    let user_id = reg["userId"].as_str().unwrap();
    let token1 = app.service_token(1).await;
    app.server
        .post(&format!("/v1/users/{}/username", user_id))
        .add_header("Authorization", &token1)
        .json(&json!({ "newUsername": "hacked" }))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    // original username still works
    let token0 = app.service_token(0).await;
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token0)
        .json(&json!({
            "credentials": { "kind": "password", "username": "usernamechangevault", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn service_cannot_add_api_key_to_user_in_another_vault() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "apikeyvaultuser", "hunter2", 0).await;
    let user_id = reg["userId"].as_str().unwrap();
    let token1 = app.service_token(1).await;
    app.server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &token1)
        .json(&json!({ "name": "hacked", "keyPrefix": "hack", "expiresAt": null }))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn service_cannot_revoke_api_key_for_user_in_another_vault() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "apikeyrevokeuser", "hunter2", 0).await;
    let user_id = reg["userId"].as_str().unwrap();
    // add a key in vault 0
    let token0 = app.service_token(0).await;
    let key_res: Value = app
        .server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &token0)
        .json(&json!({ "name": "mykey", "keyPrefix": "prod", "expiresAt": null }))
        .await
        .assert_status_ok()
        .json();
    let raw_key = key_res["key"].as_str().unwrap();
    // vault 1 tries to revoke it — idempotent 200 but key should still work
    let token1 = app.service_token(1).await;
    app.server
        .delete(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &token1)
        .json(&json!({ "key": raw_key }))
        .await
        .assert_status_ok(); // idempotent, no leak
    // key still works in vault 0
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token0)
        .json(&json!({
            "credentials": { "kind": "apiKey", "fullKey": raw_key },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn service_cannot_revoke_all_api_keys_for_user_in_another_vault() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "revokeallvaultuser", "hunter2", 0).await;
    let user_id = reg["userId"].as_str().unwrap();
    let token0 = app.service_token(0).await;
    let key_res: Value = app
        .server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &token0)
        .json(&json!({ "name": "mykey", "keyPrefix": "prod", "expiresAt": null }))
        .await
        .assert_status_ok()
        .json();
    let raw_key = key_res["key"].as_str().unwrap();
    // vault 1 tries to revoke all keys
    let token1 = app.service_token(1).await;
    app.server
        .delete(&format!("/v1/users/{}/api-key/all", user_id))
        .add_header("Authorization", &token1)
        .await
        .assert_status_ok();
    // key still works in vault 0
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token0)
        .json(&json!({
            "credentials": { "kind": "apiKey", "fullKey": raw_key },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

// cross-vault session management

#[tokio::test]
async fn service_cannot_list_sessions_for_user_in_another_vault() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "sessionlistvault", "hunter2", 0).await;
    let user_id = reg["userId"].as_str().unwrap();
    // login to create a session in vault 0
    let token0 = app.service_token(0).await;
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &token0)
        .json(&json!({
            "credentials": { "kind": "password", "username": "sessionlistvault", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
    // vault 1 tries to list sessions
    let token1 = app.service_token(1).await;
    let res: Value = app
        .server
        .get(&format!("/v1/users/{}/sessions", user_id))
        .add_header("Authorization", &token1)
        .await
        .assert_status_ok()
        .json();
    // returns empty array, not vault 0's sessions
    assert_eq!(res.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn service_cannot_revoke_session_for_user_in_another_vault() {
    let app = TestApp::new().await;
    let (token, _) = app
        .register_and_login_opaque("sessionrevokevault", "hunter2", 0)
        .await;
    // get session_id from DB
    let session_id = sqlx::query_scalar!(
        "SELECT s.id FROM sessions s
         JOIN opaque_tokens ot ON ot.session_id = s.id
         WHERE ot.hash = $1",
        shloss::crypto::hash_secret(&token)
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    // vault 1 tries to revoke vault 0's session
    let token1 = app.service_token(1).await;
    app.server
        .delete(&format!(
            "/v1/users/{}/sessions/{}",
            Uuid::new_v4(),
            session_id
        ))
        .add_header("Authorization", &token1)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    // token still valid in vault 0
    let token0 = app.service_token(0).await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &token0)
        .json(&json!({ "token": token, "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["status"].as_str().unwrap(), "valid");
}

#[tokio::test]
async fn service_cannot_revoke_all_sessions_for_user_in_another_vault() {
    let app = TestApp::new().await;
    let (token, user_id) = app
        .register_and_login_opaque("revokeallsessionvault", "hunter2", 0)
        .await;
    // vault 1 tries to revoke all sessions
    let token1 = app.service_token(1).await;
    app.server
        .delete(&format!("/v1/users/{}/sessions", user_id))
        .add_header("Authorization", &token1)
        .await
        .assert_status_ok();
    // token still valid in vault 0
    let token0 = app.service_token(0).await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &token0)
        .json(&json!({ "token": token, "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["status"].as_str().unwrap(), "valid");
}

// cross-vault user_id guessing

#[tokio::test]
async fn random_uuid_returns_not_found_or_empty_not_another_vaults_data() {
    let app = TestApp::new().await;
    register_password_user(&app, "randomunknownuser", "hunter2", 0).await;
    let token1 = app.service_token(1).await;
    // vault 1 queries a random UUID — should never return vault 0 data
    let fake_id = Uuid::new_v4();
    app.server
        .delete(&format!("/v1/users/{}", fake_id))
        .add_header("Authorization", &token1)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    let res: Value = app
        .server
        .get(&format!("/v1/users/{}/sessions", fake_id))
        .add_header("Authorization", &token1)
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res.as_array().unwrap().len(), 0);
}
