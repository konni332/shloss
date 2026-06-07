use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::common::{TestApp, register_password_user};

// token validation
mod common;

#[tokio::test]
async fn validate_valid_opaque_token_returns_user_id() {
    let app = TestApp::new().await;
    let (token, user_id) = app
        .register_and_login_opaque("validateuser", "hunter2", 0)
        .await;
    let service_token = app.service_token(0).await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": token, "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["userId"].as_str().unwrap(), user_id);
}

#[tokio::test]
async fn validate_invalid_opaque_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": "totallyinvalidtoken", "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({"status": "invalid"}));
}

#[tokio::test]
async fn validate_expired_opaque_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    register_password_user(&app, "expireduser", "hunter2", 0).await;
    let login: Value = app
        .server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "expireduser", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2000-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok()
        .json();
    let expired_token = login["token"].as_str().unwrap();
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": expired_token, "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({"status": "invalid"}));
}

#[tokio::test]
async fn validate_revoked_opaque_token_returns_invalid() {
    let app = TestApp::new().await;
    let (token, _user_id) = app
        .register_and_login_opaque("revokeduser", "hunter2", 0)
        .await;
    let service_token = app.service_token(0).await;
    // revoke it directly in the DB
    sqlx::query!(
        "UPDATE opaque_tokens SET revoked_at = NOW() WHERE hash = $1",
        shloss::crypto::hash_secret(&token)
    )
    .execute(&app.pool)
    .await
    .unwrap();
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": token, "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({"status": "invalid"}));
}

#[tokio::test]
async fn validate_valid_jwt_returns_user_id() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let reg: Value = register_password_user(&app, "jwtvalidateuser", "hunter2", 0).await;
    let expected_user_id = reg["userId"].as_str().unwrap();
    let login: Value = app
        .server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "jwtvalidateuser", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "jwt", "claims": { "exp": 9999999999i64 } },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok()
        .json();
    let jwt = login["token"].as_str().unwrap();
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": jwt, "kind": "jwt" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["userId"].as_str().unwrap(), expected_user_id);
}

#[tokio::test]
async fn validate_invalid_jwt_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": "not.a.jwt", "kind": "jwt" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({"status": "invalid"}));
}

#[tokio::test]
async fn validate_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/tokens/validate")
        .json(&json!({ "token": "sometoken", "kind": "opaque" }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// token refresh

#[tokio::test]
async fn refresh_valid_token_returns_new_opaque_and_refresh() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("refreshuser", "hunter2", 0)
        .await;
    let res: Value = app
        .server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refreshToken": refresh,
            "tokenType": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["status"], "valid");
    assert!(res["newToken"].as_str().is_some());
    assert!(res["newRefresh"].as_str().is_some());
}

#[tokio::test]
async fn refresh_valid_token_returns_new_jwt_and_refresh() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("refreshjwtuser", "hunter2", 0)
        .await;
    let res: Value = app
        .server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refreshToken": refresh,
            "tokenType": { "kind": "jwt", "claims": { "exp": 9999999999i64 } }
        }))
        .await
        .assert_status_ok()
        .json();
    dbg!(&res);
    let new_token = res["newToken"].as_str().unwrap();
    assert_eq!(new_token.split('.').count(), 3, "expected a valid JWT");
    assert!(res["newRefresh"].as_str().is_some());
}

#[tokio::test]
async fn refresh_replay_attack_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("replayuser", "hunter2", 0)
        .await;
    // use the refresh token once
    app.server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refreshToken": refresh,
            "tokenType": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status_ok();
    // replay the same refresh token
    let res: Value = app
        .server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refreshToken": refresh,
            "tokenType": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({ "status": "invalid" }));
}

#[tokio::test]
async fn refresh_expired_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    register_password_user(&app, "expiredrefreshuser", "hunter2", 0).await;
    let login: Value = app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password",  "username": "expiredrefreshuser", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": "2000-01-01T00:00:00Z"
        }))
        .await
        .assert_status_ok()
        .json();
    let refresh = login["refreshToken"].as_str().unwrap();
    let res: Value = app
        .server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refreshToken": refresh,
            "tokenType": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({ "status": "invalid" }));
}

#[tokio::test]
async fn refresh_revoked_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("revokedrefreshuser", "hunter2", 0)
        .await;
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE hash = $1",
        shloss::crypto::hash_secret(&refresh)
    )
    .execute(&app.pool)
    .await
    .unwrap();
    let res: Value = app
        .server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refreshToken": refresh,
            "tokenType": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({ "status": "invalid" }));
}

#[tokio::test]
async fn refresh_invalid_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token(0).await;
    let res: Value = app
        .server
        .post("/v1/auth/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refreshToken": "totallyinvalidrefreshtoken",
            "tokenType": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!({ "status": "invalid" }));
}

#[tokio::test]
async fn refresh_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/auth/refresh")
        .json(&json!({
            "refreshToken": "sometoken",
            "tokenType": { "kind": "opaque", "expires_at": "2099-01-01T00:00:00Z" }
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
