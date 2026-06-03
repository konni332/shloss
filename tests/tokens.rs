use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::common::{TestApp, register_password_user};

// token validation
mod common;

#[tokio::test]
async fn validate_valid_opaque_token_returns_user_id() {
    let app = TestApp::new().await;
    let (token, user_id) = app
        .register_and_login_opaque("validateuser", "hunter2")
        .await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": token, "kind": "Opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["Valid"].as_str().unwrap(), user_id);
}

#[tokio::test]
async fn validate_invalid_opaque_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": "totallyinvalidtoken", "kind": "Opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn validate_expired_opaque_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    register_password_user(&app, "expireduser", "hunter2").await;
    let login: Value = app
        .server
        .post("/v1/users/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "Password": { "username": "expireduser", "password": "hunter2" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2000-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .assert_status_ok()
        .json();
    let expired_token = login["token"].as_str().unwrap();
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": expired_token, "kind": "Opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn validate_revoked_opaque_token_returns_invalid() {
    let app = TestApp::new().await;
    let (token, _user_id) = app
        .register_and_login_opaque("revokeduser", "hunter2")
        .await;
    let service_token = app.service_token().await;
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
        .json(&json!({ "token": token, "kind": "Opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn validate_valid_jwt_returns_user_id() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let reg: Value = register_password_user(&app, "jwtvalidateuser", "hunter2").await;
    let expected_user_id = reg["Password"]["user_id"].as_str().unwrap();
    let login: Value = app
        .server
        .post("/v1/users/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "Password": { "username": "jwtvalidateuser", "password": "hunter2" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Jwt": { "claims": { "exp": 9999999999i64 } } },
            "refresh": null
        }))
        .await
        .assert_status_ok()
        .json();
    let jwt = login["token"].as_str().unwrap();
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": jwt, "kind": "Jwt" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res["Valid"].as_str().unwrap(), expected_user_id);
}

#[tokio::test]
async fn validate_invalid_jwt_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": "not.a.jwt", "kind": "Jwt" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn validate_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/tokens/validate")
        .json(&json!({ "token": "sometoken", "kind": "Opaque" }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// token refresh

#[tokio::test]
async fn refresh_valid_token_returns_new_opaque_and_refresh() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("refreshuser", "hunter2")
        .await;
    let res: Value = app
        .server
        .post("/v1/tokens/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refresh_token": refresh,
            "token_type": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } }
        }))
        .await
        .assert_status_ok()
        .json();
    assert!(res["Valid"]["new_token"].as_str().is_some());
    assert!(res["Valid"]["new_refresh"].as_str().is_some());
}

#[tokio::test]
async fn refresh_valid_token_returns_new_jwt_and_refresh() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("refreshjwtuser", "hunter2")
        .await;
    let res: Value = app
        .server
        .post("/v1/tokens/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refresh_token": refresh,
            "token_type": { "Jwt": { "claims": { "exp": 9999999999i64 } } }
        }))
        .await
        .assert_status_ok()
        .json();
    dbg!(&res);
    let new_token = res["Valid"]["new_token"].as_str().unwrap();
    assert_eq!(new_token.split('.').count(), 3, "expected a valid JWT");
    assert!(res["Valid"]["new_refresh"].as_str().is_some());
}

#[tokio::test]
async fn refresh_replay_attack_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("replayuser", "hunter2")
        .await;
    // use the refresh token once
    app.server
        .post("/v1/tokens/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refresh_token": refresh,
            "token_type": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } }
        }))
        .await
        .assert_status_ok();
    // replay the same refresh token
    let res: Value = app
        .server
        .post("/v1/tokens/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refresh_token": refresh,
            "token_type": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn refresh_expired_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    register_password_user(&app, "expiredrefreshuser", "hunter2").await;
    let login: Value = app.server
        .post("/v1/users/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "Password": { "username": "expiredrefreshuser", "password": "hunter2" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": "2000-01-01T00:00:00Z"
        }))
        .await
        .assert_status_ok()
        .json();
    let refresh = login["refresh"].as_str().unwrap();
    let res: Value = app
        .server
        .post("/v1/tokens/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refresh_token": refresh,
            "token_type": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn refresh_revoked_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let (_, refresh) = app
        .register_and_login_opaque_with_refresh("revokedrefreshuser", "hunter2")
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
        .post("/v1/tokens/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refresh_token": refresh,
            "token_type": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn refresh_invalid_token_returns_invalid() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post("/v1/tokens/refresh")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "refresh_token": "totallyinvalidrefreshtoken",
            "token_type": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } }
        }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn refresh_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/tokens/refresh")
        .json(&json!({
            "refresh_token": "sometoken",
            "token_type": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } }
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
