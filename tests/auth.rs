mod common;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use common::TestApp;
use serde_json::{Value, json};
use shloss::hash_secret;

use crate::common::register_password_user;

async fn login_opaque(app: &TestApp, username: &str, password: &str, expires_at: &str) -> Value {
    let token = app.service_token().await;
    app.server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": username, "password": password } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": expires_at } },
            "refresh": null
        }))
        .await
        .assert_status_ok()
        .json()
}

// service login

#[tokio::test]
async fn service_login_valid_key_returns_token() {
    let app = TestApp::new().await;
    let res = app
        .server
        .post("/v1/services/login")
        .json(&json!({ "raw_key": "shloss_testkey" }))
        .await;
    res.assert_status_ok();
    let body: Value = res.json();
    assert!(
        body["token"].as_str().is_some(),
        "expected token in response"
    );
}

#[tokio::test]
async fn service_login_invalid_key_returns_401() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/services/login")
        .json(&json!({ "raw_key": "shloss_wrongkey" }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn service_login_malformed_body_returns_422() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/services/login")
        .json(&json!({ "wrong_field": "shloss_testkey" }))
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn service_token_is_usable_for_protected_routes() {
    let app = TestApp::new().await;
    let token = app.service_token().await;
    app.server
        .post("/v1/users/register")
        .add_header("Authorization", &token)
        .json(&json!({ "Password": { "username": "tokentest", "password": "hunter2" } }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn expired_service_token_returns_401() {
    let app = TestApp::new().await;
    // manually insert an expired service token into the store
    {
        let mut store = app.state.store.write().await;
        let expired_token = shloss::GeneratedToken {
            raw: "expiredtoken".to_string(),
            hash: hash_secret("expiredtoken"),
        };
        store.service_tokens.push(shloss::auth::ServiceToken {
            hash: expired_token.hash,
            created_at: Utc::now() - Duration::days(2),
            expires_at: Utc::now() - Duration::days(1),
        });
    }
    app.server
        .post("/v1/users/register")
        .add_header("Authorization", "Bearer expiredtoken")
        .json(&json!({ "Password": { "username": "test", "password": "test" } }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// user registration

#[tokio::test]
async fn register_password_user_returns_user_id() {
    let app = TestApp::new().await;
    let body = register_password_user(&app, "newuser", "hunter2").await;
    assert!(body["Password"]["user_id"].as_str().is_some());
}

#[tokio::test]
async fn register_api_key_user_returns_user_id_and_key() {
    let app = TestApp::new().await;
    let token = app.service_token().await;
    let res = app
        .server
        .post("/v1/users/register")
        .add_header("Authorization", &token)
        .json(&json!({
            "ApiKey": {
                "name": "mykey",
                "key_prefix": "prod",
                "expires_at": null
            }
        }))
        .await;
    res.assert_status_ok();
    let body: Value = res.json();
    assert!(body["ApiKey"]["user_id"].as_str().is_some());
    assert!(body["ApiKey"]["raw_key"].as_str().is_some());
    let raw_key = body["ApiKey"]["raw_key"].as_str().unwrap();
    assert!(raw_key.starts_with("prod_"), "key should start with prefix");
}

#[tokio::test]
async fn register_duplicate_username_returns_conflict() {
    let app = TestApp::new().await;
    register_password_user(&app, "dupeuser", "hunter2").await;
    let token = app.service_token().await;
    app.server
        .post("/v1/users/register")
        .add_header("Authorization", &token)
        .json(&json!({ "Password": { "username": "dupeuser", "password": "different" } }))
        .await
        .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_without_service_token_returns_401() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/users/register")
        .json(&json!({ "Password": { "username": "test", "password": "hunter2" } }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_with_invalid_service_token_returns_401() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/users/register")
        .add_header("Authorization", "Bearer invalidtoken")
        .json(&json!({ "Password": { "username": "test", "password": "hunter2" } }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_malformed_body_returns_422() {
    let app = TestApp::new().await;
    let token = app.service_token().await;
    app.server
        .post("/v1/users/register")
        .add_header("Authorization", &token)
        .json(&json!({ "wrong": "shape" }))
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

// user login

#[tokio::test]
async fn login_valid_password_returns_opaque_token_and_user_id() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "loginuser", "hunter2").await;
    let expected_user_id = reg["Password"]["user_id"].as_str().unwrap();
    let body = login_opaque(&app, "loginuser", "hunter2", "2099-01-01T00:00:00Z").await;
    assert!(body["token"].as_str().is_some());
    assert_eq!(body["user_id"].as_str().unwrap(), expected_user_id);
}

#[tokio::test]
async fn login_valid_password_returns_jwt_and_user_id() {
    let app = TestApp::new().await;
    let reg: Value = register_password_user(&app, "jwtuser", "hunter2").await;
    let expected_user_id = reg["Password"]["user_id"].as_str().unwrap();
    let token = app.service_token().await;
    let res = app
        .server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": "jwtuser", "password": "hunter2" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Jwt": { "claims": { "exp": 9999999999i64 } } },
            "refresh": null
        }))
        .await;
    res.assert_status_ok();
    let body: Value = res.json();
    assert!(body["token"].as_str().is_some());
    assert_eq!(body["user_id"].as_str().unwrap(), expected_user_id);
    // JWT should have 3 dot-separated parts
    let jwt = body["token"].as_str().unwrap();
    assert_eq!(jwt.split('.').count(), 3, "expected a valid JWT");
}

#[tokio::test]
async fn login_with_refresh_token_requested() {
    let app = TestApp::new().await;
    register_password_user(&app, "refreshuser", "hunter2").await;
    let token = app.service_token().await;
    let res = app
        .server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": "refreshuser", "password": "hunter2" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": "2099-06-01T00:00:00Z"
        }))
        .await;
    res.assert_status_ok();
    let body: Value = res.json();
    assert!(body["token"].as_str().is_some());
    assert!(body["refresh"].as_str().is_some());
}

#[tokio::test]
async fn login_wrong_password_returns_401() {
    let app = TestApp::new().await;
    register_password_user(&app, "wrongpassuser", "correct").await;
    let token = app.service_token().await;
    app.server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": "wrongpassuser", "password": "wrong" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_nonexistent_user_returns_401() {
    let app = TestApp::new().await;
    let token = app.service_token().await;
    app.server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": "doesnotexist", "password": "hunter2" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_nonexistent_and_wrong_password_return_same_status() {
    // ensure we dont leak whether a username exists
    let app = TestApp::new().await;
    register_password_user(&app, "existinguser", "correct").await;
    let token = app.service_token().await;
    let wrong_pass = app
        .server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": "existinguser", "password": "wrong" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .status_code();
    let no_user = app
        .server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": "nosuchuser", "password": "wrong" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .status_code();
    assert_eq!(
        wrong_pass, no_user,
        "should not leak whether username exists"
    );
}

#[tokio::test]
async fn login_with_api_key_credential() {
    let app = TestApp::new().await;
    let token = app.service_token().await;
    let reg: Value = app
        .server
        .post("/v1/users/register")
        .add_header("Authorization", &token)
        .json(&json!({
            "ApiKey": { "name": "mykey", "key_prefix": "test", "expires_at": null }
        }))
        .await
        .assert_status_ok()
        .json();
    let raw_key = reg["ApiKey"]["raw_key"].as_str().unwrap();
    app.server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "ApiKey": { "full_key": raw_key } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn login_with_invalid_api_key_returns_401() {
    let app = TestApp::new().await;
    let token = app.service_token().await;
    app.server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "ApiKey": { "full_key": "test_totallyinvalidkey" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_with_expired_opaque_token_request() {
    // token with expiry in the past should be written but immediately invalid
    let app = TestApp::new().await;
    register_password_user(&app, "expiredtokenuser", "hunter2").await;
    let token = app.service_token().await;
    let login: Value = app.server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({
            "credentials": { "Password": { "username": "expiredtokenuser", "password": "hunter2" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2000-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .assert_status_ok()
        .json();
    let opaque = login["token"].as_str().unwrap();
    // validate should return Invalid
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &token)
        .json(&json!({ "token": opaque, "kind": "Opaque" }))
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res, json!("Invalid"));
}

#[tokio::test]
async fn login_without_service_token_returns_401() {
    let app = TestApp::new().await;
    app.server
        .post("/v1/users/login")
        .json(&json!({
            "credentials": { "Password": { "username": "test", "password": "test" } },
            "ip_address": null,
            "user_agent": null,
            "token_kind": { "Opaque": { "expires_at": "2099-01-01T00:00:00Z" } },
            "refresh": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_malformed_body_returns_422() {
    let app = TestApp::new().await;
    let token = app.service_token().await;
    app.server
        .post("/v1/users/login")
        .add_header("Authorization", &token)
        .json(&json!({ "wrong": "shape" }))
        .await
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}
