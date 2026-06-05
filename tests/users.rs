mod common;

use axum::http::StatusCode;
use common::TestApp;
use serde_json::{Value, json};
use uuid::Uuid;

// helpers

async fn register_and_get_user_id(app: &TestApp, username: &str, password: &str) -> String {
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post("/v1/auth/register")
        .add_header("Authorization", &service_token)
        .json(&json!({ "kind": "password", "username": username, "password": password }))
        .await
        .assert_status_ok()
        .json();
    res["userId"].as_str().unwrap().to_string()
}

async fn login_and_get_session_id(
    app: &TestApp,
    username: &str,
    password: &str,
) -> (String, String) {
    // returns (opaque_token, session_id)
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": username, "password": password },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok()
        .json();
    let token = res["token"].as_str().unwrap().to_string();
    // get session_id from DB directly
    let session_id = sqlx::query!(
        "SELECT s.id FROM sessions s 
         JOIN opaque_tokens ot ON ot.session_id = s.id 
         WHERE ot.hash = $1",
        shloss::crypto::hash_secret(&token)
    )
    .fetch_one(&app.pool)
    .await
    .unwrap()
    .id
    .to_string();
    (token, session_id)
}

async fn is_token_valid(app: &TestApp, token: &str) -> bool {
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post("/v1/tokens/validate")
        .add_header("Authorization", &service_token)
        .json(&json!({ "token": token, "kind": "opaque" }))
        .await
        .assert_status_ok()
        .json();
    res != json!({ "status": "invalid" })
}

// session revoke

#[tokio::test]
async fn revoke_session_returns_200() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "sessionrevokeuser", "hunter2").await;
    let (_, session_id) = login_and_get_session_id(&app, "sessionrevokeuser", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{user_id}/sessions/{}", session_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn revoke_session_invalidates_tokens() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "sessiontokenrevokeuser", "hunter2").await;
    let (token, session_id) =
        login_and_get_session_id(&app, "sessiontokenrevokeuser", "hunter2").await;
    assert!(is_token_valid(&app, &token).await);
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{user_id}/sessions/{}", session_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
    assert!(!is_token_valid(&app, &token).await);
}

#[tokio::test]
async fn revoke_nonexistent_session_returns_404() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!(
            "/v1/users/{}/sessions/{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        ))
        .add_header("Authorization", &service_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_session_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .delete(&format!(
            "/v1/users/{}/sessions/{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        ))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// delete user

#[tokio::test]
async fn delete_user_returns_200() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "deleteuser", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{}", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn delete_user_prevents_login() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "deleteloginuser", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{}", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "deleteloginuser", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refresh": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_user_invalidates_tokens() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "deletetokenuser", "hunter2").await;
    let (token, _) = login_and_get_session_id(&app, "deletetokenuser", "hunter2").await;
    assert!(is_token_valid(&app, &token).await);
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{}", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
    assert!(!is_token_valid(&app, &token).await);
}

#[tokio::test]
async fn delete_nonexistent_user_returns_404() {
    let app = TestApp::new().await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{}", Uuid::new_v4()))
        .add_header("Authorization", &service_token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_user_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .delete(&format!("/v1/users/{}", Uuid::new_v4()))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// list sessions

#[tokio::test]
async fn list_sessions_returns_all_sessions() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "listsessionuser", "hunter2").await;
    login_and_get_session_id(&app, "listsessionuser", "hunter2").await;
    login_and_get_session_id(&app, "listsessionuser", "hunter2").await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .get(&format!("/v1/users/{}/sessions", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn list_sessions_includes_revoked_sessions() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "listrevokedsession", "hunter2").await;
    let (_, session_id) = login_and_get_session_id(&app, "listrevokedsession", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{user_id}/sessions/{}", session_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
    let res: Value = app
        .server
        .get(&format!("/v1/users/{}/sessions", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res.as_array().unwrap().len(), 1);
    assert!(res[0]["revokedAt"].as_str().is_some());
}

#[tokio::test]
async fn list_sessions_empty_for_new_user() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "emptysessionuser", "hunter2").await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .get(&format!("/v1/users/{}/sessions", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok()
        .json();
    assert_eq!(res.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_sessions_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .get(&format!("/v1/users/{}/sessions", Uuid::new_v4()))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// change password

#[tokio::test]
async fn change_password_returns_200() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "changepassuser", "oldpass").await;
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/password", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "newPassword": "newpass" }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn change_password_old_password_no_longer_works() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "oldpassinvalid", "oldpass").await;
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/password", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "newPassword": "newpass" }))
        .await
        .assert_status_ok();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "oldpassinvalid", "password": "oldpass" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_new_password_works() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "newpassvalid", "oldpass").await;
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/password", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "newPassword": "newpass" }))
        .await
        .assert_status_ok();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "newpassvalid", "password": "newpass" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn change_password_nonexistent_user_returns_404() {
    let app = TestApp::new().await;
    let fake_id = Uuid::new_v4();
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/password", fake_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": fake_id, "newPassword": "newpass" }))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn change_password_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .post(&format!("/v1/users/{}/password", Uuid::new_v4()))
        .json(&json!({ "newPassword": "newpass" }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// change username

#[tokio::test]
async fn change_username_returns_200() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "changeusernameuser", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/username", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "newUsername": "newusername" }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn change_username_new_username_works_for_login() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "oldusername", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/username", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "newUsername": "brandnewusername" }))
        .await
        .assert_status_ok();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "brandnewusername", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn change_username_old_username_no_longer_works() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "oldusername2", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/username", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "newUsername": "newusername2" }))
        .await
        .assert_status_ok();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "oldusername2", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_username_duplicate_returns_conflict() {
    let app = TestApp::new().await;
    register_and_get_user_id(&app, "takenusername", "hunter2").await;
    let user_id = register_and_get_user_id(&app, "otherusernameuser", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .post(&format!("/v1/users/{}/username", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "newUsername": "takenusername" }))
        .await
        .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn change_username_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .post(&format!("/v1/users/{}/username", Uuid::new_v4()))
        .json(&json!({ "newUsername": "test" }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// api keys

#[tokio::test]
async fn add_api_key_returns_raw_key() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "apikeyuser", "hunter2").await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(
            &json!({ "userId": user_id, "name": "mykey", "keyPrefix": "prod", "expiresAt": null }),
        )
        .await
        .assert_status_ok()
        .json();
    let key = res["key"].as_str().unwrap();
    assert!(key.starts_with("prod_"));
}

#[tokio::test]
async fn add_api_key_is_usable_for_login() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "apikeyloginuser", "hunter2").await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(
            &json!({ "userId": user_id, "name": "mykey", "keyPrefix": "prod", "expiresAt": null }),
        )
        .await
        .assert_status_ok()
        .json();
    let key = res["key"].as_str().unwrap();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "apiKey", "fullKey": key },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn add_expired_api_key_cannot_login() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "expiredapikeyuser", "hunter2").await;
    let service_token = app.service_token().await;
    let res: Value = app.server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "name": "expiredkey", "keyPrefix": "test", "expiresAt": "2000-01-01T00:00:00Z" }))
        .await
        .assert_status_ok()
        .json();
    let key = res["key"].as_str().unwrap();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "apiKey", "fullKey": key },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn add_api_key_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .post(&format!("/v1/users/{}/api-key", Uuid::new_v4()))
        .json(&json!({ "name": "mykey", "keyPrefix": "prod", "expiresAt": null }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_api_key_prevents_login() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "revokeapikeyuser", "hunter2").await;
    let service_token = app.service_token().await;
    let res: Value = app
        .server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(
            &json!({ "userId": user_id, "name": "mykey", "keyPrefix": "prod", "expiresAt": null }),
        )
        .await
        .assert_status_ok()
        .json();
    let key = res["key"].as_str().unwrap();
    app.server
        .delete(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({"key": key }))
        .await
        .assert_status_ok();
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "apiKey", "fullKey": key },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_nonexistent_api_key_is_idempotent() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "idempotentrevoke", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "user_id": user_id, "key": "prod_nonexistentkey" }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn revoke_api_key_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .delete(&format!("/v1/users/{}/api-key", Uuid::new_v4()))
        .json(&json!({ "key": "somekey" }))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_all_api_keys_prevents_all_logins() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "revokeallkeys", "hunter2").await;
    let service_token = app.service_token().await;
    let key1: Value = app
        .server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "name": "key1", "keyPrefix": "k1", "expires_at": null }))
        .await
        .assert_status_ok()
        .json();
    let key2: Value = app
        .server
        .post(&format!("/v1/users/{}/api-key", user_id))
        .add_header("Authorization", &service_token)
        .json(&json!({ "userId": user_id, "name": "key2", "keyPrefix": "k2", "expiresAt": null }))
        .await
        .assert_status_ok()
        .json();
    let raw1 = key1["key"].as_str().unwrap();
    let raw2 = key2["key"].as_str().unwrap();
    app.server
        .delete(&format!("/v1/users/{}/api-key/all", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
    for key in [raw1, raw2] {
        app.server
            .post("/v1/auth/login")
            .add_header("Authorization", &service_token)
            .json(&json!({
                "credentials": { "kind": "apiKey", "fullKey": key },
                "ipAddress": null,
                "userAgent": null,
                "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
                "refreshExpiry": null
            }))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn revoke_all_api_keys_user_still_exists() {
    let app = TestApp::new().await;
    let user_id = register_and_get_user_id(&app, "revokeallkeysexists", "hunter2").await;
    let service_token = app.service_token().await;
    app.server
        .delete(&format!("/v1/users/{}/api-key/all", user_id))
        .add_header("Authorization", &service_token)
        .await
        .assert_status_ok();
    // password login still works
    app.server
        .post("/v1/auth/login")
        .add_header("Authorization", &service_token)
        .json(&json!({
            "credentials": { "kind": "password", "username": "revokeallkeysexists", "password": "hunter2" },
            "ipAddress": null,
            "userAgent": null,
            "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
            "refreshExpiry": null
        }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn revoke_all_api_keys_requires_service_auth() {
    let app = TestApp::new().await;
    app.server
        .delete(&format!("/v1/users/{}/api-key/all", Uuid::new_v4()))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
