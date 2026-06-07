use axum_test::TestServer;
use serde_json::{Value, json};
use shloss::{auth::ServiceKeyStore, build_router, jwt::Jwks, server::AppState};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tokio::sync::RwLock;

const TEST_SERVICE_KEY: &str = "shloss_testkey";

pub struct TestApp {
    pub server: TestServer,
    pub pool: PgPool,
    pub state: AppState,
}

pub async fn register_password_user(app: &TestApp, username: &str, password: &str) -> Value {
    let token = app.service_token().await;
    app.server
        .post("/v1/auth/register")
        .add_header("Authorization", &token)
        .json(&json!({
            "kind": "password", "username": username, "password": password
        }))
        .await
        .assert_status_ok()
        .json()
}

impl TestApp {
    pub async fn new() -> Self {
        let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
            &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER,
        );
        #[cfg(debug_assertions)]
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("shloss=debug")
                .try_init();
        }

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql:///shloss_test".to_string());

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("failed to connect to test DB");

        sqlx::migrate!()
            .run(&pool)
            .await
            .expect("failed to run migrations");
        let private_key_pem =
            std::env::var("SHLOSS_TEST_PRIVATE_KEY").expect("SHLOSS_TEST_PRIVATE_KEY not present");
        let encoding_key =
            Arc::new(jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap());
        let public_key_pem =
            std::env::var("SHLOSS_TEST_PUBLIC_KEY").expect("SHLOSS_TEST_PUBLIC_KEY not present");
        let decoding_key =
            Arc::new(jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).unwrap());
        let jwks = Arc::new(Jwks::from_private_pem(&private_key_pem).unwrap());

        let store = ServiceKeyStore::with_test_key(TEST_SERVICE_KEY);

        let state = AppState {
            pool: pool.clone(),
            store: Arc::new(RwLock::new(store)),
            encoding_key,
            decoding_key,
            jwks,
        };

        let router = build_router(state.clone());
        let server = TestServer::new(router);

        // clean slate
        sqlx::query!("TRUNCATE users CASCADE")
            .execute(&pool)
            .await
            .expect("failed to truncate");

        Self {
            server,
            pool,
            state,
        }
    }

    // logs in as the test service and returns the Bearer token
    pub async fn service_token(&self) -> String {
        let res = self
            .server
            .post("/v1/auth/service")
            .json(&json!({ "rawKey": TEST_SERVICE_KEY }))
            .await;
        res.assert_status_ok();
        let body: Value = res.json();
        format!("Bearer {}", body["token"].as_str().unwrap())
    }
    // returns (opaque_token, user_id)
    pub async fn register_and_login_opaque(
        &self,
        username: &str,
        password: &str,
    ) -> (String, String) {
        let reg: Value = register_password_user(self, username, password).await;
        let user_id = reg["userId"].as_str().unwrap().to_string();
        let service_token = self.service_token().await;
        let login: Value = self
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
        (login["token"].as_str().unwrap().to_string(), user_id)
    }

    // returns (opaque_token, refresh_token)
    pub async fn register_and_login_opaque_with_refresh(
        &self,
        username: &str,
        password: &str,
    ) -> (String, String) {
        register_password_user(self, username, password).await;
        let service_token = self.service_token().await;
        let login: Value = self
            .server
            .post("/v1/auth/login")
            .add_header("Authorization", &service_token)
            .json(&json!({
                "credentials": { "kind": "password", "username": username, "password": password },
                "ipAddress": null,
                "userAgent": null,
                "tokenKind": { "kind": "opaque", "expiresAt": "2099-01-01T00:00:00Z" },
                "refreshExpiry": "2099-06-01T00:00:00Z"
            }))
            .await
            .assert_status_ok()
            .json();
        (
            login["token"].as_str().unwrap().to_string(),
            login["refreshToken"].as_str().unwrap().to_string(),
        )
    }
}
