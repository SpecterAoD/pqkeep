//! DE: HTTP-Tests für `POST /v1/generate`: Erfolg (mit Entsperren der gelieferten
//! Datei), schwache Passphrase (422), ungültige Eingaben, Anmeldung, Speicherbudget (503).
//! EN: HTTP tests for `POST /v1/generate`: success (unlocking the returned file),
//! weak passphrase (422), invalid input, authentication, memory budget (503).
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use axum::{Extension, Router};
use pqkeep::api::{self, AppState, Limits, TokenHash};
use pqkeep::envelope::{KeyFile, PublicKeyFile};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "pqk1_test-token-only-for-tests";

fn app(kdf_budget_mib: u32) -> Router {
    let limits = Limits {
        kdf_budget_mib,
        ..Limits::default()
    };
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    api::router(AppState::new(TokenHash::of(TOKEN), limits)).layer(Extension(ConnectInfo(addr)))
}

fn req(token: &str, body: &Value) -> Request<Body> {
    Request::post("/v1/generate")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (parts.status, parts.headers, value)
}

fn body(pass: &str, algorithm: &str) -> Value {
    json!({
        "passphrase": pass,
        "algorithm": algorithm,
        "metadata": { "name": "Test User", "department": "IT-Sicherheit" },
    })
}

#[tokio::test]
async fn generates_key_that_unlocks_with_the_passphrase() {
    let pass = common::random_passphrase();
    let text = pass.as_ref().expose_str();
    let (status, headers, value) = send(&app(1024), req(TOKEN, &body(text, "ml-kem-768"))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(value["algorithm"], json!("ML-KEM-768"));
    let key = KeyFile::from_json(&value["key_file"].to_string()).unwrap();
    assert_eq!(key.metadata().name, "Test User");
    assert!(key.unlock(pass.as_ref()).is_ok());
    let public = PublicKeyFile::from_json(&value["public_key_file"].to_string()).unwrap();
    assert_eq!(public.key_id_hex(), key.key_id_hex());
    assert_eq!(value["key_id"], json!(key.key_id_hex()));
    // DE: Die Passphrase taucht nirgends in der Antwort auf. EN: Passphrase never echoed.
    assert!(!value.to_string().contains(text));
}

#[tokio::test]
async fn aes_key_has_no_public_file() {
    let pass = common::random_passphrase();
    let b = body(pass.as_ref().expose_str(), "aes-256");
    let (status, _, value) = send(&app(1024), req(TOKEN, &b)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(value["algorithm"], json!("AES-256"));
    assert_eq!(value["public_key_file"], Value::Null);
}

#[tokio::test]
async fn weak_passphrase_is_422_with_reasons() {
    let mut b = body("passwort", "ml-dsa-65");
    b["lang"] = json!("en");
    let (status, _, value) = send(&app(1024), req(TOKEN, &b)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(value["error"], json!("weak_passphrase"));
    assert!(value.get("strong").is_none());
    assert!(
        value["reasons"][0]["message"]
            .as_str()
            .unwrap()
            .contains("too short")
    );
    // DE: Schwache Anfragen belegen kein Budget. EN: Weak requests take no budget.
    let (status, _, _) = send(&app(0), req(TOKEN, &body("passwort", "ml-kem-768"))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn invalid_requests_are_400() {
    let app = app(1024);
    let pass = common::random_passphrase();
    let p = pass.as_ref().expose_str();
    let mut unknown = body(p, "ml-kem-768");
    unknown["extra"] = json!(1);
    let mut unknown_meta = body(p, "ml-kem-768");
    unknown_meta["metadata"]["email"] = json!("a@b");
    let mut bad_profile = body(p, "ml-kem-768");
    bad_profile["profile"] = json!("turbo");
    let cases = [
        body(p, "ML-KEM-768"),
        body(p, "rsa-4096"),
        json!({ "passphrase": p, "metadata": { "name": "" } }),
        json!({ "passphrase": p, "metadata": { "name": "x".repeat(200) } }),
        json!({ "passphrase": p }),
        json!({ "passphrase": "", "metadata": { "name": "A" } }),
        unknown,
        unknown_meta,
        bad_profile,
    ];
    for case in cases {
        let (status, _, value) = send(&app, req(TOKEN, &case)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}");
        assert_eq!(value, json!({ "error": "bad_request" }));
    }
}

#[tokio::test]
async fn generate_requires_token() {
    let (status, _, _) = send(&app(1024), req("pqk1_falsch", &body("x", "aes-256"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn insufficient_budget_is_503_with_retry_after() {
    let pass = common::random_passphrase();
    let p = pass.as_ref().expose_str();
    let (status, headers, value) = send(&app(0), req(TOKEN, &body(p, "aes-256"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value, json!({ "error": "busy" }));
    assert_eq!(headers[header::RETRY_AFTER], "5");
    // DE: Hardened (1 GiB) passt nicht in 512 MiB. EN: Hardened (1 GiB) does not fit 512 MiB.
    let mut hardened = body(p, "aes-256");
    hardened["profile"] = json!("hardened");
    let (status, _, _) = send(&app(512), req(TOKEN, &hardened)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn budget_limits_parallel_runs_and_is_released() {
    let app = app(256);
    let pass = common::random_passphrase();
    let b = body(pass.as_ref().expose_str(), "aes-256");
    let (first, second) = tokio::join!(send(&app, req(TOKEN, &b)), send(&app, req(TOKEN, &b)));
    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::SERVICE_UNAVAILABLE]
    );
    let (status, _, _) = send(&app, req(TOKEN, &b)).await;
    assert_eq!(status, StatusCode::CREATED);
}
