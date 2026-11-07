//! DE: HTTP-Tests der API über `tower::ServiceExt::oneshot` (ohne Netzwerk):
//! Anmeldung, Eingabeprüfung, Limits, Sperre, Header, Zeitausgleich.
//! EN: HTTP tests of the API via `tower::ServiceExt::oneshot` (no network):
//! authentication, input validation, limits, lockout, headers, timing padding.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Extension;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use pqc_keyforge::api::{self, AppState, Limits, MAX_BODY_BYTES, TokenHash};
use serde_json::{Value, json};

const TOKEN: &str = "kf1_test-token-only-for-tests";

fn fast_limits() -> Limits {
    Limits {
        validate_min: Duration::from_millis(20),
        ..Limits::default()
    }
}

fn app_with(limits: Limits, ip: &str) -> Router {
    let state: Arc<AppState> = AppState::new(TokenHash::of(TOKEN), limits);
    let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
    api::router(state).layer(Extension(ConnectInfo(addr)))
}

fn app() -> Router {
    app_with(fast_limits(), "127.0.0.1")
}

fn validate_req(token: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::post("/v1/validate").header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    use tower::ServiceExt;
    let res = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (parts.status, parts.headers, value)
}

fn pass_body(pass: &str) -> String {
    json!({ "passphrase": pass }).to_string()
}

#[tokio::test]
async fn health_without_auth_and_with_security_headers() {
    let (status, headers, body) = send(
        &app(),
        Request::get("/v1/health").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "status": "ok" }));
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; frame-ancestors 'none'"
    );
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert!(headers.get(header::SERVER).is_none());
}

#[tokio::test]
async fn validate_requires_token() {
    let app = app();
    let body = pass_body("irrelevant");
    for token in [None, Some("kf1_wrong"), Some("")] {
        let (status, headers, value) = send(&app, validate_req(token, &body)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(value, json!({ "error": "unauthorized" }));
    }
    // DE: Anderes Schema als Bearer. EN: Scheme other than Bearer.
    let req = Request::post("/v1/validate")
        .header(header::AUTHORIZATION, format!("Basic {TOKEN}"))
        .body(Body::from(body))
        .unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn strong_passphrase_is_accepted() {
    let pass = common::random_passphrase();
    let body = pass_body(pass.as_ref().expose_str());
    let (status, _, value) = send(&app(), validate_req(Some(TOKEN), &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["strong"], json!(true));
    assert!(value["entropy_bits"].as_u64().unwrap() >= 80);
    assert_eq!(value["reasons"], json!([]));
}

#[tokio::test]
async fn weak_passphrase_lists_reasons_in_both_languages() {
    let app = app();
    let (status, _, de) = send(&app, validate_req(Some(TOKEN), &pass_body("passwort"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(de["strong"], json!(false));
    let codes: Vec<&str> = de["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"too_short"), "{codes:?}");
    assert!(
        de["reasons"][0]["message"]
            .as_str()
            .unwrap()
            .contains("zu kurz")
    );
    let en_body = json!({ "passphrase": "passwort", "lang": "en" }).to_string();
    let (_, _, en) = send(&app, validate_req(Some(TOKEN), &en_body)).await;
    assert!(
        en["reasons"][0]["message"]
            .as_str()
            .unwrap()
            .contains("too short")
    );
    // DE: Die Eingabe taucht in der Antwort nicht auf. EN: The input is not echoed.
    assert!(!de.to_string().contains("passwort"));
}

#[tokio::test]
async fn malformed_requests_get_generic_errors() {
    let app = app();
    let cases = [
        (r#"{"passphrase":"x","extra":1}"#, StatusCode::BAD_REQUEST),
        (r#"{"passphrase":"x","lang":"fr"}"#, StatusCode::BAD_REQUEST),
        (r#"{"pass":"x"}"#, StatusCode::BAD_REQUEST),
        (r#"{"passphrase":""}"#, StatusCode::BAD_REQUEST),
        ("not json", StatusCode::BAD_REQUEST),
    ];
    for (body, expected) in cases {
        let (status, _, value) = send(&app, validate_req(Some(TOKEN), body)).await;
        assert_eq!(status, expected, "{body}");
        assert_eq!(value, json!({ "error": "bad_request" }), "{body}");
    }
    let req = Request::post("/v1/validate")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(pass_body("x")))
        .unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let big = "a".repeat(MAX_BODY_BYTES + 1);
    let (status, _, value) = send(&app(), validate_req(Some(TOKEN), &pass_body(&big))).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(value, json!({ "error": "payload_too_large" }));
}

#[tokio::test]
async fn unknown_path_and_method_with_headers() {
    let app = app();
    let (status, headers, value) =
        send(&app, Request::get("/admin").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(value, json!({ "error": "not_found" }));
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    let req = Request::get("/v1/validate").body(Body::empty()).unwrap();
    let (status, _, value) = send(&app, req).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(value, json!({ "error": "method_not_allowed" }));
}

#[tokio::test]
async fn validate_is_padded_to_minimum_duration() {
    let limits = Limits {
        validate_min: Duration::from_millis(250),
        ..Limits::default()
    };
    let app = app_with(limits, "127.0.0.1");
    for body in [pass_body("kurz"), "kaputt".to_owned()] {
        let start = Instant::now();
        let _ = send(&app, validate_req(Some(TOKEN), &body)).await;
        assert!(start.elapsed() >= Duration::from_millis(250));
    }
}

#[tokio::test]
async fn rate_limit_per_client() {
    let limits = Limits {
        requests_per_window: 3,
        ..fast_limits()
    };
    let state = AppState::new(TokenHash::of(TOKEN), limits);
    let health = || Request::get("/v1/health").body(Body::empty()).unwrap();
    let a = api::router(state.clone()).layer(Extension(ConnectInfo(addr("10.0.0.1"))));
    let b = api::router(state).layer(Extension(ConnectInfo(addr("10.0.0.2"))));
    for _ in 0..3 {
        assert_eq!(send(&a, health()).await.0, StatusCode::OK);
    }
    let (status, _, value) = send(&a, health()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(value, json!({ "error": "too_many_requests" }));
    assert_eq!(send(&b, health()).await.0, StatusCode::OK);
}

fn addr(ip: &str) -> SocketAddr {
    format!("{ip}:1").parse().unwrap()
}

#[tokio::test]
async fn lockout_after_failed_tokens_even_with_correct_token() {
    let state = AppState::new(TokenHash::of(TOKEN), fast_limits());
    let a = api::router(state.clone()).layer(Extension(ConnectInfo(addr("10.0.0.1"))));
    let b = api::router(state).layer(Extension(ConnectInfo(addr("10.0.0.2"))));
    let body = pass_body("kurz");
    for _ in 0..5 {
        let status = send(&a, validate_req(Some("kf1_falsch"), &body)).await.0;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let status = send(&a, validate_req(Some(TOKEN), &body)).await.0;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // DE: Andere Clients sind nicht betroffen. EN: Other clients are not affected.
    assert_eq!(
        send(&b, validate_req(Some(TOKEN), &body)).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn successful_auth_resets_failures() {
    let app = app();
    let body = pass_body("kurz");
    for _ in 0..3 {
        let _ = send(&app, validate_req(Some("kf1_falsch"), &body)).await;
        assert_eq!(
            send(&app, validate_req(Some(TOKEN), &body)).await.0,
            StatusCode::OK
        );
    }
}
