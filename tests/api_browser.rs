//! DE: Schutz der lokalen API vor Webseiten (#253): Anfragen ohne Token zählen nicht zur
//! Sperre, Browser-Anfragen (`Origin`, `Sec-Fetch-Site`) und fremde `Host`-Werte werden mit
//! 403 abgewiesen, falsche Tokens sperren weiterhin.
//! EN: Protection of the local API against web pages (#253): requests without a token do not
//! count towards the lockout, browser requests (`Origin`, `Sec-Fetch-Site`) and foreign `Host`
//! values are rejected with 403, wrong tokens still lock out.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use pqkeep::api::{self, AppState, Limits, TokenHash};
use tower::ServiceExt;

const TOKEN: &str = "pqk1_test-token-only-for-tests";

fn app(hosts: Option<Vec<String>>) -> Router {
    let limits = Limits {
        validate_min: Duration::from_millis(5),
        allowed_hosts: hosts,
        ..Limits::default()
    };
    let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    api::router(AppState::new(TokenHash::of(TOKEN), limits)).layer(Extension(ConnectInfo(addr)))
}

fn validate(token: Option<&str>, extra: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::post("/v1/validate").header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    b.body(Body::from(r#"{"passphrase":"kurz"}"#)).unwrap()
}

async fn status(app: &Router, req: Request<Body>) -> StatusCode {
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn requests_without_token_do_not_lock_out() {
    let app = app(None);
    for _ in 0..10 {
        assert_eq!(
            status(&app, validate(None, &[])).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        status(&app, validate(Some(TOKEN), &[])).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn browser_requests_are_rejected_and_not_counted() {
    let app = app(None);
    let browser: [&[(&str, &str)]; 2] = [
        &[("origin", "https://evil.example")],
        &[("sec-fetch-site", "cross-site")],
    ];
    for headers in browser {
        for token in [None, Some("pqk1_falsch"), Some(TOKEN)] {
            assert_eq!(
                status(&app, validate(token, headers)).await,
                StatusCode::FORBIDDEN
            );
        }
    }
    // DE: Auch 12 Browser-Anfragen mit falschem Token sperren nicht. EN: No lockout either.
    assert_eq!(
        status(&app, validate(Some(TOKEN), &[])).await,
        StatusCode::OK
    );
    let health = Request::get("/v1/health").header("origin", "https://evil.example");
    assert_eq!(
        status(&app, health.body(Body::empty()).unwrap()).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn foreign_host_is_rejected_when_hosts_are_restricted() {
    let app = app(Some(Limits::loopback_hosts(8787)));
    let host = |h: &str| validate(Some(TOKEN), &[("host", h)]);
    for ok in [
        "127.0.0.1:8787",
        "localhost:8787",
        "LOCALHOST:8787",
        "[::1]:8787",
    ] {
        assert_eq!(status(&app, host(ok)).await, StatusCode::OK, "{ok}");
    }
    for bad in [
        "attacker.example:8787",
        "127.0.0.1:9999",
        "localhost",
        "127.0.0.1.evil:8787",
    ] {
        assert_eq!(
            status(&app, host(bad)).await,
            StatusCode::FORBIDDEN,
            "{bad}"
        );
    }
    // DE: Ohne Host-Header (z. B. HTTP/1.0) angenommen. EN: Accepted without a Host header.
    assert_eq!(
        status(&app, validate(Some(TOKEN), &[])).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn wrong_tokens_still_lock_out() {
    let app = app(None);
    for _ in 0..5 {
        let s = status(&app, validate(Some("pqk1_falsch"), &[])).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        status(&app, validate(Some(TOKEN), &[])).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}
