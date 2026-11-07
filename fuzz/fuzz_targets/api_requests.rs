//! DE: REST-API mit beliebigen Bodies an `/v1/validate` und `/v1/generate`: nie Panik, nie 5xx
//!     außer 503 (Argon2-Budget ist hier 0, damit kein teures Argon2 läuft).
//! EN: REST API with arbitrary bodies to `/v1/validate` and `/v1/generate`: never panic, no 5xx
//!     except 503 (Argon2 budget is 0 here so no expensive Argon2 runs).
#![no_main]

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use axum::Extension;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use libfuzzer_sys::fuzz_target;
use pqkeep::api::{self, AppState, Limits, TokenHash};
use tower::ServiceExt;

const TOKEN: &str = "pqk1_fuzz";

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt")
    })
}

fuzz_target!(|input: (bool, Vec<u8>)| {
    let (generate, body) = input;
    let limits = Limits {
        validate_min: Duration::ZERO,
        kdf_budget_mib: 0,
        requests_per_window: u32::MAX,
        ..Limits::default()
    };
    let addr: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let app = api::router(AppState::new(TokenHash::of(TOKEN), limits))
        .layer(Extension(ConnectInfo(addr)));
    let path = if generate {
        "/v1/generate"
    } else {
        "/v1/validate"
    };
    let req = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::from(body))
        .expect("request");
    let status = runtime()
        .block_on(app.oneshot(req))
        .expect("infallible")
        .status();
    assert!(
        !status.is_server_error() || status == StatusCode::SERVICE_UNAVAILABLE,
        "unerwarteter Serverfehler / unexpected server error: {status}"
    );
});
