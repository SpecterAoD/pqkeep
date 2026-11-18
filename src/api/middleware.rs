//! DE: Schutzschichten: Browser-Sperre und `Host`-Prüfung (alle Routen), Rate-Limit (alle
//! Routen), Token-Prüfung mit Sperre (geschützte Routen) und Sicherheits-Header (alle Antworten).
//! Hinter einem Reverse Proxy sehen alle Anfragen wie eine Adresse aus; Header wie
//! `X-Forwarded-For` werden bewusst nicht ausgewertet (fälschbar).
//!
//! EN: Protection layers: browser block and `Host` check (all routes), rate limit (all
//! routes), token check with lockout (protected routes) and security headers (all responses).
//! Behind a reverse proxy all requests look like one address; headers such as
//! `X-Forwarded-For` are deliberately ignored (spoofable).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::AppState;
use super::handlers::ApiError;

/// DE: Client-Adresse aus der Verbindung; fehlt sie, gilt eine gemeinsame Adresse.
/// EN: Client address from the connection; if missing, a shared address applies.
fn client_ip(req: &Request) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip())
}

/// DE: Browser-Anfragen (`Origin` oder `Sec-Fetch-Site`) und fremde `Host`-Werte abweisen
/// (#253): Eine Webseite soll die lokale API weder erreichen noch Fehlversuche auslösen können.
/// EN: Reject browser requests (`Origin` or `Sec-Fetch-Site`) and foreign `Host` values
/// (#253): a web page must neither reach the local API nor trigger failed attempts.
pub async fn browser_guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    if headers.contains_key(header::ORIGIN) || headers.contains_key("sec-fetch-site") {
        return ApiError::Forbidden.into_response();
    }
    if let (Some(allowed), Some(host)) = (&state.limits().allowed_hosts, headers.get(header::HOST))
    {
        let host = host.to_str().unwrap_or_default();
        if !allowed.iter().any(|a| a.eq_ignore_ascii_case(host)) {
            return ApiError::Forbidden.into_response();
        }
    }
    next.run(req).await
}

/// DE: Rate-Limit je Client. EN: Rate limit per client.
pub async fn rate_limit(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if !state.guard.allow_request(client_ip(&req)) {
        return ApiError::TooManyRequests.into_response();
    }
    next.run(req).await
}

/// DE: Bearer-Token prüfen; gesperrte Clients erhalten 429 ohne Prüfung.
/// EN: Check bearer token; locked-out clients get 429 without a check.
pub async fn auth(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let ip = client_ip(&req);
    if state.guard.is_locked(ip) {
        return ApiError::TooManyRequests.into_response();
    }
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(token) if state.token.verify(token) => {
            state.guard.record_success(ip);
            next.run(req).await
        }
        // DE: Ohne Token kein Rateversuch – nicht zählen (#253). EN: No token, no guess – not counted.
        None => ApiError::Unauthorized.into_response(),
        Some(_) => {
            state.guard.record_failure(ip);
            ApiError::Unauthorized.into_response()
        }
    }
}

/// DE: Sicherheits-Header für jede Antwort. EN: Security headers for every response.
pub async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    let fixed = [
        (header::CACHE_CONTROL, "no-store"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
    ];
    for (name, value) in fixed {
        h.insert(name, HeaderValue::from_static(value));
    }
    res
}
