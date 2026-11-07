//! DE: REST-API (Feature `api`, Standard an). Endpunkte: `GET /v1/health` (ohne
//! Anmeldung), `POST /v1/validate` und `POST /v1/generate` (Token); siehe `docs/API.md`.
//! Härtung: Bind standardmäßig nur auf 127.0.0.1 (Prüfung in der CLI), Token nur als
//! Hash gespeichert, Rate-Limit und Sperre je Client, Größen- und Zeitlimits,
//! Speicherbudget für Argon2, generische Fehler, keine Inhalts-Logs,
//! Sicherheits-Header, kein CORS. TLS ist nicht eingebaut (Reverse Proxy).
//!
//! EN: REST API (feature `api`, on by default). Endpoints: `GET /v1/health` (no
//! authentication), `POST /v1/validate` and `POST /v1/generate` (token); see `docs/API.md`.
//! Hardening: bind to 127.0.0.1 only by default (checked in the CLI), token stored as
//! hash only, per-client rate limit and lockout, size and time limits, memory budget
//! for Argon2, generic errors, no content logs, security headers, no CORS. TLS is not
//! built in (reverse proxy).

mod generate;
mod guard;
mod handlers;
mod middleware;
mod server;
pub mod token;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tokio::sync::Semaphore;

pub use guard::{Guard, MAX_TRACKED_CLIENTS, client_key};
pub use server::serve;
pub use token::TokenHash;

/// DE: Höchstgröße eines Request-Bodys. EN: Maximum size of a request body.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// DE: Grenzwerte der API. Standardwerte siehe [`Limits::default`].
/// EN: API limits. Defaults see [`Limits::default`].
#[derive(Debug, Clone)]
pub struct Limits {
    /// DE: Anfragen je Client und Zeitfenster (60). EN: Requests per client and window (60).
    pub requests_per_window: u32,
    /// DE: Länge des Zeitfensters (60 s). EN: Length of the window (60 s).
    pub rate_window: Duration,
    /// DE: Falsche Tokens bis zur Sperre (5). EN: Wrong tokens until lockout (5).
    pub max_failed_tokens: u32,
    /// DE: Dauer der Sperre (15 min). EN: Lockout duration (15 min).
    pub lockout: Duration,
    /// DE: Mindestdauer jeder `/v1/validate`-Antwort (300 ms).
    /// EN: Minimum duration of every `/v1/validate` response (300 ms).
    pub validate_min: Duration,
    /// DE: Gleichzeitige Verbindungen (64). EN: Concurrent connections (64).
    pub max_connections: usize,
    /// DE: Höchstdauer einer Verbindung inkl. Body und Antwort (30 s).
    /// EN: Maximum duration of a connection incl. body and response (30 s).
    pub request_timeout: Duration,
    /// DE: Zeit für das Lesen der Header (10 s). EN: Time to read the headers (10 s).
    pub header_timeout: Duration,
    /// DE: Speicherbudget aller gleichzeitigen Argon2-Läufe in MiB (1024 = vier
    /// Standard- oder ein Hardened-Lauf). Reicht es nicht, antwortet die API sofort 503.
    /// EN: Memory budget of all concurrent Argon2 runs in MiB (1024 = four standard
    /// or one hardened run). If insufficient, the API answers 503 immediately.
    pub kdf_budget_mib: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests_per_window: 60,
            rate_window: Duration::from_secs(60),
            max_failed_tokens: 5,
            lockout: Duration::from_secs(15 * 60),
            validate_min: Duration::from_millis(300),
            max_connections: 64,
            request_timeout: Duration::from_secs(30),
            header_timeout: Duration::from_secs(10),
            kdf_budget_mib: 1024,
        }
    }
}

/// DE: Gemeinsamer Zustand aller Anfragen. EN: Shared state of all requests.
pub struct AppState {
    token: TokenHash,
    guard: Guard,
    limits: Limits,
    kdf_budget: Arc<Semaphore>,
}

impl AppState {
    /// DE: Neuer Zustand. EN: New state.
    #[must_use]
    pub fn new(token: TokenHash, limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            token,
            guard: Guard::new(limits.clone()),
            kdf_budget: Arc::new(Semaphore::new(limits.kdf_budget_mib as usize)),
            limits,
        })
    }

    /// DE: Grenzwerte. EN: Limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

/// DE: Vollständiger Router mit allen Schutzschichten. Die Client-Adresse wird als
/// `ConnectInfo<SocketAddr>` erwartet (setzt [`serve`]; in Tests z. B. `Extension(ConnectInfo(..))`).
/// EN: Full router with all protection layers. The client address is expected as
/// `ConnectInfo<SocketAddr>` (set by [`serve`]; in tests e.g. `Extension(ConnectInfo(..))`).
pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/v1/validate", post(handlers::validate))
        .route("/v1/generate", post(generate::generate))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth,
        ));
    Router::new()
        .route("/v1/health", get(handlers::health))
        .merge(protected)
        .fallback(handlers::not_found)
        .method_not_allowed_fallback(handlers::method_not_allowed)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit,
        ))
        .layer(axum::middleware::map_response(middleware::security_headers))
        .with_state(state)
}
