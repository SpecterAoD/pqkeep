//! DE: Endpunkte und Fehlerantworten. Fehler sind generisch (nur ein fester Code),
//! Eingaben werden nie protokolliert oder zurückgegeben.
//! EN: Endpoints and error responses. Errors are generic (a fixed code only);
//! inputs are never logged or echoed back.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use super::AppState;
use crate::security::{Assessment, Lang, Passphrase, Reason};

/// DE: Generische Fehler der API. EN: Generic API errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// 400
    BadRequest,
    /// 401
    Unauthorized,
    /// 404
    NotFound,
    /// 405
    MethodNotAllowed,
    /// 413
    PayloadTooLarge,
    /// 415
    UnsupportedMediaType,
    /// 429
    TooManyRequests,
    /// 500
    Internal,
}

impl ApiError {
    fn parts(self) -> (StatusCode, &'static str) {
        match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let mut res = (status, Json(serde_json::json!({ "error": code }))).into_response();
        if self == Self::Unauthorized {
            res.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        res
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => Self::PayloadTooLarge,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Self::UnsupportedMediaType,
            _ => Self::BadRequest,
        }
    }
}

/// DE: `GET /v1/health` – bewusst ohne Versionsangabe. EN: Deliberately without version.
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// DE: Unbekannter Pfad. EN: Unknown path.
pub async fn not_found() -> ApiError {
    ApiError::NotFound
}

/// DE: Falsche Methode. EN: Wrong method.
pub async fn method_not_allowed() -> ApiError {
    ApiError::MethodNotAllowed
}

/// DE: Anfrage an `/v1/validate`. EN: Request to `/v1/validate`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateRequest {
    passphrase: String,
    #[serde(default)]
    lang: Option<ReqLang>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum ReqLang {
    De,
    En,
}

/// DE: Ein Ablehnungsgrund. EN: One rejection reason.
#[derive(Serialize)]
struct ReasonOut {
    code: &'static str,
    message: String,
}

/// DE: Antwort von `/v1/validate`. EN: Response of `/v1/validate`.
#[derive(Serialize)]
struct ValidateResponse {
    strong: bool,
    entropy_bits: u32,
    reasons: Vec<ReasonOut>,
}

/// DE: Fester Code je Grund (stabil für Clients). EN: Fixed code per reason (stable for clients).
fn reason_code(reason: &Reason) -> &'static str {
    match reason {
        Reason::TooShort { .. } => "too_short",
        Reason::TooLong { .. } => "too_long",
        Reason::MissingLowercase => "missing_lowercase",
        Reason::MissingUppercase => "missing_uppercase",
        Reason::MissingDigit => "missing_digit",
        Reason::MissingSpecial => "missing_special",
        Reason::ControlCharacter => "control_character",
        Reason::Repetition => "repetition",
        Reason::Sequence => "sequence",
        Reason::KeyboardPattern => "keyboard_pattern",
        Reason::Blocklisted => "blocklisted",
        Reason::DictionaryWords => "dictionary_words",
        Reason::LowEntropy { .. } => "low_entropy",
    }
}

fn to_response(assessment: &Assessment, lang: Lang) -> ValidateResponse {
    ValidateResponse {
        strong: assessment.is_strong(),
        // DE: Abgerundet, begrenzt auf u32. EN: Rounded down, clamped to u32.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        entropy_bits: assessment
            .entropy_bits
            .floor()
            .clamp(0.0, f64::from(u32::MAX)) as u32,
        reasons: assessment
            .reasons
            .iter()
            .map(|r| ReasonOut {
                code: reason_code(r),
                message: r.message(lang),
            })
            .collect(),
    }
}

/// DE: Prüfung außerhalb des Async-Executors. EN: Check outside the async executor.
async fn assess(req: ValidateRequest) -> Result<ValidateResponse, ApiError> {
    let lang = match req.lang {
        Some(ReqLang::En) => Lang::En,
        _ => Lang::De,
    };
    let job = move || {
        // DE: `from_string` nullt die Eingabe. EN: `from_string` zeroes the input.
        let pass = Passphrase::from_string(req.passphrase).map_err(|_| ApiError::BadRequest)?;
        Ok(to_response(&pass.assess(), lang))
    };
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|_| ApiError::Internal)?
}

/// DE: `POST /v1/validate`. Jede Antwort (auch Fehler) wird auf die Mindestdauer
/// aufgefüllt, damit die Laufzeit nichts über den Aufbau der Passphrase verrät.
/// EN: Every response (errors too) is padded to the minimum duration so that the
/// run time reveals nothing about the structure of the passphrase.
pub async fn validate(
    State(state): State<Arc<AppState>>,
    body: Result<Json<ValidateRequest>, JsonRejection>,
) -> Response {
    let deadline = Instant::now() + state.limits.validate_min;
    let result = match body {
        Ok(Json(req)) => assess(req).await,
        Err(rejection) => Err(ApiError::from(rejection)),
    };
    tokio::time::sleep_until(deadline).await;
    match result {
        Ok(out) => Json(out).into_response(),
        Err(e) => e.into_response(),
    }
}
