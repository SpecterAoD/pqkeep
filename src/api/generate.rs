//! DE: `POST /v1/generate`: erzeugt einen Schlüssel, schützt ihn mit der Passphrase
//! und liefert Schlüsseldatei und (außer bei AES) öffentliche Schlüsseldatei als JSON.
//! Der Server speichert nichts. Argon2 läuft in `spawn_blocking`; ein Speicherbudget
//! (Semaphore, Einheit MiB) begrenzt gleichzeitige Läufe, sonst sofort 503. Die
//! Reservierung wird erst nach Ende der Berechnung frei, auch wenn der Client vorher
//! die Verbindung trennt.
//!
//! EN: `POST /v1/generate`: generates a key, protects it with the passphrase and
//! returns key file and (except for AES) public key file as JSON. The server stores
//! nothing. Argon2 runs in `spawn_blocking`; a memory budget (semaphore, unit MiB)
//! limits concurrent runs, otherwise 503 immediately. The reservation is released
//! only when the computation ends, even if the client disconnects earlier.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::OwnedSemaphorePermit;

use super::AppState;
use super::handlers::{ApiError, ReqLang, lang_of, to_response};
use crate::crypto::KeyAlgorithm;
use crate::crypto::kdf::KdfProfile;
use crate::envelope::{KeyFile, Metadata};
use crate::security::{Lang, Passphrase, Rejection, StrongPassphrase};

/// DE: Metadaten in der Anfrage. EN: Metadata in the request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetaIn {
    name: String,
    organization: Option<String>,
    company: Option<String>,
    department: Option<String>,
    account_type: Option<String>,
}

/// DE: Anfrage an `/v1/generate`. EN: Request to `/v1/generate`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateRequest {
    passphrase: String,
    metadata: MetaIn,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    profile: Option<ProfileIn>,
    #[serde(default)]
    lang: Option<ReqLang>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum ProfileIn {
    Standard,
    Hardened,
}

/// DE: Algorithmus aus dem CLI-Namen (`ml-kem-768`, `aes-256` …), nur Kleinschreibung.
/// EN: Algorithm from the CLI name (`ml-kem-768`, `aes-256` …), lowercase only.
fn algorithm(name: Option<&str>) -> Result<KeyAlgorithm, ApiError> {
    let name = name.unwrap_or("ml-kem-768");
    if name != name.to_ascii_lowercase() {
        return Err(ApiError::BadRequest);
    }
    KeyAlgorithm::from_id(&name.to_ascii_uppercase()).map_err(|_| ApiError::BadRequest)
}

fn metadata(m: MetaIn) -> Result<Metadata, ApiError> {
    Metadata {
        name: m.name,
        organization: m.organization,
        company: m.company,
        department: m.department,
        account_type: m.account_type,
    }
    .normalized()
    .map_err(|_| ApiError::BadRequest)
}

/// DE: Schlüssel erzeugen und als JSON aufbereiten (blockierend).
/// EN: Generate the key and prepare it as JSON (blocking).
fn create(
    strong: StrongPassphrase,
    alg: KeyAlgorithm,
    meta: &Metadata,
    profile: KdfProfile,
) -> Result<Value, ApiError> {
    let key =
        KeyFile::generate(&strong, alg, meta, &profile.params()).map_err(|_| ApiError::Internal)?;
    drop(strong);
    let parse = |text: String| serde_json::from_str::<Value>(&text).map_err(|_| ApiError::Internal);
    let key_json = parse(key.to_json().map_err(|_| ApiError::Internal)?)?;
    let public_json = match key.public_part() {
        Ok(p) => parse(p.to_json().map_err(|_| ApiError::Internal)?)?,
        Err(_) => Value::Null,
    };
    Ok(json!({
        "algorithm": alg.id(),
        "key_id": key.key_id_hex(),
        "key_file": key_json,
        "public_key_file": public_json,
    }))
}

/// DE: Reserviert das Speicherbudget für das Profil (ohne Warten).
/// EN: Reserves the memory budget for the profile (without waiting).
fn reserve(state: &AppState, profile: KdfProfile) -> Result<OwnedSemaphorePermit, ApiError> {
    let mib = profile.params().memory_kib / 1024;
    state
        .kdf_budget
        .clone()
        .try_acquire_many_owned(mib)
        .map_err(|_| ApiError::Busy)
}

fn weak_response(rejection: &Rejection, lang: Lang) -> Response {
    let assessment = crate::security::Assessment {
        reasons: rejection.reasons.clone(),
        entropy_bits: rejection.entropy_bits,
    };
    let mut body = serde_json::to_value(to_response(&assessment, lang)).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut body {
        map.remove("strong");
        map.insert("error".to_owned(), json!("weak_passphrase"));
    }
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

async fn run(state: &AppState, req: GenerateRequest) -> Result<Response, ApiError> {
    let lang = lang_of(req.lang);
    let alg = algorithm(req.algorithm.as_deref())?;
    let meta = metadata(req.metadata)?;
    let profile = match req.profile {
        Some(ProfileIn::Hardened) => KdfProfile::Hardened,
        _ => KdfProfile::Standard,
    };
    // DE: `from_string` nullt die Eingabe. EN: `from_string` zeroes the input.
    let pass = Passphrase::from_string(req.passphrase).map_err(|_| ApiError::BadRequest)?;
    // DE: Erst prüfen, dann Budget reservieren. EN: Check first, then reserve the budget.
    let strong = match StrongPassphrase::try_from(pass) {
        Ok(p) => p,
        Err(rejection) => return Ok(weak_response(&rejection, lang)),
    };
    let permit = reserve(state, profile)?;
    let job = move || {
        let result = create(strong, alg, &meta, profile);
        drop(permit);
        result
    };
    let body = tokio::task::spawn_blocking(job)
        .await
        .map_err(|_| ApiError::Internal)??;
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// DE: `POST /v1/generate`. EN: `POST /v1/generate`.
pub async fn generate(
    State(state): State<Arc<AppState>>,
    body: Result<Json<GenerateRequest>, JsonRejection>,
) -> Response {
    let result = match body {
        Ok(Json(req)) => run(&state, req).await,
        Err(rejection) => Err(ApiError::from(rejection)),
    };
    result.unwrap_or_else(IntoResponse::into_response)
}
