//! DE: Maschinenlesbare Ausgabe (`--json`, #85): genau ein JSON-Objekt auf stdout mit stabilem,
//! versioniertem Schema (`pqkeep-json/1`). Feldnamen und `kind` sind englisch und stabil, nur
//! `message` folgt `--lang`. Auch wenn ein Befehl scheitert, steht ein gültiges Objekt mit
//! `"ok": false` und `error` da; nur Fehler in den Argumenten selbst (clap) bleiben Text (Exit 2).
//! Keine Geheimnisse, keine Pfade aus dem Archivinhalt. Beschreibung: `docs/JSON.md`.
//! EN: Machine-readable output (`--json`, #85): exactly one JSON object on stdout with a stable,
//! versioned schema (`pqkeep-json/1`). Field names and `kind` are English and stable, only
//! `message` follows `--lang`. Even when a command fails a valid object with `"ok": false` and
//! `error` is printed; only errors in the arguments themselves (clap) stay text (exit 2). No
//! secrets, no paths from archive contents. Description: `docs/JSON.md`.

use clap::{Arg, ArgMatches};
use pqkeep::security::Lang;
use serde_json::{Map, Value, json};

use super::io::{CliResult, Failure, code};

/// DE: Schema-Kennung; ändert sich nur bei inkompatiblen Änderungen.
/// EN: Schema identifier; changes only with incompatible changes.
pub const SCHEMA: &str = "pqkeep-json/1";

/// DE: Option `--json`. EN: Option `--json`.
pub fn arg(lang: Lang) -> Arg {
    let help = match lang {
        Lang::De => "Ergebnis als JSON auf stdout (Schema pqkeep-json/1, siehe docs/JSON.md)",
        Lang::En => "Result as JSON on stdout (schema pqkeep-json/1, see docs/JSON.md)",
    };
    super::args::flag("json", help)
}

/// DE: Ist `--json` gesetzt? (auch für Befehle ohne die Option). EN: Is `--json` set?
pub fn wanted(m: &ArgMatches) -> bool {
    matches!(m.try_get_one::<bool>("json"), Ok(Some(true)))
}

/// DE: Stabiler Name je Exit-Code. EN: Stable name per exit code.
pub fn kind(exit: u8) -> &'static str {
    match exit {
        code::OK => "ok",
        code::USAGE => "usage",
        code::DECRYPT => "decrypt_failed",
        code::WEAK => "weak_passphrase",
        code::EXISTS => "target_exists",
        code::NO_WINDOWS => "no_windows",
        code::INVALID => "invalid_signature",
        _ => "error",
    }
}

/// DE: Fehlerobjekt `{code, kind, message}`. EN: Error object `{code, kind, message}`.
pub fn error(f: &Failure) -> Value {
    json!({ "code": f.code, "kind": kind(f.code), "message": f.message })
}

/// DE: Gibt das Objekt aus und liefert den Exit-Code (ohne zweite Textmeldung).
/// EN: Prints the object and returns the exit code (without a second text message).
pub fn emit(command: &str, body: Map<String, Value>, exit: u8) -> CliResult {
    let mut out = Map::new();
    out.insert("schema".into(), SCHEMA.into());
    out.insert("command".into(), command.into());
    out.insert("ok".into(), (exit == code::OK).into());
    out.insert("exit_code".into(), exit.into());
    out.extend(body);
    println!("{}", Value::Object(out));
    if exit == code::OK {
        Ok(())
    } else {
        Err(Failure::new(exit, ""))
    }
}

/// DE: Scheitert ein Befehl vorzeitig, ein Objekt mit `error` ausgeben.
/// EN: If a command fails early, print an object with `error`.
pub fn failed(command: &str, f: &Failure) -> CliResult {
    let mut body = Map::new();
    body.insert("error".into(), error(f));
    emit(command, body, f.code)
}

/// DE: Führt `f` im JSON-Modus aus: Erfolg → Daten, Fehler → Fehlerobjekt.
/// EN: Runs `f` in JSON mode: success → data, failure → error object.
pub fn run(command: &str, f: impl FnOnce() -> CliResult<(Map<String, Value>, u8)>) -> CliResult {
    match f() {
        Ok((body, exit)) => emit(command, body, exit),
        Err(e) => failed(command, &e),
    }
}

/// DE: Bei `--json` einen frühen Fehler (z. B. Sandbox: „nicht gefunden“) als JSON melden.
/// EN: With `--json` report an early error (e.g. sandbox: "not found") as JSON.
pub fn early(command: &str, m: &ArgMatches, f: Failure) -> Failure {
    if wanted(m) {
        return failed(command, &f).err().unwrap_or(f);
    }
    f
}

#[cfg(test)]
#[path = "json_out_tests.rs"]
mod tests;
