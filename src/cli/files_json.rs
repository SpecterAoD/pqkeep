//! DE: `encrypt --json` und `decrypt --json` (#85, `docs/JSON.md`): dieselben Abläufe wie ohne
//! `--json`, aber statt Textzeilen ein Objekt mit `results` (je Ziel: Quelle, Ziel, Zähler oder
//! Fehler) und `summary`. Scheitert der Befehl als Ganzes (eine Quelle, Container, falsche
//! Passphrase vor dem Start), gibt es nur `error`. Keine Pfade aus dem Archivinhalt: übersprungene
//! Einträge erscheinen nur als Anzahl.
//! EN: `encrypt --json` and `decrypt --json` (#85, `docs/JSON.md`): the same flows as without
//! `--json`, but instead of text lines an object with `results` (per target: source, target,
//! counters or error) and `summary`. If the command fails as a whole (one source, container,
//! wrong passphrase before starting) there is only `error`. No paths from archive contents:
//! skipped entries appear as a count only.

use std::path::{Path, PathBuf};

use clap::ArgMatches;
use pqkeep::files::{self, Report};
use pqkeep::security::Lang;
use serde_json::{Map, Value, json};

use super::files_cmd::{
    apply_temp_tag, default_decrypted, default_encrypted, default_for, read_protection, source,
    sources, target,
};
use super::io::{CliResult, Failure, code};
use super::text::Texts;

/// DE: Ergebnis je Ziel. EN: Result per target.
type Outcome = Result<Report, Failure>;

/// DE: Ein Eintrag in `results`; `source` ist ein Pfad oder (Container) eine Liste.
/// EN: One entry in `results`; `source` is a path or (container) a list.
fn entry(source: &Value, out: Option<&Path>, r: &Outcome) -> Value {
    let target = out.map(|p| p.to_string_lossy().into_owned());
    match r {
        Ok(r) => json!({ "source": source, "target": target, "ok": true, "files": r.files,
            "directories": r.directories, "bytes": r.bytes, "skipped": r.skipped.len(),
            "signer": signer(r) }),
        Err(f) => json!({ "source": source, "target": target, "ok": false,
            "error": super::json_out::error(f) }),
    }
}

/// DE: `results`, `summary` und erster Fehlercode. EN: `results`, `summary` and first error code.
fn body(entries: &[(Value, Option<PathBuf>, Outcome)]) -> (Map<String, Value>, u8) {
    let ok = entries.iter().filter(|(_, _, r)| r.is_ok()).count();
    let total = entries.len();
    let exit = entries
        .iter()
        .find_map(|(_, _, r)| r.as_ref().err().map(|f| f.code))
        .unwrap_or(code::OK);
    let results: Vec<Value> = entries
        .iter()
        .map(|(s, out, r)| entry(s, out.as_deref(), r))
        .collect();
    let mut map = Map::new();
    map.insert("results".into(), results.into());
    map.insert(
        "summary".into(),
        json!({ "total": total, "ok": ok, "failed": total - ok }),
    );
    (map, exit)
}

/// DE: Geprüfter Absender als Schlüssel-ID (hex) oder `null` (#44). EN: Verified sender as key ID
/// (hex) or `null` (#44).
pub(super) fn signer(r: &Report) -> Value {
    r.signer.as_ref().map_or(Value::Null, |s| {
        pqkeep::envelope::hex_encode(&s.key_id).into()
    })
}

fn path_value(p: &Path) -> Value {
    p.to_string_lossy().into_owned().into()
}

/// DE: Zu schwache Passphrase: Text kommt sonst nur auf stderr – hier eine kurze Meldung.
/// EN: Weak passphrase: the text otherwise goes to stderr only – here a short message.
fn weak(t: &Texts) -> impl Fn(Failure) -> Failure + '_ {
    |f| {
        if f.code == code::WEAK && f.message.is_empty() {
            Failure::new(code::WEAK, t.msg_rejected.trim_end_matches(':'))
        } else {
            f
        }
    }
}

/// DE: `pqkeep encrypt --json`. EN: `pqkeep encrypt --json`.
pub fn encrypt(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<(Map<String, Value>, u8)> {
    apply_temp_tag(m, lang)?;
    let all = sources(m);
    let fail = |e: pqkeep::Error| Failure::from_error(&e, lang);
    if all.len() > 1 && !m.get_flag("each") {
        let s = super::many_text::many_texts(lang);
        let out = m
            .get_one::<PathBuf>("out")
            .ok_or_else(|| Failure::new(code::USAGE, s.need_out))?;
        let protection = read_protection(t, lang, m).map_err(weak(t))?;
        let list: Vec<&Path> = all.iter().map(PathBuf::as_path).collect();
        let report = protection.encrypt_many(&list, out).map_err(fail)?;
        let names = all.iter().map(|p| path_value(p)).collect::<Vec<_>>();
        return Ok(body(&[(names.into(), Some(out.clone()), Ok(report))]));
    }
    if all.len() == 1 && !m.get_flag("each") {
        let src = source(m);
        let out = target(t, m, default_for(m, default_encrypted(&src)))?;
        let protection = read_protection(t, lang, m).map_err(weak(t))?;
        let report = protection.encrypt(&src, &out).map_err(fail)?;
        return Ok(body(&[(path_value(&src), Some(out), Ok(report))]));
    }
    let protection = read_protection(t, lang, m).map_err(weak(t))?;
    let entries: Vec<_> = all
        .iter()
        .map(|src| {
            let out = default_for(m, default_encrypted(src));
            let r = match &out {
                Some(out) => protection.encrypt(src, out).map_err(fail),
                None => Err(Failure::new(code::EXISTS, "")),
            };
            (path_value(src), out, r)
        })
        .collect();
    Ok(body(&entries))
}

/// DE: `pqkeep decrypt --json`. EN: `pqkeep decrypt --json`.
pub fn decrypt(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult<(Map<String, Value>, u8)> {
    apply_temp_tag(m, lang)?;
    let all = sources(m);
    let fail = |e: pqkeep::Error| Failure::from_error(&e, lang);
    if all.len() == 1 {
        let src = source(m);
        let access = super::unlock::Access::read(&src).map_err(fail)?;
        let out = target(t, m, default_for(m, default_decrypted(&src)))?;
        let use_key = access.use_key(m.get_one::<PathBuf>("key").is_some());
        let expected = super::signing::load_expected(lang, m)?;
        let opened = super::unlock::for_decrypt(t, lang, m, use_key, access.passphrase)?;
        let report =
            files::decrypt_with(&src, &out, &opened.get(), expected.as_ref()).map_err(fail)?;
        return Ok(body(&[(path_value(&src), Some(out), Ok(report))]));
    }
    let (opened, expected) = super::files_many::open_many_signed(t, lang, m, &all)?;
    let unlock = opened.get();
    let entries: Vec<_> = all
        .iter()
        .map(|src| {
            let out = default_for(m, default_decrypted(src));
            let r = match &out {
                Some(out) => {
                    files::decrypt_with(src, out, &unlock, expected.as_ref()).map_err(fail)
                }
                None => Err(Failure::new(code::EXISTS, "")),
            };
            (path_value(src), out, r)
        })
        .collect();
    Ok(body(&entries))
}
