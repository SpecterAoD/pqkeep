//! DE: Verständliche Meldung, wenn gesperrter Speicher nicht reicht (#325): erlaubtes Limit,
//! Bedarf der Passphrase-Ableitung und Abhilfe. Die Sperrpflicht bleibt unverändert.
//! EN: Clear message when locked memory is insufficient (#325): allowed limit, need of the
//! passphrase derivation and remedy. Mandatory locking stays unchanged.

/// DE: Zweisprachiger Text „Deutsch / English“ (genau ein ` / `) für `localize`.
/// EN: Bilingual text "German / English" (exactly one ` / `) for `localize`.
pub fn message() -> String {
    if cfg!(windows) {
        return "Geheimer Speicher konnte nicht gesperrt werden (Windows verweigert das Working Set) / secret memory could not be locked (Windows refused the working set)"
            .to_owned();
    }
    let allowed = pqkeep::hardening::memlock::lock_limit().map(|bytes| bytes / (1024 * 1024));
    let (de, en) = match allowed {
        Some(mib) => (format!("erlaubt: {mib} MiB"), format!("allowed: {mib} MiB")),
        None => ("Limit unbekannt".to_owned(), "limit unknown".to_owned()),
    };
    format!(
        "Geheimer Speicher konnte nicht gesperrt werden ({de}; Passphrasen brauchen 256 MiB, Profil hardened 1 GiB). Abhilfe: sudo setcap cap_ipc_lock+p \"$(command -v pqkeep)\" (das Debian-Paket macht das selbst) oder 'ulimit -l' anheben – siehe docs/INSTALL.md \
         / secret memory could not be locked ({en}; passphrases need 256 MiB, profile hardened 1 GiB). Fix: sudo setcap cap_ipc_lock+p \"$(command -v pqkeep)\" (the Debian package does this itself) or raise 'ulimit -l' – see docs/INSTALL.md"
    )
}

#[cfg(test)]
#[path = "memlock_hint_tests.rs"]
mod memlock_hint_tests;
