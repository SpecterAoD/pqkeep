//! DE: Speichersperre: Geheimnisse liegen in gesperrten Seiten; beim Freigeben
//! sinkt die Zahl gesperrter Seiten wieder. Unter Linux zusätzlich über `VmLck`
//! in /proc/self/status geprüft. Ein Test pro Datei, da der Status prozessweit ist.
//! EN: Memory locking: secrets live in locked pages; releasing them lowers the
//! number of locked pages again. On Linux additionally checked via `VmLck` in
//! /proc/self/status. One test per file because the status is process-wide.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::crypto::SecretBytes;
use pqkeep::hardening::memlock;

#[cfg(target_os = "linux")]
fn vm_lck_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmLck:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

#[test]
fn secrets_are_locked_and_released() {
    let before = memlock::stats();
    #[cfg(target_os = "linux")]
    let kib_before = vm_lck_kib();

    // DE: 3 Seiten großes Geheimnis. EN: Secret spanning 3 pages.
    let size = 3 * region::page::size();
    let secret = SecretBytes::new(vec![0x5A; size]);
    let during = memlock::stats();
    assert!(secret.is_locked(), "{during:?}");
    assert!(during.locked_pages >= before.locked_pages + 3);
    assert_eq!(during.failed_attempts, before.failed_attempts);
    #[cfg(target_os = "linux")]
    assert!(vm_lck_kib() >= kib_before + size as u64 / 1024, "VmLck");

    drop(secret);
    let after = memlock::stats();
    assert_eq!(after.locked_pages, before.locked_pages);
    #[cfg(target_os = "linux")]
    assert_eq!(vm_lck_kib(), kib_before);
}
