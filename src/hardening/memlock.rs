//! DE: Sperren von Speicherseiten mit Geheimnissen (Linux `mlock`, Windows
//! `VirtualLock`) über die Crate `region` – ohne eigenen `unsafe`-Code.
//! Gesperrt wird pro Seite, nicht pro Variable. Ein Seitenzähler verhindert, dass
//! das Freigeben eines Geheimnisses die Sperre eines anderen auf derselben Seite
//! aufhebt. Best effort: Schlägt das Sperren fehl (z. B. Grenze `RLIMIT_MEMLOCK`),
//! läuft das Programm weiter und der Fehlschlag wird gezählt.
//!
//! EN: Locking memory pages holding secrets (Linux `mlock`, Windows
//! `VirtualLock`) via the `region` crate – without own `unsafe` code.
//! Locking is per page, not per variable. A page counter prevents releasing one
//! secret from unlocking another one on the same page. Best effort: if locking
//! fails (e.g. `RLIMIT_MEMLOCK`), the program continues and the failure is counted.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use region::LockGuard;

#[cfg(test)]
#[path = "memlock_tests.rs"]
mod memlock_tests;

/// DE: Gesperrte Seiten: Seitenadresse → (Anzahl Nutzer, Sperre).
/// EN: Locked pages: page address → (number of users, lock).
type Registry = BTreeMap<usize, (usize, LockGuard)>;

fn registry() -> MutexGuard<'static, Registry> {
    static PAGES: OnceLock<Mutex<Registry>> = OnceLock::new();
    PAGES
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

static FAILED: AtomicUsize = AtomicUsize::new(0);

/// DE: Momentaufnahme des Sperrstatus. EN: Snapshot of the lock status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockStats {
    /// DE: Aktuell gesperrte Seiten. EN: Currently locked pages.
    pub locked_pages: usize,
    /// DE: Fehlgeschlagene Sperrversuche seit Start. EN: Failed lock attempts since start.
    pub failed_attempts: usize,
}

/// DE: Aktueller Sperrstatus. EN: Current lock status.
#[must_use]
pub fn stats() -> LockStats {
    LockStats {
        locked_pages: registry().len(),
        failed_attempts: FAILED.load(Ordering::Relaxed),
    }
}

/// DE: Bereich, dessen Seiten (teilweise) gesperrt sind; gibt beim Drop frei.
/// EN: Range whose pages are (partly) locked; releases on drop.
pub(crate) struct LockedRange {
    pages: Vec<usize>,
}

impl LockedRange {
    /// DE: `true`, wenn alle Seiten gesperrt werden konnten.
    /// EN: `true` if all pages could be locked.
    pub fn complete(&self, addr: usize, len: usize) -> bool {
        self.pages.len() == page_span(addr, len).count()
    }
}

fn page_span(addr: usize, len: usize) -> impl Iterator<Item = usize> {
    let size = region::page::size();
    let first = addr - addr % size;
    let end = addr.saturating_add(len);
    (first..end).step_by(size)
}

/// DE: Sperrt alle Seiten von `[addr, addr + len)`; leere Bereiche werden ignoriert.
/// EN: Locks all pages of `[addr, addr + len)`; empty ranges are ignored.
pub(crate) fn lock_range(addr: usize, len: usize) -> LockedRange {
    let mut pages = Vec::new();
    if len == 0 {
        return LockedRange { pages };
    }
    let size = region::page::size();
    let mut reg = registry();
    for page in page_span(addr, len) {
        if let Some(entry) = reg.get_mut(&page) {
            entry.0 += 1;
            pages.push(page);
            continue;
        }
        match region::lock(std::ptr::without_provenance::<u8>(page), size) {
            Ok(guard) => {
                reg.insert(page, (1, guard));
                pages.push(page);
            }
            Err(_) => {
                FAILED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    LockedRange { pages }
}

impl Drop for LockedRange {
    fn drop(&mut self) {
        let mut reg = registry();
        for page in &self.pages {
            let remove = reg.get_mut(page).is_some_and(|entry| {
                entry.0 -= 1;
                entry.0 == 0
            });
            if remove {
                // DE: Entfernen gibt die Sperre frei (Drop von `LockGuard`).
                // EN: Removing releases the lock (drop of `LockGuard`).
                reg.remove(page);
            }
        }
    }
}

/// DE: Ist die Seite der Adresse gesperrt (laut Zähler)? EN: Is the address' page locked?
#[must_use]
pub fn is_locked(addr: usize) -> bool {
    let size = region::page::size();
    registry().contains_key(&(addr - addr % size))
}
