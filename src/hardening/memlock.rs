//! DE: Sperren von Speicherseiten mit Geheimnissen (Linux `mlock`, Windows
//! `VirtualLock`) über die Crate `region` – ohne eigenen `unsafe`-Code.
//! Gesperrt wird pro Seite, nicht pro Variable. Ein Seitenzähler verhindert, dass
//! das Freigeben eines Geheimnisses die Sperre eines anderen auf derselben Seite
//! aufhebt. Unvollständige Sperren werden gemeldet; Secret-Konstruktoren verweigern die Nutzung.
//!
//! EN: Locking memory pages holding secrets (Linux `mlock`, Windows
//! `VirtualLock`) via the `region` crate – without own `unsafe` code.
//! Locking is per page, not per variable. A page counter prevents releasing one
//! secret from unlocking another on the same page. Secret constructors reject incomplete locks.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use region::LockGuard;
use zeroize::Zeroize;

#[cfg(test)]
#[path = "memlock_tests.rs"]
mod memlock_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "memlock_denial_tests.rs"]
mod denial_tests;

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
    // DE: Nur der erfolgreiche zusammenhängende Präfix, keine eigene Adressliste.
    // EN: Only the successful contiguous prefix, with no separate address allocation.
    pages: Range<usize>,
}

impl LockedRange {
    /// DE: `true`, wenn alle Seiten gesperrt werden konnten.
    /// EN: `true` if all pages could be locked.
    pub fn complete(&self, addr: usize, len: usize) -> bool {
        len == 0 || page_span(addr, len).is_some_and(|span| self.pages == span)
    }

    fn release(&mut self) {
        let mut reg = registry();
        for page in self.pages.clone().step_by(region::page::size()) {
            let remove = reg.get_mut(&page).is_some_and(|entry| {
                entry.0 -= 1;
                entry.0 == 0
            });
            if remove {
                // DE: Entfernen gibt die Sperre frei (Drop von LockGuard).
                // EN: Removing releases the lock (drop of LockGuard).
                reg.remove(&page);
            }
        }
        // DE: Eigenen Record löschen; temporäre Compiler-/Stackkopien bleiben offen.
        // EN: Wipe the owned record; temporary compiler/stack copies remain open.
        self.pages.start.zeroize();
        self.pages.end.zeroize();
    }
}

fn page_span(addr: usize, len: usize) -> Option<Range<usize>> {
    if len == 0 {
        return Some(0..0);
    }
    let size = region::page::size();
    let last = addr.checked_add(len)?.checked_sub(1)?;
    let end = (last - last % size).checked_add(size)?;
    Some((addr - addr % size)..end)
}

fn acquire_page(reg: &mut Registry, page: usize, size: usize) -> bool {
    if let Some(entry) = reg.get_mut(&page) {
        let Some(count) = entry.0.checked_add(1) else {
            return false;
        };
        entry.0 = count;
        return true;
    }
    if let Ok(guard) = region::lock(std::ptr::without_provenance::<u8>(page), size) {
        reg.insert(page, (1, guard));
        true
    } else {
        false
    }
}

fn lock_capacity(pages: usize, span: &Range<usize>) -> Option<usize> {
    pages
        .checked_mul(region::page::size())?
        .checked_add(span.len())
}

/// DE: Sperrt alle Seiten von `[addr, addr + len)`; leere Bereiche werden ignoriert.
/// EN: Locks all pages of `[addr, addr + len)`; empty ranges are ignored.
pub(crate) fn lock_range(addr: usize, len: usize) -> LockedRange {
    let mut locked = LockedRange::empty();
    locked.acquire(addr, len);
    locked
}

impl LockedRange {
    // DE: Nur öffentliche Anfangswerte vor einer optionalen Metadatensperre.
    // EN: Only public initial values before an optional metadata lock.
    pub(crate) fn empty() -> Self {
        Self { pages: 0..0 }
    }

    // DE: Record direkt befüllen; bestehende vollständige/partielle Sperren behalten.
    // EN: Populate in place; preserve existing complete or partial lock ownership.
    pub(crate) fn acquire(&mut self, addr: usize, len: usize) -> bool {
        if self.pages != (0..0) {
            return false;
        }
        if len == 0 {
            return true;
        }
        let Some(span) = page_span(addr, len) else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        self.pages = span.start..span.start;
        let size = region::page::size();
        let mut reg = registry();
        let total = lock_capacity(reg.len(), &span);
        if total.is_none_or(|n| region::prepare_lock_capacity(n).is_err()) {
            FAILED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        for page in span.step_by(size) {
            if !acquire_page(&mut reg, page, size) {
                FAILED.fetch_add(1, Ordering::Relaxed);
                break;
            }
            // DE: Die geprüfte Spanne umfasst bereits jede volle Seite ohne Überlauf.
            // EN: The checked span already contains each full page without overflow.
            self.pages.end = page + size;
        }
        self.complete(addr, len)
    }
}

// DE: Der konkrete Drop löscht beide Felder nach Freigabe des Seitenzählers.
// EN: The concrete destructor wipes both fields after releasing page references.
impl zeroize::ZeroizeOnDrop for LockedRange {}

impl Default for LockedRange {
    fn default() -> Self {
        Self::empty()
    }
}

impl Zeroize for LockedRange {
    fn zeroize(&mut self) {
        self.release();
    }
}

impl Drop for LockedRange {
    fn drop(&mut self) {
        self.release();
    }
}

/// DE: Ist die Seite der Adresse gesperrt (laut Zähler)? EN: Is the address' page locked?
#[must_use]
pub fn is_locked(addr: usize) -> bool {
    let size = region::page::size();
    registry().contains_key(&(addr - addr % size))
}

/// DE: Erlaubtes Sperrbudget (weiches `RLIMIT_MEMLOCK`) in Byte, nur zur Diagnose (#325);
/// `None` = unbegrenzt, unbekannt oder nicht Linux. Mit `CAP_IPC_LOCK` gilt das Limit nicht.
/// EN: Allowed lock budget (soft `RLIMIT_MEMLOCK`) in bytes, for diagnosis only (#325); `None` =
/// unlimited, unknown or not Linux. With `CAP_IPC_LOCK` the limit does not apply.
#[must_use]
pub fn lock_limit() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        rustix::process::getrlimit(rustix::process::Resource::Memlock).current
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
