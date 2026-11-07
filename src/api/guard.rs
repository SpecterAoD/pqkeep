//! DE: Schutz vor Überlastung und Raten: einfaches Rate-Limit je Client (festes
//! Zeitfenster) und Sperre nach wiederholt falschen Tokens. IPv6-Adressen werden auf
//! ihr /64-Präfix gekürzt, damit ein Angreifer nicht einfach die Adresse wechselt.
//! Die Tabelle ist in der Größe begrenzt; ist sie voll, werden neue Clients abgewiesen.
//!
//! EN: Protection against overload and guessing: simple per-client rate limit (fixed
//! window) and lockout after repeated wrong tokens. IPv6 addresses are truncated to
//! their /64 prefix so an attacker cannot simply switch addresses. The table has a
//! bounded size; when full, new clients are rejected.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use super::Limits;

/// DE: Höchstzahl gleichzeitig verfolgter Clients. EN: Maximum number of tracked clients.
pub const MAX_TRACKED_CLIENTS: usize = 4096;

#[derive(Clone, Copy)]
struct Entry {
    window_start: Instant,
    requests: u32,
    failures: u32,
    locked_until: Option<Instant>,
}

impl Entry {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            requests: 0,
            failures: 0,
            locked_until: None,
        }
    }

    fn is_active(&self, now: Instant, limits: &Limits) -> bool {
        self.locked_until.is_some_and(|t| t > now)
            || self.failures > 0
            || now.duration_since(self.window_start) < limits.rate_window
    }
}

/// DE: Zustand aller Clients. EN: State of all clients.
pub struct Guard {
    limits: Limits,
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

/// DE: Schlüssel für die Tabelle: IPv4 unverändert, IPv6 als /64-Präfix.
/// EN: Table key: IPv4 unchanged, IPv6 as /64 prefix.
#[must_use]
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        }
    }
}

impl Guard {
    /// DE: Neuer Wächter mit den gegebenen Grenzen. EN: New guard with the given limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// DE: Wendet `f` auf den Eintrag des Clients an; `None`, wenn die Tabelle voll ist.
    /// EN: Applies `f` to the client's entry; `None` if the table is full.
    fn with_entry<T>(&self, ip: IpAddr, f: impl FnOnce(&mut Entry, Instant) -> T) -> Option<T> {
        let now = Instant::now();
        let key = client_key(ip);
        // DE: Mit `panic = "abort"` kann der Mutex nicht vergiftet werden.
        // EN: With `panic = "abort"` the mutex cannot be poisoned.
        let mut map = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if !map.contains_key(&key) && map.len() >= MAX_TRACKED_CLIENTS {
            map.retain(|_, e| e.is_active(now, &self.limits));
            if map.len() >= MAX_TRACKED_CLIENTS {
                return None;
            }
        }
        let entry = map.entry(key).or_insert_with(|| Entry::new(now));
        Some(f(entry, now))
    }

    /// DE: Zählt eine Anfrage; `false`, wenn das Limit überschritten ist.
    /// EN: Counts a request; `false` if the limit is exceeded.
    #[must_use]
    pub fn allow_request(&self, ip: IpAddr) -> bool {
        let window = self.limits.rate_window;
        let max = self.limits.requests_per_window;
        self.with_entry(ip, |e, now| {
            if now.duration_since(e.window_start) >= window {
                e.window_start = now;
                e.requests = 0;
            }
            e.requests = e.requests.saturating_add(1);
            e.requests <= max
        })
        .unwrap_or(false)
    }

    /// DE: `true`, wenn der Client wegen falscher Tokens gesperrt ist.
    /// EN: `true` if the client is locked out because of wrong tokens.
    #[must_use]
    pub fn is_locked(&self, ip: IpAddr) -> bool {
        self.with_entry(ip, |e, now| e.locked_until.is_some_and(|t| t > now))
            .unwrap_or(true)
    }

    /// DE: Falsches oder fehlendes Token; sperrt nach `max_failed_tokens` Versuchen.
    /// EN: Wrong or missing token; locks out after `max_failed_tokens` attempts.
    pub fn record_failure(&self, ip: IpAddr) {
        let limits = &self.limits;
        let _ = self.with_entry(ip, |e, now| {
            e.failures = e.failures.saturating_add(1);
            if e.failures >= limits.max_failed_tokens {
                e.locked_until = Some(now + limits.lockout);
                e.failures = 0;
            }
        });
    }

    /// DE: Gültiges Token: Fehlversuche zurücksetzen. EN: Valid token: reset failures.
    pub fn record_success(&self, ip: IpAddr) {
        let _ = self.with_entry(ip, |e, _| e.failures = 0);
    }
}
