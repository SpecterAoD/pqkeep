//! DE: Kernel-Limitabfrage mit echter Fehlerprüfung statt Unfehlbarkeitsannahme.
//! EN: Check actual kernel-query failure instead of assuming infallibility.
use std::io;

/// DE: Aktuelles Core-Limit dieses Prozesses ohne Policy-Änderung prüfen.
/// EN: Check this process's current core limits without changing policy.
/// # Errors
/// DE/EN: Native Verweigerung, etwa Seccomp / native refusal, including seccomp.
pub fn core_limits_disabled() -> io::Result<bool> {
    // DE/EN: Öffentliche Policy-Diagnose, keine privaten Anwendungsdaten / public policy diagnostic only.
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // DE: Tatsächlicher libc-Typ, vollständig initialisiertes exklusives Ziel.
    // SAFETY: RLIMIT_CORE is valid; limits has the actual SDK layout/alignment
    // and remains writable/exclusive for the synchronous call. No pointer is retained.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limits) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(limits.rlim_cur == 0 && limits.rlim_max == 0)
}
