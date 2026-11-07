//! DE: Systemaufruf-Listen je Profil, ermittelt mit `strace -f` aus den tatsächlichen
//! Abläufen (Start der Laufzeit, Anfragen, Argon2-/rayon-Threads, Speichersperre,
//! Strg+C). Varianten anderer glibc-Versionen und Architekturen sind ergänzt
//! (z. B. `epoll_pwait`, `newfstatat`). Bei Änderungen: Tests unter Linux laufen lassen.
//!
//! EN: System call lists per profile, derived with `strace -f` from the actual flows
//! (runtime start, requests, Argon2/rayon threads, memory locking, Ctrl+C). Variants
//! of other glibc versions and architectures are added (e.g. `epoll_pwait`,
//! `newfstatat`). When changing: run the tests on Linux.

use super::Profile;

/// DE: Bedingung für einen erlaubten Aufruf. EN: Condition for an allowed call.
#[derive(Debug, Clone, Copy)]
pub(super) enum Rule {
    /// DE: Immer erlaubt. EN: Always allowed.
    Always,
    /// DE: `(arg & mask) == mask` (32 Bit). EN: `(arg & mask) == mask` (32 bits).
    Masked(u8, u64),
    /// DE: `arg != wert` (32 Bit). EN: `arg != value` (32 bits).
    NotEq(u8, u64),
    /// DE: `arg == wert` (32 Bit). EN: `arg == value` (32 bits).
    Eq(u8, u64),
    /// DE: Zeiger-Argument ist NULL (64 Bit). EN: Pointer argument is NULL (64 bits).
    IsNull(u8),
}

/// DE: Nur Threads (`CLONE_THREAD`), keine neuen Prozesse.
/// EN: Threads only (`CLONE_THREAD`), no new processes.
#[allow(clippy::cast_sign_loss)]
const CLONE_THREAD_ONLY: &[Rule] = &[Rule::Masked(0, libc::CLONE_THREAD as u64)];

/// DE: Kein Einschleusen von Terminal-Eingaben (`TIOCSTI`, `TIOCLINUX`).
/// EN: No injection of terminal input (`TIOCSTI`, `TIOCLINUX`).
const IOCTL_SAFE: &[Rule] = &[
    Rule::NotEq(1, libc::TIOCSTI),
    Rule::NotEq(1, libc::TIOCLINUX),
];

/// DE: `prlimit64` nur lesend (neues Limit = NULL). EN: `prlimit64` read-only (new limit = NULL).
const PRLIMIT_READ: &[Rule] = &[Rule::IsNull(2)];

/// DE: `prctl` nur für Namen von Threads und Speicherbereichen (tokio, rayon, glibc).
/// EN: `prctl` only for names of threads and memory areas (tokio, rayon, glibc).
#[allow(clippy::cast_sign_loss)]
const PRCTL_OPTIONS: [u64; 3] = [
    libc::PR_SET_NAME as u64,
    libc::PR_GET_NAME as u64,
    libc::PR_SET_VMA as u64,
];

/// DE: Grundbedarf jedes Profils (Speicher, Threads, Zeit, Signale, Beenden).
/// EN: Base needs of every profile (memory, threads, time, signals, exit).
const BASE: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_lseek,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_openat,
    libc::SYS_fcntl,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_mlock,
    libc::SYS_munlock,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_tgkill,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_clock_gettime,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_getrandom,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_clone3,
];

/// DE: Zusätzlich für die API (Laufzeit und Verbindungen). EN: Additional for the API.
const API: &[i64] = &[
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_eventfd2,
    libc::SYS_socketpair,
    libc::SYS_accept4,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_shutdown,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_ppoll,
];

/// DE: Nur `x86_64` (`aarch64` kennt diese Aufrufe nicht). EN: `x86_64` only (absent on `aarch64`).
#[cfg(target_arch = "x86_64")]
const LEGACY: &[i64] = &[
    libc::SYS_epoll_wait,
    libc::SYS_poll,
    libc::SYS_access,
    libc::SYS_arch_prctl,
];
#[cfg(not(target_arch = "x86_64"))]
const LEGACY: &[i64] = &[];

/// DE: Erlaubte Aufrufe. Mehrere Einträge desselben Aufrufs gelten als ODER, die
/// Bedingungen innerhalb eines Eintrags als UND.
/// EN: Allowed calls. Several entries of the same call act as OR, the conditions
/// within one entry as AND.
pub(super) fn allow_list(profile: Profile) -> Vec<(i64, Vec<Rule>)> {
    let extra = match profile {
        Profile::Api => API,
    };
    let mut list: Vec<(i64, Vec<Rule>)> = BASE
        .iter()
        .chain(extra)
        .chain(LEGACY)
        .map(|&nr| (nr, vec![Rule::Always]))
        .collect();
    list.push((libc::SYS_clone, CLONE_THREAD_ONLY.to_vec()));
    list.push((libc::SYS_ioctl, IOCTL_SAFE.to_vec()));
    list.push((libc::SYS_prlimit64, PRLIMIT_READ.to_vec()));
    for option in PRCTL_OPTIONS {
        list.push((libc::SYS_prctl, vec![Rule::Eq(0, option)]));
    }
    list
}

/// DE: Aufrufe, die den Prozess sofort beenden. EN: Calls that kill the process at once.
pub(super) fn deny_list(profile: Profile) -> Vec<i64> {
    let mut list = vec![
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
    ];
    #[cfg(target_arch = "x86_64")]
    list.extend([libc::SYS_fork, libc::SYS_vfork]);
    match profile {
        Profile::Api => list.extend([
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
        ]),
    }
    list
}
