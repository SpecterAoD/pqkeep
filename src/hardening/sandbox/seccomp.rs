//! DE: Seccomp-Filter je Profil. Drei gestapelte Filter; der Kernel wendet jeweils die
//! strengste Antwort an:
//! 1. Erlaubnisliste: nicht gelistete Aufrufe → `EPERM` (Fehler statt Absturz, falls eine
//!    andere glibc einen unerwarteten Aufruf nutzt).
//! 2. Verbotsliste: z. B. `execve`, `ptrace`, neue Sockets → Prozess wird beendet (SIGSYS).
//! 3. `clone3` → `ENOSYS`: Seine Flags liegen in einer Struktur und sind nicht prüfbar;
//!    glibc weicht auf `clone` aus, das nur mit `CLONE_THREAD` erlaubt ist (Threads ja,
//!    neue Prozesse nein).
//!
//! EN: Seccomp filters per profile. Three stacked filters; the kernel applies the
//! strictest answer:
//! 1. Allow list: unlisted calls → `EPERM` (an error instead of a crash if another glibc
//!    uses an unexpected call).
//! 2. Deny list: e.g. `execve`, `ptrace`, new sockets → process is killed (SIGSYS).
//! 3. `clone3` → `ENOSYS`: its flags live in a struct and cannot be checked; glibc falls
//!    back to `clone`, which is allowed only with `CLONE_THREAD` (threads yes, new
//!    processes no).

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use super::syscalls::{Rule, allow_list, deny_list};
use super::{Profile, Status};

type Rules = BTreeMap<i64, Vec<SeccompRule>>;

fn condition(rule: Rule) -> Result<Option<SeccompCondition>, ()> {
    use SeccompCmpArgLen::{Dword, Qword};
    let (arg, len, op, value) = match rule {
        Rule::Always => return Ok(None),
        Rule::Masked(arg, mask) => (arg, Dword, SeccompCmpOp::MaskedEq(mask), mask),
        Rule::NotEq(arg, value) => (arg, Dword, SeccompCmpOp::Ne, value),
        Rule::Eq(arg, value) => (arg, Dword, SeccompCmpOp::Eq, value),
        Rule::IsNull(arg) => (arg, Qword, SeccompCmpOp::Eq, 0),
    };
    SeccompCondition::new(arg, len, op, value)
        .map(Some)
        .map_err(|_| ())
}

/// DE: Baut die Regelmenge. Ein Eintrag ohne Bedingungen erlaubt den Aufruf immer;
/// mehrere Einträge desselben Aufrufs gelten als ODER.
/// EN: Builds the rule set. An entry without conditions always allows the call;
/// several entries of the same call act as OR.
fn rules(entries: &[(i64, Vec<Rule>)]) -> Result<Rules, ()> {
    let mut map = Rules::new();
    for (nr, conds) in entries {
        let mut conditions = Vec::new();
        for &rule in conds {
            conditions.extend(condition(rule)?);
        }
        if conditions.is_empty() {
            map.insert(*nr, Vec::new());
        } else if map.get(nr).is_none_or(|existing| !existing.is_empty()) {
            // DE: Nur ergänzen, wenn der Aufruf nicht schon bedingungslos erlaubt ist.
            // EN: Only add if the call is not already allowed unconditionally.
            let rule = SeccompRule::new(conditions).map_err(|_| ())?;
            map.entry(*nr).or_default().push(rule);
        }
    }
    Ok(map)
}

fn compile(
    rules: Rules,
    mismatch: SeccompAction,
    matched: SeccompAction,
) -> Result<BpfProgram, ()> {
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|_| ())?;
    let filter = SeccompFilter::new(rules, mismatch, matched, arch).map_err(|_| ())?;
    BpfProgram::try_from(filter).map_err(|_| ())
}

fn arch_supported() -> bool {
    TargetArch::try_from(std::env::consts::ARCH).is_ok()
}

/// DE: Installiert die drei Filter (für alle Threads). `Err` nur bei echtem Fehlschlag.
/// EN: Installs the three filters (for all threads). `Err` only on real failure.
pub(super) fn install(profile: &Profile) -> Result<Status, ()> {
    if !arch_supported() {
        return Ok(Status::Unsupported);
    }
    let errno = |e: i32| SeccompAction::Errno(u32::try_from(e).unwrap_or(1));
    let allow = compile(
        rules(&allow_list(profile))?,
        errno(libc::EPERM),
        SeccompAction::Allow,
    )?;
    let deny_entries: Vec<(i64, Vec<Rule>)> = deny_list(profile)
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();
    let deny = compile(
        rules(&deny_entries)?,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
    )?;
    let clone3 = compile(
        rules(&[(libc::SYS_clone3, Vec::new())])?,
        SeccompAction::Allow,
        errno(libc::ENOSYS),
    )?;
    // DE: Erlaubnisliste zuletzt: Danach sind `seccomp` und `prctl(PR_SET_NO_NEW_PRIVS)`
    //     nicht mehr nötig und bleiben verboten.
    // EN: Allow list last: afterwards `seccomp` and `prctl(PR_SET_NO_NEW_PRIVS)` are no
    //     longer needed and stay forbidden.
    for program in [&deny, &clone3, &allow] {
        seccompiler::apply_filter_all_threads(program).map_err(|_| ())?;
    }
    Ok(Status::Full)
}
