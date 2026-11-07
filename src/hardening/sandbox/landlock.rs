//! DE: Landlock-Regeln je Profil (Best Effort: ältere Kernel setzen nur einen Teil um).
//! EN: Landlock rules per profile (best effort: older kernels enforce only a part).

use landlock::{ABI, Access, AccessFs, AccessNet, RulesetAttr, RulesetStatus, Scope};

use super::{Profile, Status};

/// DE: Höchste ABI, die wir anfordern; ältere Kernel erfüllen den unterstützten Teil.
/// EN: Highest ABI we request; older kernels enforce the supported part.
const TARGET_ABI: ABI = ABI::V6;

/// DE: Schränkt den aufrufenden Thread ein. EN: Restricts the calling thread.
pub(super) fn restrict(profile: Profile) -> Status {
    match profile {
        // DE: API: keinerlei Dateizugriff, kein TCP-Bind/-Connect, keine Signale oder
        //     abstrakten Unix-Sockets außerhalb der Sandbox (keine Regeln = alles verboten).
        // EN: API: no file access at all, no TCP bind/connect, no signals or abstract
        //     Unix sockets outside the sandbox (no rules = everything denied).
        Profile::Api => deny_all(),
    }
}

fn deny_all() -> Status {
    let result = landlock::Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .and_then(|r| r.handle_access(AccessNet::from_all(TARGET_ABI)))
        .and_then(|r| r.scope(Scope::from_all(TARGET_ABI)))
        .and_then(landlock::Ruleset::create)
        .and_then(landlock::RulesetCreated::restrict_self);
    match result.map(|s| s.ruleset) {
        Ok(RulesetStatus::FullyEnforced) => Status::Full,
        Ok(RulesetStatus::PartiallyEnforced) => Status::Partial,
        Ok(RulesetStatus::NotEnforced) | Err(_) => Status::Unsupported,
    }
}
