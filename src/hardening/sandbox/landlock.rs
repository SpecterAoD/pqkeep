//! DE: Landlock-Regeln je Profil (Best Effort: ältere Kernel setzen nur einen Teil um).
//! Ohne Regel ist ein Zugriff verboten; erlaubt wird nur, was das Profil nennt.
//! EN: Landlock rules per profile (best effort: older kernels enforce only a part).
//! Without a rule access is denied; only what the profile names is allowed.

use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus, Scope, make_bitflags,
};

use super::{CliAccess, Profile, Status};

/// DE: Höchste ABI, die wir anfordern; ältere Kernel erfüllen den unterstützten Teil.
/// EN: Highest ABI we request; older kernels enforce the supported part.
const TARGET_ABI: ABI = ABI::V6;

/// DE: Lesen (Datei bzw. Ordner rekursiv). EN: Read (file or directory recursively).
const READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{ReadFile | ReadDir});

/// DE: Zielordner: Dateien/Ordner anlegen, schreiben, umbenennen, entfernen (für
/// Temporärdateien und atomares Veröffentlichen). Keine Geräte, Pipes, Sockets,
/// Symlinks, kein Ausführen.
/// EN: Target directory: create, write, rename, remove files/directories (for
/// temporary files and atomic publishing). No devices, pipes, sockets, symlinks,
/// no execution.
const WRITE_DIR: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    ReadFile | ReadDir | WriteFile | RemoveDir | RemoveFile | MakeDir | MakeReg | Refer | Truncate
});

/// DE: Terminal für verdeckte Eingabe. EN: Terminal for hidden input.
const TTY: BitFlags<AccessFs> = make_bitflags!(AccessFs::{ReadFile | WriteFile | IoctlDev});

/// DE: Schränkt den aufrufenden Thread ein; `Err` bei echtem Fehler (z. B. Pfad
/// nicht zu öffnen) – dann bricht der Aufrufer ab statt ungeschützt weiterzulaufen.
/// EN: Restricts the calling thread; `Err` on a real failure (e.g. path cannot be
/// opened) – the caller then aborts instead of continuing unprotected.
pub(super) fn restrict(profile: &Profile) -> Result<Status, ()> {
    let ruleset = base().map_err(|_| ())?;
    let ruleset = match profile {
        // DE: API: keinerlei Dateizugriff. EN: API: no file access at all.
        Profile::Api => ruleset,
        Profile::Cli(access) => cli_rules(ruleset, access)?,
    };
    let status = ruleset.restrict_self().map_err(|_| ())?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => Status::Full,
        RulesetStatus::PartiallyEnforced => Status::Partial,
        RulesetStatus::NotEnforced => Status::Unsupported,
    })
}

/// DE: Alles verbieten: Dateien, TCP-Bind/-Connect, Signale und abstrakte
/// Unix-Sockets außerhalb der Sandbox.
/// EN: Deny everything: files, TCP bind/connect, signals and abstract Unix sockets
/// outside the sandbox.
fn base() -> Result<RulesetCreated, RulesetError> {
    Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))?
        .handle_access(AccessNet::from_all(TARGET_ABI))?
        .scope(Scope::from_all(TARGET_ABI))?
        .create()
}

fn rule(path: &Path, access: BitFlags<AccessFs>) -> Result<PathBeneath<PathFd>, ()> {
    let fd = PathFd::new(path).map_err(|_| ())?;
    // DE: Für Dateien nur dateibezogene Rechte (sonst lehnt der Kernel ab).
    // EN: For files only file-related rights (the kernel rejects others).
    let access = if path.is_dir() {
        access
    } else {
        access & AccessFs::from_file(TARGET_ABI)
    };
    Ok(PathBeneath::new(fd, access))
}

fn cli_rules(mut ruleset: RulesetCreated, access: &CliAccess) -> Result<RulesetCreated, ()> {
    for path in &access.read {
        ruleset = ruleset.add_rule(rule(path, READ)?).map_err(|_| ())?;
    }
    for dir in &access.write_dirs {
        ruleset = ruleset.add_rule(rule(dir, WRITE_DIR)?).map_err(|_| ())?;
    }
    // DE: Geräte sind optional (z. B. kein Terminal in CI). EN: Devices are optional.
    for (device, rights) in [("/dev/tty", TTY), ("/dev/urandom", READ)] {
        if let Ok(r) = rule(Path::new(device), rights) {
            ruleset = ruleset.add_rule(r).map_err(|_| ())?;
        }
    }
    Ok(ruleset)
}
