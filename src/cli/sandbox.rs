//! DE: Sandbox in der CLI: Aktivieren mit Statusmeldungen und `--no-sandbox` mit
//! deutlicher Warnung (Risiken) und – im Terminal – Rückfrage (Standard: Nein).
//! EN: Sandbox in the CLI: enabling with status messages and `--no-sandbox` with a
//! clear warning (risks) and – in a terminal – confirmation (default: no).

use std::io::IsTerminal;

use dialoguer::Confirm;
use pqc_keyforge::hardening::sandbox::{self, Profile, SandboxReport, Status};
use pqc_keyforge::security::Lang;

use super::io::{CliResult, Failure, code};

struct SandboxTexts {
    arg_no_sandbox: &'static str,
    warning: &'static str,
    prompt: &'static str,
    aborted: &'static str,
    landlock_missing: &'static str,
    seccomp_missing: &'static str,
    status: &'static str,
}

static DE: SandboxTexts = SandboxTexts {
    arg_no_sandbox: "Sandbox (Landlock/Seccomp) abschalten – NUR zur Fehlersuche, erhebliches Risiko (siehe Warnung)",
    warning: "WARNUNG: --no-sandbox schaltet die Sandbox (Landlock und Seccomp) ab.\n\
Risiken:\n  \
- Eine Sicherheitslücke in keyforge oder einer Bibliothek (z. B. im JSON-, HTTP- oder\n    \
Archiv-Parser) kann dann auf ALLE Ihre Dateien zugreifen, sie verändern oder löschen.\n  \
- Eingeschleuster Code kann Programme starten und Netzwerkverbindungen aufbauen –\n    \
also Schlüssel und Passphrasen unbemerkt nach außen senden.\n  \
- Bei der API (keyforge serve) ist das Risiko am größten, weil sie Eingaben von\n    \
anderen Programmen oder aus dem Netz verarbeitet.\n\
Nur verwenden, wenn keyforge mit Sandbox nicht startet – und das Problem bitte melden.",
    prompt: "Trotzdem OHNE Sandbox fortfahren?",
    aborted: "Abgebrochen – keyforge läuft nicht ohne Sandbox.",
    landlock_missing: "WARNUNG: Landlock ist auf diesem System nicht verfügbar (Kernel zu alt oder abgeschaltet). Dateizugriffe sind nicht eingeschränkt; Seccomp bleibt aktiv.",
    seccomp_missing: "WARNUNG: Seccomp-Filter werden auf dieser Architektur nicht unterstützt (nur x86_64/aarch64). Systemaufrufe sind nicht eingeschränkt.",
    status: "Sandbox",
};

static EN: SandboxTexts = SandboxTexts {
    arg_no_sandbox: "Disable the sandbox (Landlock/seccomp) – ONLY for troubleshooting, considerable risk (see warning)",
    warning: "WARNING: --no-sandbox disables the sandbox (Landlock and seccomp).\n\
Risks:\n  \
- A vulnerability in keyforge or a library (e.g. in the JSON, HTTP or archive parser)\n    \
can then access, modify or delete ALL of your files.\n  \
- Injected code can start programs and open network connections – i.e. send keys\n    \
and passphrases out unnoticed.\n  \
- The risk is highest for the API (keyforge serve), because it processes input from\n    \
other programs or the network.\n\
Only use it if keyforge does not start with the sandbox – and please report the problem.",
    prompt: "Continue WITHOUT the sandbox anyway?",
    aborted: "Aborted – keyforge does not run without the sandbox.",
    landlock_missing: "WARNING: Landlock is not available on this system (kernel too old or disabled). File access is not restricted; seccomp stays active.",
    seccomp_missing: "WARNING: seccomp filters are not supported on this architecture (x86_64/aarch64 only). System calls are not restricted.",
    status: "Sandbox",
};

fn texts(lang: Lang) -> &'static SandboxTexts {
    match lang {
        Lang::De => &DE,
        Lang::En => &EN,
    }
}

/// DE: Hilfetext der Option `--no-sandbox`. EN: Help text of the `--no-sandbox` option.
pub fn arg_help(lang: Lang) -> &'static str {
    texts(lang).arg_no_sandbox
}

/// DE: Warnt vor `--no-sandbox` und fragt im Terminal nach (Standard: Nein).
/// Ohne Terminal (Skripte) bleibt es bei der Warnung.
/// EN: Warns about `--no-sandbox` and asks in a terminal (default: no).
/// Without a terminal (scripts) only the warning is shown.
pub fn confirm_disabled(lang: Lang) -> CliResult {
    let s = texts(lang);
    eprintln!("{}", s.warning);
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return Ok(());
    }
    let ok = Confirm::new()
        .with_prompt(s.prompt)
        .default(false)
        .interact()
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Failure::new(code::USAGE, s.aborted))
    }
}

/// DE: Aktiviert die Sandbox (außer bei `--no-sandbox`) und meldet fehlende Schichten.
/// EN: Enables the sandbox (unless `--no-sandbox`) and reports missing layers.
pub fn enable(profile: &Profile, enabled: bool, verbose: bool, lang: Lang) -> CliResult {
    let s = texts(lang);
    let report = if enabled {
        sandbox::apply(profile).map_err(|e| Failure::from_error(&e, lang))?
    } else {
        SandboxReport::disabled()
    };
    let linux = cfg!(target_os = "linux");
    if enabled && linux && report.landlock == Status::Unsupported {
        eprintln!("{}", s.landlock_missing);
    }
    if enabled && linux && report.seccomp == Status::Unsupported {
        eprintln!("{}", s.seccomp_missing);
    }
    if verbose {
        eprintln!(
            "{}: landlock={} seccomp={}",
            s.status,
            report.landlock.as_str(),
            report.seccomp.as_str()
        );
    }
    Ok(())
}
