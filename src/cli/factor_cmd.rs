//! DE: Faktordatei auf der Kommandozeile (U0-3): `pqkeep factor --out <pfad>` erzeugt sie, die
//! Option `--factor-file <pfad>` nutzt sie bei `generate`, `encrypt`, `decrypt` und `sign`.
//! Übergeben wird immer nur der Pfad – der Inhalt steht nie in Argumenten, Umgebungsvariablen
//! oder Ausgaben. Ohne die Option bleibt alles beim Format v1.
//! EN: Factor file on the command line (U0-3): `pqkeep factor --out <path>` creates it, the
//! option `--factor-file <path>` uses it with `generate`, `encrypt`, `decrypt` and `sign`.
//! Only the path is ever passed – the content never appears in arguments, environment
//! variables or output. Without the option everything stays in format v1.

use std::path::PathBuf;

use clap::{Arg, ArgMatches, Command, value_parser};
use pqkeep::crypto::factor::Factor;
use pqkeep::security::Lang;

use super::args::{base, opt};
use super::io::{CliResult, Failure};

/// DE: Name der Option. EN: Name of the option.
pub const OPTION: &str = "factor-file";
/// DE: Option mit Strichen, für Kindprozesse. EN: Option with dashes, for child processes.
pub const FLAG: &str = "--factor-file";

struct FactorTexts {
    about: &'static str,
    after: &'static str,
    arg_out: &'static str,
    arg_factor: &'static str,
    created: &'static str,
    hint: &'static str,
    needed: &'static str,
}

static DE: FactorTexts = FactorTexts {
    about: "Faktordatei erzeugen (zweiter Faktor zusätzlich zur Passphrase)",
    after: "Beispiele:\n  pqkeep factor --out /media/usb/max.factor\n  pqkeep generate --name \"Max Muster\" --out max.key.json --factor-file /media/usb/max.factor\n  pqkeep encrypt bericht.pdf --factor-file /media/usb/max.factor\n\nDie Faktordatei enthält 32 zufällige Bytes und wird nie überschrieben. Getrennt von Schlüsseldatei und Passphrase aufbewahren (z. B. USB-Stick) und sichern: Ohne sie lässt sich nichts mehr öffnen, was damit geschützt wurde.",
    arg_out: "Zieldatei (wird nie überschrieben)",
    arg_factor: "Faktordatei zusätzlich zur Passphrase (nur der Pfad; erzeugen mit „pqkeep factor“)",
    created: "Faktordatei erzeugt",
    hint: "Wichtig: Faktordatei sichern und getrennt von Schlüsseldatei und Passphrase aufbewahren. Ohne sie lässt sich nichts mehr öffnen, was damit geschützt wurde.",
    needed: "Faktordatei: erforderlich",
};

static EN: FactorTexts = FactorTexts {
    about: "Create a factor file (second factor in addition to the passphrase)",
    after: "Examples:\n  pqkeep factor --out /media/usb/max.factor\n  pqkeep generate --name \"Max Muster\" --out max.key.json --factor-file /media/usb/max.factor\n  pqkeep encrypt report.pdf --factor-file /media/usb/max.factor\n\nThe factor file holds 32 random bytes and is never overwritten. Keep it apart from key file and passphrase (e.g. on a USB stick) and back it up: without it nothing protected with it can be opened again.",
    arg_out: "Target file (never overwritten)",
    arg_factor: "Factor file in addition to the passphrase (path only; create with \"pqkeep factor\")",
    created: "Factor file created",
    hint: "Important: back up the factor file and keep it apart from key file and passphrase. Without it nothing protected with it can be opened again.",
    needed: "Factor file: required",
};

fn texts(lang: Lang) -> &'static FactorTexts {
    if lang == Lang::De { &DE } else { &EN }
}

/// DE: Option `--factor-file <pfad>`. EN: Option `--factor-file <path>`.
pub fn arg(lang: Lang) -> Arg {
    opt(OPTION, texts(lang).arg_factor).value_parser(value_parser!(PathBuf))
}

/// DE: Befehl `factor`. EN: Command `factor`.
pub fn command(lang: Lang) -> Command {
    let s = texts(lang);
    base("factor", s.about, s.after, lang).arg(
        opt("out", s.arg_out)
            .short('o')
            .required(true)
            .value_parser(value_parser!(PathBuf)),
    )
}

/// DE: Pfad aus `--factor-file`; `None` auch bei Befehlen ohne diese Option.
/// EN: Path from `--factor-file`; `None` also for commands without this option.
pub fn path(m: &ArgMatches) -> Option<PathBuf> {
    m.try_get_one::<PathBuf>(OPTION).ok().flatten().cloned()
}

/// DE: Liest die Faktordatei, falls angegeben (vor jeder Passphrase-Abfrage).
/// EN: Reads the factor file if given (before any passphrase prompt).
pub fn load(m: &ArgMatches, lang: Lang) -> CliResult<Option<Factor>> {
    path(m)
        .map(|p| Factor::read(&p).map_err(|e| Failure::from_error(&e, lang)))
        .transpose()
}

/// DE: Zeile für `inspect`: Faktordatei erforderlich. EN: Line for `inspect`: factor file required.
pub fn needed(lang: Lang) -> &'static str {
    texts(lang).needed
}

/// DE: `pqkeep factor`. EN: `pqkeep factor`.
pub fn create(lang: Lang, m: &ArgMatches) -> CliResult {
    let s = texts(lang);
    let out = m.get_one::<PathBuf>("out").cloned().unwrap_or_default();
    Factor::create(&out).map_err(|e| Failure::from_error(&e, lang))?;
    println!("{}: {}", s.created, out.display());
    eprintln!("{}", s.hint);
    Ok(())
}

/// DE: Verständliche Meldung („Deutsch / English“) zu den Faktor-Fehlern der Bibliothek.
/// EN: Understandable message ("Deutsch / English") for the library's factor errors.
pub fn message(field: &str) -> Option<&'static str> {
    Some(match field {
        "factor_required" => {
            "Dafür ist zusätzlich die Faktordatei nötig (--factor-file <Pfad>) / this additionally needs the factor file (--factor-file <path>)"
        }
        "factor_unused" => {
            "Hier wird keine Faktordatei verwendet – bitte --factor-file weglassen / no factor file is used here – please omit --factor-file"
        }
        "factor_permissions" => {
            "Faktordatei ist für andere zugänglich – sie muss Ihnen gehören und darf nur für Sie lesbar sein (chmod 600) / factor file is accessible to others – it must belong to you and be readable by you only (chmod 600)"
        }
        "factor" => {
            "Keine gültige Faktordatei (reguläre Datei mit genau 32 Bytes) / not a valid factor file (regular file with exactly 32 bytes)"
        }
        _ => return None,
    })
}
