//! DE: Geführtes Erstellen eines Schlüssels: Zweck → Stärke → Angaben → Schutzprofil →
//! Passphrase → Dateien → Zusammenfassung mit entsprechenden Befehlen → Ausführung.
//! EN: Guided key creation: purpose → strength → details → protection profile → passphrase →
//! files → summary with corresponding commands → execution.

use std::path::Path;

use pqkeep::security::{Lang, MIN_BITS, generator};

use super::levels::{Level, Purpose, for_purpose};
use super::text::{GuideTexts, guide_texts};
use super::{child, command_line, confirm, input, select};
use crate::cli::io::{CliResult, Failure, code};

/// DE: Alle Antworten des Ablaufs. EN: All answers of the flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPlan {
    pub algorithm: &'static str,
    pub name: String,
    pub details: Details,
    pub hardened: bool,
    pub min_bits: u32,
    /// DE: Länge der erzeugten Passphrase; `None` = eigene. EN: Generated length; `None` = own.
    pub pass_len: Option<usize>,
    pub out: String,
    pub export: Option<String>,
}

impl KeyPlan {
    /// DE: Argumente für `pqkeep passphrase`. EN: Arguments for `pqkeep passphrase`.
    pub fn passphrase_args(&self) -> Option<Vec<String>> {
        let mut a = vec!["passphrase".to_owned(), self.pass_len?.to_string()];
        if self.min_bits > MIN_BITS {
            a.extend(["--min-bits".to_owned(), self.min_bits.to_string()]);
        }
        Some(a)
    }

    /// DE: Argumente für `pqkeep generate`. EN: Arguments for `pqkeep generate`.
    pub fn generate_args(&self) -> Vec<String> {
        let mut a: Vec<String> = ["generate", "--algorithm", self.algorithm, "--name"]
            .map(str::to_owned)
            .to_vec();
        a.push(self.name.clone());
        for (flag, value) in &self.details {
            if let Some(v) = value {
                a.extend([format!("--{flag}"), v.clone()]);
            }
        }
        if self.hardened {
            a.extend(["--profile".to_owned(), "hardened".to_owned()]);
        }
        if self.min_bits > MIN_BITS {
            a.extend(["--min-bits".to_owned(), self.min_bits.to_string()]);
        }
        a.extend(["--out".to_owned(), self.out.clone()]);
        a
    }

    /// DE: Argumente für `pqkeep export`. EN: Arguments for `pqkeep export`.
    pub fn export_args(&self) -> Option<Vec<String>> {
        let public = self.export.clone()?;
        Some(vec![
            "export".to_owned(),
            self.out.clone(),
            "--out".to_owned(),
            public,
        ])
    }

    /// DE: Alle Befehle in Reihenfolge. EN: All commands in order.
    pub fn commands(&self) -> Vec<Vec<String>> {
        let mut all: Vec<Vec<String>> = self.passphrase_args().into_iter().collect();
        all.push(self.generate_args());
        all.extend(self.export_args());
        all
    }
}

/// DE: Dateiname aus dem Namen (Kleinbuchstaben, Bindestriche), im Ordner `dir` frei
/// (`anna.key.json`, sonst `anna-2.key.json` …). EN: File name from the name, free in `dir`.
pub fn suggest(dir: &Path, name: &str, suffix: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let slug = slug
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = if slug.is_empty() {
        "pqkeep".to_owned()
    } else {
        slug
    };
    let first = format!("{base}{suffix}");
    std::iter::once(first.clone())
        .chain((2..100).map(|n| format!("{base}-{n}{suffix}")))
        .find(|f| !dir.join(f).exists())
        .unwrap_or(first)
}

fn ask_level(g: &GuideTexts, lang: Lang, preset: Option<Purpose>) -> CliResult<Level> {
    let purpose = if let Some(p) = preset {
        p
    } else {
        let items: Vec<&str> = g.purposes.split('|').collect();
        [Purpose::Encrypt, Purpose::Sign, Purpose::Symmetric][select(g.purpose, &items, 0)?]
    };
    // DE: Vorgabe (aus „Datei signieren“): nur die Stufe, die `pqkeep sign` nutzt.
    // EN: Preset (from "sign a file"): only the level `pqkeep sign` uses.
    let levels: Vec<Level> = for_purpose(purpose)
        .into_iter()
        .filter(|l| preset.is_none() || l.recommended)
        .collect();
    if let [only] = levels.as_slice() {
        eprintln!("{}", only.label(lang));
        return Ok(*only);
    }
    let labels: Vec<String> = levels.iter().map(|l| l.label(lang)).collect();
    Ok(levels[select(g.level, &labels, 0)?])
}

/// DE: Optionale Angaben als (Option, Wert). EN: Optional details as (option, value).
type Details = [(&'static str, Option<String>); 4];

fn ask_details(g: &GuideTexts) -> CliResult<(String, Details)> {
    eprintln!("{}", g.details);
    let name = input(g.name, None, false)?.trim().to_owned();
    let mut details = [
        ("organization", None),
        ("company", None),
        ("department", None),
        ("account-type", None),
    ];
    let prompts = [g.organization, g.company, g.department, g.account_type];
    for (slot, prompt) in details.iter_mut().zip(prompts) {
        let value = input(&format!("{prompt} ({})", g.optional), None, true)?;
        slot.1 = Some(value.trim().to_owned()).filter(|v| !v.is_empty());
    }
    Ok((name, details))
}

fn ask_files(g: &GuideTexts, name: &str, purpose: Purpose) -> CliResult<(String, Option<String>)> {
    let out = loop {
        let out = input(
            g.out_file,
            Some(&suggest(Path::new("."), name, ".key.json")),
            false,
        )?;
        if !Path::new(&out).exists() {
            break out;
        }
        eprintln!("{}", g.exists);
    };
    let export = if purpose != Purpose::Symmetric && confirm(g.export, true)? {
        Some(input(
            g.pub_file,
            Some(&suggest(Path::new("."), name, ".pub.json")),
            false,
        )?)
    } else {
        None
    };
    Ok((out, export))
}

/// DE: Fragt alles ab und liefert den Plan (ohne Ausführung). EN: Asks everything, returns the plan.
fn ask(lang: Lang, preset: Option<Purpose>) -> CliResult<KeyPlan> {
    let g = guide_texts(lang);
    eprintln!("\n{}\n", g.keygen_title);
    let level = ask_level(g, lang, preset)?;
    let (name, details) = ask_details(g)?;
    let profiles: Vec<&str> = g.profiles.split('|').collect();
    let hardened = select(g.profile, &profiles, 0)? == 1;
    let strengths: Vec<&str> = g.min_bits_items.split('|').collect();
    let min_bits = [128, 192, 256][select(g.min_bits, &strengths, 0)?];
    let modes: Vec<&str> = g.pass_items.split('|').collect();
    let pass_len = if select(g.pass, &modes, 0)? == 0 {
        // DE: Länge passend zur Mindeststärke (128 → 24–256, Vorgabe 32; 192 → ab 36; 256 → ab 48).
        // EN: Length matching the minimum strength (128 → 24–256, default 32; 192 → from 36; …).
        let least = generator::min_len(min_bits);
        let default = (least + 4).max(generator::DEFAULT_LEN);
        let prompt = format!("{} ({least}–{})", g.pass_len, generator::MAX_LEN);
        let len = input(&prompt, Some(&default.to_string()), false)?;
        let len = len.trim().parse::<usize>().unwrap_or(default);
        Some(len.clamp(least, generator::MAX_LEN))
    } else {
        None
    };
    let (out, export) = ask_files(g, &name, level.purpose)?;
    Ok(KeyPlan {
        algorithm: level.id,
        name,
        details,
        hardened,
        min_bits,
        pass_len,
        out,
        export,
    })
}

fn show(g: &GuideTexts, plan: &KeyPlan) {
    eprintln!("\n{}:", g.summary);
    eprintln!("  {}  ·  {}", plan.algorithm.to_uppercase(), plan.name);
    for (flag, value) in &plan.details {
        if let Some(v) = value {
            eprintln!("  {flag}: {v}");
        }
    }
    let pass = plan
        .pass_len
        .map_or(g.own.to_owned(), |n| format!("{} ({n})", g.generated));
    eprintln!(
        "  ≥ {} Bit · {pass} · {}",
        plan.min_bits,
        if plan.hardened {
            "hardened"
        } else {
            "standard"
        }
    );
    eprintln!(
        "  → {}{}",
        plan.out,
        plan.export
            .as_deref()
            .map(|p| format!(", {p}"))
            .unwrap_or_default()
    );
    eprintln!("\n{}", g.equivalent);
    for cmd in plan.commands() {
        eprintln!("  {}", command_line(&cmd));
    }
    eprintln!();
}

/// DE: Exit-Code eines Kindprozesses als Ergebnis (der Kindprozess hat den Fehler schon gemeldet).
/// EN: A child's exit code as a result (the child has already reported the error).
fn succeed(exit: i32) -> CliResult {
    match exit {
        0 => Ok(()),
        c => Err(Failure::new(u8::try_from(c).unwrap_or(code::ERROR), "")),
    }
}

/// DE: Geführtes Erstellen; liefert den ausgeführten Plan. EN: Guided creation; returns the plan.
pub fn run(lang: Lang, preset: Option<Purpose>) -> CliResult<KeyPlan> {
    let g = guide_texts(lang);
    let plan = ask(lang, preset)?;
    show(g, &plan);
    if !confirm(g.confirm, true)? {
        return Err(super::cancelled());
    }
    if let Some(args) = plan.passphrase_args() {
        succeed(child(lang, &args)?)?;
        eprintln!("{}", g.pass_save);
    }
    loop {
        match child(lang, &plan.generate_args())? {
            0 => break,
            c if c == i32::from(code::WEAK) && confirm(g.retry, true)? => {}
            c => return succeed(c).map(|()| plan),
        }
    }
    if let Some(args) = plan.export_args() {
        succeed(child(lang, &args)?)?;
    }
    eprintln!("{}", g.done);
    Ok(plan)
}

#[cfg(test)]
#[path = "keygen_tests.rs"]
mod keygen_tests;
