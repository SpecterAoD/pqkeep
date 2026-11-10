//! DE: Befehle zu Passphrasen: validate (prüfen) und passphrase (erzeugen).
//! EN: Passphrase commands: validate (check) and passphrase (generate).

use clap::ArgMatches;
use pqkeep::security::generator::{self, Options};
use pqkeep::security::{Lang, MIN_BITS, MIN_ENTROPY_BITS, Passphrase, Rejection, StrongPassphrase};

use super::io::{CliResult, Failure, code, read_passphrase};
use super::text::Texts;

/// DE: Gibt alle Ablehnungsgründe aus. EN: Prints all rejection reasons.
pub fn print_rejection(t: &Texts, lang: Lang, rejection: &Rejection) {
    eprintln!("{}", t.msg_rejected);
    for reason in &rejection.reasons {
        eprintln!("  - {}", reason.message(lang));
    }
    eprintln!("{}: {}", t.msg_entropy, rejection.entropy_bits.floor());
}

/// DE: Gewählter Mindestwert (`--min-bits`, sonst 128). EN: Chosen minimum (`--min-bits`, else 128).
fn min_bits(m: &ArgMatches) -> u32 {
    m.try_get_one::<u32>("min-bits")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(MIN_BITS)
}

/// DE: Neue Passphrase mit dem gewählten Mindestwert prüfen. EN: Check a new passphrase.
pub(super) fn strong(m: &ArgMatches, pass: Passphrase) -> Result<StrongPassphrase, Rejection> {
    StrongPassphrase::with_min_bits(pass, min_bits(m))
}

/// DE: Einstufung: unter 128 zu schwach, ab 128 gut, ab 192 sehr stark.
/// EN: Rating: below 128 too weak, from 128 good, from 192 very strong.
pub(super) fn rating(t: &Texts, bits: f64) -> &'static str {
    if bits >= 192.0 {
        t.rate_strong
    } else if bits >= MIN_ENTROPY_BITS {
        t.rate_good
    } else {
        t.rate_weak
    }
}

/// DE: `pqkeep validate`. EN: `pqkeep validate`.
pub fn validate(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let pass = read_passphrase(t, lang, m.get_flag("passphrase-stdin"), false)?;
    let assessment = pass.assess_with(min_bits(m));
    drop(pass);
    if assessment.is_strong() {
        println!("{}", t.msg_strong);
        let bits = assessment.entropy_bits;
        println!("{}: {} – {}", t.msg_entropy, bits.floor(), rating(t, bits));
        Ok(())
    } else {
        print_rejection(
            t,
            lang,
            &Rejection {
                reasons: assessment.reasons,
                entropy_bits: assessment.entropy_bits,
            },
        );
        Err(Failure::new(code::WEAK, ""))
    }
}

/// DE: `pqkeep passphrase`: nur die Passphrase auf Stdout, Hinweise auf Stderr.
/// EN: `pqkeep passphrase`: only the passphrase on stdout, notes on stderr.
pub fn passphrase(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let options = Options {
        length: m
            .get_one::<usize>("count")
            .or_else(|| m.get_one::<usize>("length"))
            .copied()
            .unwrap_or(generator::DEFAULT_LEN),
        exclude_ambiguous: m.get_flag("no-ambiguous"),
    };
    let bits = min_bits(m);
    let needed = generator::min_len(bits);
    if (generator::MIN_LEN..needed).contains(&options.length) {
        return Err(Failure::new(
            code::USAGE,
            format!("{} {needed}", t.msg_pass_too_short),
        ));
    }
    let generated =
        generator::generate_with(&options, bits).map_err(|e| Failure::from_error(&e, lang))?;
    println!("{}", generated.as_ref().expose_str());
    // DE: Anzeige wie bei `validate` (vorsichtige Schätzung der Prüfung, nicht der Formelwert).
    // EN: Shown as `validate` does (the check's conservative estimate, not the formula value).
    let bits = generated.entropy_bits();
    eprintln!("{}: {} – {}", t.msg_entropy, bits.floor(), rating(t, bits));
    eprintln!("{}", t.msg_generated_hint);
    Ok(())
}
