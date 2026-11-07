//! DE: Befehle zu Passphrasen: validate (prüfen) und passphrase (erzeugen).
//! EN: Passphrase commands: validate (check) and passphrase (generate).

use clap::ArgMatches;
use pqc_keyforge::security::generator::{self, Options};
use pqc_keyforge::security::{Lang, Rejection};

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

/// DE: `keyforge validate`. EN: `keyforge validate`.
pub fn validate(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let pass = read_passphrase(t, lang, m.get_flag("passphrase-stdin"), false)?;
    let assessment = pass.assess();
    drop(pass);
    if assessment.is_strong() {
        println!("{}", t.msg_strong);
        println!("{}: {}", t.msg_entropy, assessment.entropy_bits.floor());
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

/// DE: `keyforge passphrase`: nur die Passphrase auf Stdout, Hinweise auf Stderr.
/// EN: `keyforge passphrase`: only the passphrase on stdout, notes on stderr.
pub fn passphrase(t: &Texts, lang: Lang, m: &ArgMatches) -> CliResult {
    let options = Options {
        length: m
            .get_one::<usize>("length")
            .copied()
            .unwrap_or(generator::DEFAULT_LEN),
        exclude_ambiguous: m.get_flag("no-ambiguous"),
    };
    let generated = generator::generate(&options).map_err(|e| Failure::from_error(&e, lang))?;
    println!("{}", generated.as_ref().expose_str());
    eprintln!("{}: {}", t.msg_entropy, options.entropy_bits().floor());
    eprintln!("{}", t.msg_generated_hint);
    Ok(())
}
