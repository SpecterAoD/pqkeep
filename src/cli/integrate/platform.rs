//! DE: Plattformteil von `integrate`: Linux schreibt Einträge, andere Systeme melden „noch nicht
//! unterstützt“ (Windows folgt mit U4-2).
//! EN: Platform part of `integrate`: Linux writes entries, other systems report "not yet
//! supported" (Windows follows with U4-2).

#[cfg(target_os = "linux")]
pub use super::linux::run;

#[cfg(not(target_os = "linux"))]
pub fn run(
    _action: &str,
    _opts: &super::Options,
    lang: pqkeep::security::Lang,
) -> super::super::io::CliResult {
    let s = super::super::integrate_text::integrate_texts(lang);
    Err(super::super::io::Failure::new(
        super::super::io::code::ERROR,
        s.msg_unsupported,
    ))
}
