//! DE: Plattformteil von `integrate`: Linux schreibt Dateien, Windows Registry-Einträge (HKCU),
//! andere Systeme melden „nicht unterstützt“.
//! EN: Platform part of `integrate`: Linux writes files, Windows registry entries (HKCU), other
//! systems report "not supported".

#[cfg(target_os = "linux")]
pub use super::linux::run;

#[cfg(windows)]
pub use super::windows::run;

#[cfg(not(any(target_os = "linux", windows)))]
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
