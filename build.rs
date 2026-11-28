//! DE: Öffentliche Unicode-Falttabelle ohne private Laufzeit-Eingaben erzeugen.
//! EN: Generate a public Unicode folding table without private runtime inputs.
use std::{env, error::Error, fmt::Write, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    let mut table = String::from("static FOLD: &[(u32, &[u8])] = &[\n");
    for scalar in 0..=0x0010_ffff {
        let Some(c) = char::from_u32(scalar) else {
            continue;
        };
        // DE: Nur öffentliche Skalare; privates ToLowercase-Scratch entfällt zur Laufzeit.
        // EN: Public scalars only; runtime needs no private ToLowercase scratch.
        let folded: String = c
            .to_lowercase()
            .map(|v| if v == 'ς' { 'σ' } else { v })
            .collect();
        if !folded.chars().eq(std::iter::once(c)) {
            writeln!(
                table,
                "(0x{:04x}_{:04x}, &{:?}),",
                scalar >> 16,
                scalar & 0xffff,
                folded.as_bytes()
            )?;
        }
    }
    table.push_str("];\n");
    let destination = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    fs::write(destination.join("unicode_fold.rs"), table)?;
    Ok(())
}
