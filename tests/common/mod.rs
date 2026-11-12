//! DE: Gemeinsame Test-Hilfen. Passphrasen werden zur Laufzeit erzeugt (keine Secrets im Repo).
//! EN: Shared test helpers. Passphrases are generated at runtime (no secrets in the repo).

// DE: Hilfsfunktionen sind keine #[test]-Funktionen, unwrap hier bewusst erlaubt.
// EN: Helpers are not #[test] functions; unwrap deliberately allowed here.
#![allow(dead_code, clippy::unwrap_used)]

pub mod fake_dialog;
pub mod v2_files;
pub mod v2_header;

use pqkeep::crypto::kdf::{self, KdfParams};
use pqkeep::crypto::rng;
use pqkeep::security::{Passphrase, StrongPassphrase, generator};

/// DE: Kleinste zulässige Parameter (schnellster gültiger Fall).
/// EN: Smallest permitted parameters (fastest valid case).
pub fn min_params() -> KdfParams {
    KdfParams {
        memory_kib: kdf::MIN_MEMORY_KIB,
        iterations: kdf::MIN_ITERATIONS,
        parallelism: kdf::auto_parallelism(),
    }
}

/// DE: Zufällige starke Passphrase aus dem Generator.
/// EN: Random strong passphrase from the generator.
pub fn random_passphrase() -> StrongPassphrase {
    generator::generate(&generator::Options::default()).unwrap()
}

/// DE: Zufällige Bytes als KDF-Eingabe (48 Hex-Zeichen).
/// EN: Random bytes as KDF input (48 hex characters).
pub fn random_secret() -> Vec<u8> {
    let raw = rng::array::<24>().unwrap();
    hex::encode(raw).into_bytes()
}

/// DE: Normalisierte Passphrase aus Text (für Varianten in Negativtests).
/// EN: Normalised passphrase from text (for variants in negative tests).
pub fn passphrase(text: &str) -> Passphrase {
    Passphrase::new(text).unwrap()
}

/// DE: Kopie mit einem gekippten Bit an Position `i`. EN: Copy with one flipped bit at `i`.
pub fn flip(data: &[u8], i: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out[i] ^= 0x01;
    out
}

/// DE: Schlüsseldatei mit Minimalparametern; liefert Datei und Passphrase.
/// EN: Key file with minimal parameters; returns file and passphrase.
pub fn key_file(
    algorithm: pqkeep::crypto::KeyAlgorithm,
) -> (pqkeep::envelope::KeyFile, StrongPassphrase) {
    let pass = random_passphrase();
    let meta = pqkeep::envelope::Metadata {
        name: "Test User".to_owned(),
        organization: Some("Example Org".to_owned()),
        company: None,
        department: Some("IT-Sicherheit".to_owned()),
        account_type: Some("service".to_owned()),
    };
    let file = pqkeep::envelope::KeyFile::generate(&pass, algorithm, &meta, &min_params()).unwrap();
    (file, pass)
}

/// DE: Liest einen Ordnerbaum: relativer Pfad → Inhalt (None = Ordner).
/// EN: Reads a directory tree: relative path → content (None = directory).
pub fn read_tree(root: &std::path::Path) -> std::collections::BTreeMap<String, Option<Vec<u8>>> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let rel = format!("{prefix}{}", entry.file_name().to_str().unwrap());
            if entry.file_type().unwrap().is_dir() {
                out.insert(rel.clone(), None);
                stack.push((entry.path(), format!("{rel}/")));
            } else {
                out.insert(rel, Some(std::fs::read(entry.path()).unwrap()));
            }
        }
    }
    out
}

/// DE: Beispielbaum mit Unterordnern, leerem Ordner, Unicode und größerer Datei.
/// EN: Sample tree with subdirectories, empty directory, Unicode and a larger file.
pub fn write_sample_tree(root: &std::path::Path) {
    let dirs = ["Dokumente", "Dokumente/Prüfung 2026", "leer", "日本語"];
    for d in dirs {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    let big: Vec<u8> = (0..200_000u32)
        .map(|i| u8::try_from(i % 253).unwrap())
        .collect();
    let files: [(&str, &[u8]); 5] = [
        ("Dokumente/Bericht.txt", b"Inhalt / content"),
        ("Dokumente/Prüfung 2026/Größe.bin", &big),
        ("Dokumente/leer.txt", b""),
        ("日本語/ファイル.md", "テキスト".as_bytes()),
        ("wurzel.txt", b"root"),
    ];
    for (path, data) in files {
        std::fs::write(root.join(path), data).unwrap();
    }
}

/// DE: Namen aller Einträge eines Ordners (für „keine Reste“-Prüfungen).
/// EN: Names of all entries of a directory (for "no leftovers" checks).
pub fn dir_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// DE: Führt `pqkeep` aus (Stdin als Text). EN: Runs `pqkeep` (stdin as text).
/// Rückgabe / returns: (Exit-Code, Stdout, Stderr).
pub fn pqkeep(args: &[&str], stdin: &str, cwd: &std::path::Path) -> (i32, String, String) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_pqkeep"))
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // DE: Beendet sich pqkeep vor dem Lesen (z. B. Ziel existiert), ist die Pipe zu –
    //     das ist kein Testfehler (früher sporadisch „Broken pipe“).
    // EN: If pqkeep exits before reading (e.g. target exists), the pipe is closed –
    //     not a test failure (used to fail sporadically with "broken pipe").
    if let Err(e) = child.stdin.take().unwrap().write_all(stdin.as_bytes()) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// DE: Fachbegriffe aus Hilfetexten, die formal die Passphrase-Regeln erfüllen, aber
/// keine Geheimnisse sind (zeigt zugleich die Grenze der Heuristik, siehe
/// `docs/SECURITY_PASSPHRASE.md`). Bewusst kurz und sichtbar gehalten.
/// EN: Technical terms from help texts that formally meet the passphrase rules but
/// are not secrets (also shows the heuristic's limit). Kept short and visible.
pub const HELP_TERMS: [&str; 1] = ["FIPS-140-validiert"];

/// DE: Prüft, dass kein Wort eines Hilfetexts die Passphrase-Regeln erfüllt.
/// EN: Checks that no word of a help text meets the passphrase rules.
pub fn assert_no_secret_like_words(text: &str, context: &str) {
    let edge = |c: char| ".,:;!?()[]\"'„“<>".contains(c);
    for word in text.split_whitespace().map(|w| w.trim_matches(edge)) {
        if word.is_empty() || HELP_TERMS.contains(&word) {
            continue;
        }
        let strong = StrongPassphrase::try_from(Passphrase::new(word).unwrap());
        assert!(strong.is_err(), "{context}: {word}");
    }
}
