//! DE: Gemeinsame Test-Hilfen. Passphrasen werden zur Laufzeit erzeugt (keine Secrets im Repo).
//! EN: Shared test helpers. Passphrases are generated at runtime (no secrets in the repo).

// DE: Hilfsfunktionen sind keine #[test]-Funktionen, unwrap hier bewusst erlaubt.
// EN: Helpers are not #[test] functions; unwrap deliberately allowed here.
#![allow(dead_code, clippy::unwrap_used)]

use pqc_keyforge::crypto::kdf::{self, KdfParams};
use pqc_keyforge::crypto::rng;
use pqc_keyforge::security::{Passphrase, StrongPassphrase, generator};

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
    algorithm: pqc_keyforge::crypto::KeyAlgorithm,
) -> (pqc_keyforge::envelope::KeyFile, StrongPassphrase) {
    let pass = random_passphrase();
    let meta = pqc_keyforge::envelope::Metadata {
        name: "Test User".to_owned(),
        organization: Some("Example Org".to_owned()),
        company: None,
        department: Some("IT-Sicherheit".to_owned()),
        account_type: Some("service".to_owned()),
    };
    let file =
        pqc_keyforge::envelope::KeyFile::generate(&pass, algorithm, &meta, &min_params()).unwrap();
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
