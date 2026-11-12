//! DE: Hilfen für Tests des Ver-/Entschlüsselns im Format v2: Schlüssel, Faktordatei, Quelle und
//! ein Entschlüsselversuch, der bei Fehlern prüft, dass nichts zurückbleibt.
//! EN: Helpers for tests of encrypting/decrypting in format v2: keys, factor file, source and a
//! decryption attempt that checks nothing is left behind on errors.

use std::path::{Path, PathBuf};

use pqkeep::Error;
use pqkeep::crypto::factor::{FACTOR_LEN, Factor};
use pqkeep::crypto::rng;
use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{PublicKeyFile, UnlockedKey};
use pqkeep::files::{self, HeaderV2, Unlock};

pub const KEMS: [KemAlgorithm; 3] = [
    KemAlgorithm::MlKem512,
    KemAlgorithm::MlKem768,
    KemAlgorithm::MlKem1024,
];
pub const CONTENT: &[u8] = b"Inhalt der Testdatei / content of the test file\n";

/// DE: Öffentlicher und entsperrter ML-KEM-Schlüssel. EN: Public and unlocked ML-KEM key.
pub fn kem_key(algorithm: KemAlgorithm) -> (PublicKeyFile, UnlockedKey) {
    let (file, pass) = super::key_file(KeyAlgorithm::Kem(algorithm));
    (
        file.public_part().unwrap(),
        file.unlock(pass.as_ref()).unwrap(),
    )
}

/// DE: Zufälliger Faktor (wie der Inhalt einer Faktordatei). EN: Random factor.
pub fn factor() -> Factor {
    Factor::from_bytes(&rng::array::<FACTOR_LEN>().unwrap()).unwrap()
}

/// DE: Arbeitsordner mit Quelldatei `quelle.txt` und leerem Unterordner `arbeit`.
/// EN: Working directory with source file `quelle.txt` and empty subdirectory `arbeit`.
pub struct Workspace {
    pub dir: tempfile::TempDir,
    pub source: PathBuf,
    pub work: PathBuf,
}

pub fn workspace() -> Workspace {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("quelle.txt");
    std::fs::write(&source, CONTENT).unwrap();
    let work = dir.path().join("arbeit");
    std::fs::create_dir(&work).unwrap();
    Workspace { dir, source, work }
}

/// DE: Formatversion einer verschlüsselten Datei. EN: Format version of an encrypted file.
pub fn version(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[8], bytes[9]])
}

/// DE: Länge des v2-Headers am Anfang von `bytes`. EN: Length of the v2 header at the start.
pub fn header_len(bytes: &[u8]) -> usize {
    HeaderV2::read(&mut &bytes[..])
        .unwrap()
        .encode()
        .unwrap()
        .len()
}

/// DE: Entschlüsselt `bytes` in `work`; bei Erfolg wird der Inhalt geprüft und entfernt, bei
/// einem Fehler darf nichts zurückbleiben.
/// EN: Decrypts `bytes` inside `work`; on success the content is checked and removed, on error
/// nothing may be left behind.
pub fn try_decrypt(work: &Path, bytes: &[u8], unlock: &Unlock<'_>) -> Result<(), Error> {
    let input = work.join("in.pqkf");
    std::fs::write(&input, bytes).unwrap();
    let out = work.join("out");
    let result = files::decrypt(&input, &out, unlock);
    std::fs::remove_file(&input).unwrap();
    if result.is_ok() {
        assert_eq!(std::fs::read(&out).unwrap(), CONTENT);
        std::fs::remove_file(&out).unwrap();
    }
    assert_eq!(
        super::dir_names(work),
        Vec::<String>::new(),
        "Reste / leftovers"
    );
    result.map(|_| ())
}
