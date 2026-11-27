//! DE: Hilfen für die Integritätstests (#335): je Format eine kleine Datei mit Empfänger-Schlüssel
//! (ohne Argon2id, damit viele Varianten schnell laufen), Header-Länge, Strom-Bereich und eine
//! Prüfung, dass ein Lesepfad scheitert, ohne etwas zu veröffentlichen.
//! EN: Helpers for the integrity tests (#335): per format a small file with a recipient key
//! (without Argon2id so many variants run fast), header length, stream range and a check that a
//! read path fails without publishing anything.

use std::path::{Path, PathBuf};

use pqkeep::crypto::{DsaAlgorithm, KemAlgorithm, KeyAlgorithm};
use pqkeep::envelope::{PublicKeyFile, UnlockedKey};
use pqkeep::files::{self, EncryptOptions, Protection, Unlock};

/// DE: Länge eines vollen verschlüsselten Blocks. EN: Length of a full encrypted chunk.
pub const ENC_CHUNK: usize = 64 * 1024 + 16;
/// DE: Länge der sichtbaren Signatur (v3). EN: Length of the visible signature (v3).
pub const SIG_LEN: usize = 4627;

/// DE: Format bzw. Option, die eine Datei bekommt. EN: Format or option a file gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    V1,
    V2,
    V3,
    V4Pad,
    V4Hidden,
    V4Anon,
    V4Stream,
    V4StreamHidden,
}

pub const ALL: [Kind; 8] = [
    Kind::V1,
    Kind::V2,
    Kind::V3,
    Kind::V4Pad,
    Kind::V4Hidden,
    Kind::V4Anon,
    Kind::V4Stream,
    Kind::V4StreamHidden,
];

/// DE: Schlüssel für alle Fälle. EN: Keys for all cases.
pub struct Keys {
    pub kem: (PublicKeyFile, UnlockedKey),
    pub other: PublicKeyFile,
    pub kem1024: (PublicKeyFile, UnlockedKey),
    pub signer: UnlockedKey,
}

fn pair(algorithm: KeyAlgorithm) -> (PublicKeyFile, UnlockedKey) {
    let (file, pass) = super::key_file(algorithm);
    (
        file.public_part().unwrap(),
        file.unlock(pass.as_ref()).unwrap(),
    )
}

pub fn keys() -> Keys {
    Keys {
        kem: pair(KeyAlgorithm::Kem(KemAlgorithm::MlKem768)),
        other: pair(KeyAlgorithm::Kem(KemAlgorithm::MlKem768)).0,
        kem1024: pair(KeyAlgorithm::Kem(KemAlgorithm::MlKem1024)),
        signer: pair(KeyAlgorithm::Dsa(DsaAlgorithm::MlDsa87)).1,
    }
}

impl Keys {
    /// DE: Entsperren passend zum Fall. EN: Unlock matching the case.
    pub fn unlock(&self, kind: Kind) -> Unlock<'_> {
        match kind {
            Kind::V4Anon => Unlock::Key(&self.kem1024.1),
            _ => Unlock::Key(&self.kem.1),
        }
    }
}

/// DE: Verschlüsselt `plain` als Datei bzw. Strom im Format `kind`. EN: Encrypts `plain`.
pub fn seal(dir: &Path, name: &str, kind: Kind, k: &Keys, plain: &[u8]) -> Vec<u8> {
    let src = dir.join(format!("{name}.src"));
    std::fs::write(&src, plain).unwrap();
    let enc = dir.join(format!("{name}.pqkf"));
    let one = [&k.kem.0];
    let two = [&k.kem.0, &k.other];
    let anon = [&k.kem1024.0];
    let (recipients, signer, options): (&[&PublicKeyFile], _, _) = match kind {
        Kind::V1 => (&one, None, EncryptOptions::default()),
        Kind::V2 => (&two, None, EncryptOptions::default()),
        Kind::V3 => (&one, Some(&k.signer), EncryptOptions::default()),
        // DE: Strom und Datei mit gleichen Optionen; der Weg folgt aus `is_stream`.
        // EN: Stream and file with the same options; the way follows from `is_stream`.
        Kind::V4Pad | Kind::V4Stream => (&one, None, opts(true, false, false)),
        Kind::V4Hidden | Kind::V4StreamHidden => (&one, Some(&k.signer), opts(false, false, true)),
        Kind::V4Anon => (&anon, None, opts(false, true, false)),
    };
    let p = Protection::Slots {
        passphrase: None,
        recipients,
    };
    if is_stream(kind) {
        files::encrypt_stream_to(&mut &plain[..], &enc, &p, signer, options).unwrap();
    } else {
        files::encrypt_with_options(&src, &enc, &p, signer, options).unwrap();
    }
    let bytes = std::fs::read(&enc).unwrap();
    std::fs::remove_file(&enc).unwrap();
    std::fs::remove_file(&src).unwrap();
    bytes
}

fn opts(pad: bool, anonymous: bool, hide_sender: bool) -> EncryptOptions {
    EncryptOptions {
        pad,
        anonymous,
        hide_sender,
    }
}

pub fn is_stream(kind: Kind) -> bool {
    matches!(kind, Kind::V4Stream | Kind::V4StreamHidden)
}

/// DE: Länge des Headers (v1 bzw. v2–v4). EN: Header length (v1 or v2–v4).
pub fn header_len(bytes: &[u8]) -> usize {
    if u16::from_le_bytes([bytes[8], bytes[9]]) == 1 {
        let header = files::FileHeader::read(&mut &bytes[..]).unwrap();
        header.encode().len()
    } else {
        super::v2_files::header_len(bytes)
    }
}

/// DE: Bereich des verschlüsselten Stroms (ohne Header und sichtbare Signatur).
/// EN: Range of the encrypted stream (without header and visible signature).
pub fn body(kind: Kind, bytes: &[u8]) -> std::ops::Range<usize> {
    let end = bytes.len() - if kind == Kind::V3 { SIG_LEN } else { 0 };
    header_len(bytes)..end
}

/// DE: Lesepfade. EN: Read paths.
#[derive(Clone, Copy, Debug)]
pub enum Path4 {
    Decrypt,
    Check,
    List,
    Original,
}

/// DE: `bytes` muss auf `path` scheitern; nichts wird veröffentlicht, keine Temporärreste.
/// EN: `bytes` must fail on `path`; nothing is published, no temporary leftovers.
pub fn must_fail(dir: &Path, bytes: &[u8], unlock: &Unlock<'_>, path: Path4, what: &str) {
    let input = dir.join("probe.pqkf");
    std::fs::write(&input, bytes).unwrap();
    let out = dir.join("probe.out");
    let restored: PathBuf = dir.join("restored");
    let result = match path {
        Path4::Decrypt => files::decrypt(&input, &out, unlock).map(|_| ()),
        Path4::Check => files::check(&input, unlock).map(|_| ()),
        Path4::List => files::list(&input, unlock).map(|_| ()),
        Path4::Original => {
            let choose = |_: &Path| Some(restored.clone());
            files::decrypt_original(&input, dir, unlock, None, &choose).map(|_| ())
        }
    };
    assert!(
        result.is_err(),
        "{what} ({path:?}) wurde angenommen / was accepted"
    );
    assert!(
        !out.exists() && !restored.exists(),
        "{what}: Ausgabe / output"
    );
    std::fs::remove_file(&input).unwrap();
    let left = super::dir_names(dir);
    assert!(
        left.iter().all(|n| !n.contains(".tmp-")),
        "{what}: {left:?}"
    );
}
