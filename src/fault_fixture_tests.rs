//! DE: Laufzeit-Fixtures für Lib-Faulttests; Assertions geben keine Geheimwerte aus.
//! EN: Runtime fixtures for lib fault tests; assertions never print secret values.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use base64ct::{Base64, Encoding};
use zeroize::Zeroizing;

use crate::crypto::factor::Factor;
use crate::crypto::kdf;
use crate::crypto::{KeyAlgorithm, rng};
use crate::envelope::{self, KeyFile, Metadata};
use crate::fault_io_tests::{Action, Plan, Point};
use crate::security::{StrongPassphrase, generator};

pub(crate) fn plan(point: Point, action: Action) -> Plan {
    Plan {
        point,
        occurrence: 1,
        action,
    }
}

pub(crate) struct Keys {
    pub old: KeyFile,
    pub new: KeyFile,
    pass: StrongPassphrase,
    factor: Option<Factor>,
}

impl Keys {
    pub(crate) fn new(with_factor: bool) -> Self {
        let pass = generator::generate(&generator::Options::default()).unwrap();
        let factor = with_factor.then(|| Factor::from_bytes(&rng::array::<32>().unwrap()).unwrap());
        let metadata = Metadata {
            name: "Fault test / Fehlertest".into(),
            organization: None,
            company: None,
            department: None,
            account_type: None,
        };
        let params = crate::crypto::kdf::KdfParams {
            memory_kib: kdf::MIN_MEMORY_KIB,
            iterations: kdf::MIN_ITERATIONS,
            parallelism: 1,
        };
        let generate = || {
            match &factor {
                Some(f) => KeyFile::generate_with_factor(
                    &pass,
                    f,
                    KeyAlgorithm::Aes256,
                    &metadata,
                    &params,
                ),
                None => KeyFile::generate(&pass, KeyAlgorithm::Aes256, &metadata, &params),
            }
            .unwrap()
        };
        let (old, new) = (generate(), generate());
        Self {
            old,
            new,
            pass,
            factor,
        }
    }

    pub(crate) fn assert_valid(&self, path: &Path, expected: &KeyFile) {
        let loaded = envelope::load(path).unwrap().0;
        assert!(loaded == *expected, "Key changed / Schlüssel verändert");
        let unlocked = match &self.factor {
            Some(factor) => loaded.unlock_with_factor(self.pass.as_ref(), factor),
            None => loaded.unlock(self.pass.as_ref()),
        };
        assert!(
            unlocked.is_ok(),
            "Unlock failed / Entsperren fehlgeschlagen"
        );
    }

    pub(crate) fn assert_no_secrets(&self, message: &str) {
        assert_absent(message, self.pass.as_ref().expose());
        for key in [&self.old, &self.new] {
            let unlocked = match &self.factor {
                Some(factor) => key.unlock_with_factor(self.pass.as_ref(), factor),
                None => key.unlock(self.pass.as_ref()),
            }
            .unwrap();
            assert_absent(message, unlocked.secret().expose());
        }
        if let Some(factor) = &self.factor {
            assert_absent(message, factor.expose());
        }
    }
}

fn assert_absent(message: &str, secret: &[u8]) {
    let hex = Zeroizing::new(hex::encode(secret));
    let base64 = Zeroizing::new(Base64::encode_string(secret));
    assert!(
        !message
            .as_bytes()
            .windows(secret.len())
            .any(|w| w == secret),
        "Secret bytes / Geheimbytes"
    );
    assert!(!message.contains(hex.as_str()), "Secret hex / Geheimhex");
    assert!(
        !message.contains(base64.as_str()),
        "Secret base64 / Geheimbasis64"
    );
}

pub(crate) fn assert_no_temps(root: &Path) {
    assert!(
        std::fs::read_dir(root).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")),
        "Temporary leftovers / Temporärreste"
    );
}

pub(crate) struct ArchiveCase {
    pub root: tempfile::TempDir,
    pub source: std::path::PathBuf,
    pub archive: std::path::PathBuf,
    pass: StrongPassphrase,
    factor: Option<Factor>,
}

impl ArchiveCase {
    pub(crate) fn new(v2: bool, tree: bool, size: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let archive = root.path().join("archive.pqkf");
        let payload = vec![0x5a; size];
        if tree {
            std::fs::create_dir_all(source.join("nested")).unwrap();
            std::fs::write(source.join("a"), &payload).unwrap();
            std::fs::write(source.join("nested/b"), b"synthetic / synthetisch").unwrap();
        } else {
            std::fs::write(&source, &payload).unwrap();
        }
        Self {
            root,
            source,
            archive,
            pass: generator::generate(&generator::Options::default()).unwrap(),
            factor: v2.then(|| Factor::from_bytes(&rng::array::<32>().unwrap()).unwrap()),
        }
    }

    pub(crate) fn encrypt(&self) -> crate::Result<crate::files::Report> {
        let params = kdf::KdfParams {
            memory_kib: kdf::MIN_MEMORY_KIB,
            iterations: kdf::MIN_ITERATIONS,
            parallelism: 1,
        };
        let protection = match &self.factor {
            Some(factor) => crate::files::Protection::Slots {
                passphrase: Some(crate::files::PassphraseAccess {
                    passphrase: &self.pass,
                    params,
                    factor: Some(factor),
                }),
                recipients: &[],
            },
            None => crate::files::Protection::Passphrase {
                passphrase: &self.pass,
                params,
            },
        };
        crate::files::encrypt(&self.source, &self.archive, &protection)
    }

    pub(crate) fn unlock(&self) -> crate::files::Unlock<'_> {
        match &self.factor {
            Some(factor) => crate::files::Unlock::PassphraseWithFactor {
                passphrase: self.pass.as_ref(),
                factor,
            },
            None => crate::files::Unlock::Passphrase(self.pass.as_ref()),
        }
    }

    pub(crate) fn assert_valid(&self, output: &Path) {
        crate::files::check(&self.archive, &self.unlock()).unwrap();
        crate::files::decrypt(&self.archive, output, &self.unlock()).unwrap();
        assert!(
            tree_bytes(&self.source) == tree_bytes(output),
            "Output changed / Ausgabe verändert"
        );
    }

    pub(crate) fn assert_no_secrets(&self, message: &str) {
        assert_absent(message, self.pass.as_ref().expose());
        if let Some(factor) = &self.factor {
            assert_absent(message, factor.expose());
        }
    }
}

pub(crate) fn tree_bytes(path: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    if path.is_file() {
        return vec![(std::path::PathBuf::new(), std::fs::read(path).unwrap())];
    }
    let mut entries: Vec<_> = std::fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    let mut files = Vec::new();
    for entry in entries {
        for (tail, bytes) in tree_bytes(&entry) {
            files.push((
                std::path::PathBuf::from(entry.file_name().unwrap()).join(tail),
                bytes,
            ));
        }
    }
    files
}
