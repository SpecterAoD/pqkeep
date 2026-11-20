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
