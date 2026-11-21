//! DE: Isolierte Rekey-Fixtures; Geheimnisse nur zur Laufzeit. EN: Isolated runtime-only secrets.
// DE: Boolean-Vergleiche verhindern Secret-/Container-Dumps bei Fehlern.
// EN: Boolean comparisons avoid secret/container dumps on assertion failures.
#![allow(clippy::unwrap_used, clippy::manual_assert_eq)]

use std::path::PathBuf;

use pqkeep::crypto::KeyAlgorithm;
use pqkeep::crypto::factor::Factor;
use pqkeep::envelope::{self, KeyFile, Metadata, Overwrite, RekeyOptions, UnlockedKey};
use pqkeep::security::{Passphrase, StrongPassphrase};

pub struct Fixture {
    pub root: tempfile::TempDir,
    pub old: StrongPassphrase,
    pub new: StrongPassphrase,
    pub key: KeyFile,
    pub factor: Option<Factor>,
    pub factor_path: PathBuf,
    pub source: PathBuf,
    pub output: PathBuf,
    pub backup: PathBuf,
}

impl Fixture {
    pub fn new(v2: bool, algorithm: KeyAlgorithm) -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("key.json");
        let output = root.path().join("new.json");
        let backup = root.path().join("backup.json");
        let factor_path = root.path().join("factor");
        let factor = v2.then(|| {
            Factor::create(&factor_path).unwrap();
            Factor::read(&factor_path).unwrap()
        });
        let old = super::random_passphrase();
        let new = super::random_passphrase();
        let meta = Metadata {
            name: "Rekey test".into(),
            organization: Some("Test".into()),
            ..Metadata::default()
        };
        let params = super::min_params();
        let key = match &factor {
            Some(f) => KeyFile::generate_with_factor(&old, f, algorithm, &meta, &params),
            None => KeyFile::generate(&old, algorithm, &meta, &params),
        }
        .unwrap();
        envelope::save(&key, &source, Overwrite::No).unwrap();
        Self {
            root,
            old,
            new,
            key,
            factor,
            factor_path,
            source,
            output,
            backup,
        }
    }

    pub fn options(&self, in_place: bool) -> RekeyOptions<'_> {
        let mut options = RekeyOptions::new(if in_place { &self.source } else { &self.output });
        options.backup = Some(&self.backup);
        options.overwrite = if in_place {
            Overwrite::Yes
        } else {
            Overwrite::No
        };
        options
    }

    pub fn unlock(&self, key: &KeyFile, pass: &Passphrase) -> pqkeep::Result<UnlockedKey> {
        match &self.factor {
            Some(f) => key.unlock_with_factor(pass, f),
            None => key.unlock(pass),
        }
    }

    pub fn assert_identity(&self, changed: &KeyFile) {
        assert_eq!(changed.algorithm(), self.key.algorithm());
        assert_eq!(changed.key_id(), self.key.key_id());
        assert_eq!(changed.created_utc(), self.key.created_utc());
        assert_eq!(changed.metadata(), self.key.metadata());
        assert_eq!(changed.public_key(), self.key.public_key());
        assert_eq!(changed.format_version(), self.key.format_version());
        let before = self.unlock(&self.key, self.old.as_ref()).unwrap();
        let after = self.unlock(changed, self.new.as_ref()).unwrap();
        assert!(
            before.secret().expose() == after.secret().expose(),
            "Secret changed / Geheimnis verändert"
        );
        assert!(matches!(
            self.unlock(changed, self.old.as_ref()),
            Err(pqkeep::Error::Decrypt)
        ));
    }
}
