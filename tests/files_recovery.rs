//! DE: REC-012: normale Core-/CLI-Aufrufe mit alten Temps und unvollständigen Metadaten.
//! EN: REC-012: ordinary core/CLI calls with stale temps and incomplete metadata.
#![allow(clippy::unwrap_used)]

mod common;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::{envelope, files};
use std::path::Path;

#[test]
fn rec012_fresh_cli_rejects_stale_data_and_preserves_valid_archive() {
    for v2 in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let pass = common::random_passphrase();
        let factor = factor_fixture(v2);
        let archive = root.path().join("valid.pqkf");
        let before = encrypt_fixture(root.path(), &pass, factor.as_ref());
        let stale = root
            .path()
            .join(".valid.pqkf.tmp-00112233aabbccdd0123456789abcdef");
        std::fs::write(&stale, &before[..before.len() - 1]).unwrap();
        let (key, _) = common::key_file(KeyAlgorithm::Aes256);
        let valid_key = root.path().join("valid.key.json");
        envelope::save(&key, &valid_key, envelope::Overwrite::No).unwrap();
        let incomplete = root
            .path()
            .join(".valid.key.json.tmp-00112233aabbccdd0123456789abcdef");
        std::fs::write(&incomplete, b"{\"format_version\":1,\"metadata\":{").unwrap();
        assert!(envelope::load(&incomplete).is_err());
        inspect_clean(root.path(), &pass);
        check_archive(&archive, &pass, factor.as_ref());
        assert!(
            std::fs::read(
                root.path()
                    .join(".valid.pqkf.tmp-ffffffffffffffff0123456789abcdef")
            )
            .unwrap()
                == before,
            "Foreign changed / Fremdes verändert"
        );
        assert!(
            std::fs::read(&archive).unwrap() == before,
            "Archive changed / Archiv verändert"
        );
        assert!(
            std::fs::read(&stale).unwrap() == before[..before.len() - 1],
            "Stale changed / Rest verändert"
        );
        assert_eq!(
            std::fs::read(&incomplete).unwrap(),
            b"{\"format_version\":1,\"metadata\":{"
        );
        assert!(
            envelope::load(&valid_key).unwrap().0 == key,
            "Key changed / Schlüssel verändert"
        );
    }
}

#[test]
fn rec012_truncated_headers_are_rejected_without_promoting_temp() {
    let root = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    for data in [
        b"".as_slice(),
        b"PQKFENC",
        b"PQKFENC\x02\x00\xff\xff\xff\xff",
    ] {
        let source = root.path().join("broken.pqkf");
        let target = root.path().join("out");
        std::fs::write(&source, data).unwrap();
        std::fs::write(root.path().join(".out.tmp-foreign"), b"foreign").unwrap();
        assert!(
            files::decrypt(&source, &target, &files::Unlock::Passphrase(pass.as_ref())).is_err()
        );
        assert!(!target.exists());
        assert_eq!(
            std::fs::read(root.path().join(".out.tmp-foreign")).unwrap(),
            b"foreign"
        );
        assert_no_own_temp(root.path());
    }
}

fn assert_no_own_temp(root: &Path) {
    assert!(std::fs::read_dir(root).unwrap().all(|e| {
        let name = e.unwrap().file_name();
        let name = name.to_string_lossy();
        !name.starts_with(".out.tmp-") || name == ".out.tmp-foreign"
    }));
}

fn encrypt_fixture(
    root: &Path,
    pass: &pqkeep::security::StrongPassphrase,
    factor: Option<&pqkeep::crypto::factor::Factor>,
) -> Vec<u8> {
    std::fs::write(root.join("source"), b"synthetic").unwrap();
    let protection = files::Protection::Slots {
        passphrase: Some(files::PassphraseAccess {
            passphrase: pass,
            params: common::min_params(),
            factor,
        }),
        recipients: &[],
    };
    let archive = root.join("valid.pqkf");
    files::encrypt(&root.join("source"), &archive, &protection).unwrap();
    let before = std::fs::read(archive).unwrap();
    std::fs::write(
        root.join(".valid.pqkf.tmp-ffffffffffffffff0123456789abcdef"),
        &before,
    )
    .unwrap();
    before
}

fn factor_fixture(v2: bool) -> Option<pqkeep::crypto::factor::Factor> {
    v2.then(|| {
        pqkeep::crypto::factor::Factor::from_bytes(&pqkeep::crypto::rng::array::<32>().unwrap())
            .unwrap()
    })
}

fn inspect_clean(root: &Path, pass: &pqkeep::security::StrongPassphrase) {
    let (code, out, err) = common::pqkeep(
        &["--lang", "en", "inspect", "valid.pqkf", "--json"],
        "",
        root,
    );
    assert_eq!(code, 0);
    assert!(!out.contains(pass.as_ref().expose_str()) && !err.contains(pass.as_ref().expose_str()));
}

fn check_archive(
    path: &Path,
    pass: &pqkeep::security::StrongPassphrase,
    factor: Option<&pqkeep::crypto::factor::Factor>,
) {
    let unlock = match factor {
        Some(factor) => files::Unlock::PassphraseWithFactor {
            passphrase: pass.as_ref(),
            factor,
        },
        None => files::Unlock::Passphrase(pass.as_ref()),
    };
    files::check(path, &unlock).unwrap();
}
