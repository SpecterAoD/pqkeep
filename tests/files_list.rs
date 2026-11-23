//! DE: LIST-001–006: authentisierte v1/v2-Liste ohne Schreiben oder Teilergebnis.
//! EN: LIST-001–006: authenticated v1/v2 listing without writes or partial results.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use common::v2_files::{factor, kem_key, workspace};
use pqkeep::Error;
use pqkeep::files::{self, EntryKind, PassphraseAccess, Protection, Unlock};

fn pass_protection<'a>(
    pass: &'a pqkeep::security::StrongPassphrase,
    factor: Option<&'a pqkeep::crypto::factor::Factor>,
) -> Protection<'a> {
    if factor.is_some() {
        Protection::Slots {
            passphrase: Some(PassphraseAccess {
                passphrase: pass,
                params: common::min_params(),
                factor,
            }),
            recipients: &[],
        }
    } else {
        Protection::Passphrase {
            passphrase: pass,
            params: common::min_params(),
        }
    }
}

fn pass_unlock<'a>(
    pass: &'a pqkeep::security::StrongPassphrase,
    factor: Option<&'a pqkeep::crypto::factor::Factor>,
) -> Unlock<'a> {
    factor.map_or(Unlock::Passphrase(pass.as_ref()), |factor| {
        Unlock::PassphraseWithFactor {
            passphrase: pass.as_ref(),
            factor,
        }
    })
}

fn factor_checks(
    enc: &std::path::Path,
    pass: &pqkeep::security::StrongPassphrase,
    factor: &pqkeep::crypto::factor::Factor,
    wrong: &pqkeep::crypto::factor::Factor,
) {
    assert_eq!(
        files::list(enc, &pass_unlock(pass, Some(factor)))
            .unwrap()
            .entries[0]
            .path
            .expose()
            .unwrap(),
        "quelle.txt"
    );
    assert!(files::list(enc, &Unlock::Passphrase(pass.as_ref())).is_err());
    assert_eq!(
        files::list(enc, &pass_unlock(pass, Some(wrong))),
        Err(Error::Decrypt)
    );
}

#[test]
fn v1_and_v2_directory_metadata_matches_extraction_and_check_without_writes() {
    let w = workspace();
    let tree = w.dir.path().join("tree");
    common::write_sample_tree(&tree);
    let expected = common::read_tree(&tree)
        .into_iter()
        .map(|(p, b)| (p, b.map(|b| b.len() as u64)))
        .collect::<BTreeMap<_, _>>();
    let pass = common::random_passphrase();
    let f = factor();
    for v2 in [false, true] {
        let enc = w.work.join(if v2 { "v2.pqkf" } else { "v1.pqkf" });
        let factor = v2.then_some(&f);
        let protection = pass_protection(&pass, factor);
        files::encrypt(&tree, &enc, &protection).unwrap();
        let unlock = pass_unlock(&pass, factor);
        let before = common::read_tree(w.dir.path());
        let listed = files::list(&enc, &unlock).unwrap();
        assert_eq!(listed.report, files::check(&enc, &unlock).unwrap());
        assert_eq!(listed, files::list(&enc, &unlock).unwrap());
        let actual = listed
            .entries
            .into_iter()
            .map(|e| {
                assert_eq!(e.kind == EntryKind::File, e.bytes.is_some());
                (e.path.expose().unwrap().to_owned(), e.bytes)
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual, expected);
        assert_eq!(common::read_tree(w.dir.path()), before);
    }
}

#[test]
fn all_kem_accesses_and_factor_errors_follow_existing_unlock_rules() {
    let w = workspace();
    let pass = common::random_passphrase();
    let f = factor();
    let wrong = factor();
    for algorithm in common::v2_files::KEMS {
        let (public, secret) = kem_key(algorithm);
        let recipients = [&public];
        for v2 in [false, true] {
            let enc = w.work.join("input.pqkf");
            let protection = if v2 {
                Protection::Slots {
                    passphrase: Some(PassphraseAccess {
                        passphrase: &pass,
                        params: common::min_params(),
                        factor: Some(&f),
                    }),
                    recipients: &recipients,
                }
            } else {
                Protection::Recipient(&public)
            };
            files::encrypt(&w.source, &enc, &protection).unwrap();
            assert_eq!(
                files::list(&enc, &Unlock::Key(&secret))
                    .unwrap()
                    .entries
                    .len(),
                1
            );
            if v2 {
                factor_checks(&enc, &pass, &f, &wrong);
            }
            std::fs::remove_file(enc).unwrap();
        }
    }
}

fn reject_late(w: &common::v2_files::Workspace, protection: &Protection<'_>, unlock: &Unlock<'_>) {
    let enc = w.work.join("input.pqkf");
    files::encrypt(&w.source, &enc, protection).unwrap();
    let original = std::fs::read(&enc).unwrap();
    assert!(files::list(&enc, unlock).is_ok());
    let last = original.len() - 1;
    let mut appended = original.clone();
    appended.push(0);
    for bytes in [
        common::flip(&original, last),
        original[..last].to_vec(),
        appended,
    ] {
        std::fs::write(&enc, bytes).unwrap();
        assert!(files::list(&enc, unlock).is_err());
        assert_eq!(common::dir_names(&w.work), ["input.pqkf"]);
    }
    std::fs::remove_file(enc).unwrap();
}

#[test]
fn late_tampering_truncation_and_appending_never_return_a_listing() {
    let w = workspace();
    let (public, secret) = kem_key(common::v2_files::KEMS[1]);
    let (other, _) = kem_key(common::v2_files::KEMS[2]);
    std::fs::write(&w.source, vec![17; 200_000]).unwrap();
    let recipients = [&public, &other];
    for protection in [
        Protection::Recipient(&public),
        Protection::Slots {
            passphrase: None,
            recipients: &recipients,
        },
    ] {
        reject_late(&w, &protection, &Unlock::Key(&secret));
    }
}
