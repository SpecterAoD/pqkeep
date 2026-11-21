//! DE: LIST-002/006/009: Schlüssel/Faktoren, geschützte Eingabe und nur Leserechte.
//! EN: LIST-002/006/009: keys/factors, protected input and read-only access.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use pqkeep::crypto::{KemAlgorithm, KeyAlgorithm};
use pqkeep::files::{self, Protection};
use serde_json::Value;
use zeroize::Zeroizing;

fn no_secret(out: &str, err: &str, secret: &str) {
    assert!(!out.contains(secret) && !err.contains(secret));
}

fn missing_key_factor(d: &std::path::Path) {
    let (code, out, _) = common::pqkeep(
        &[
            "--batch",
            "list",
            "input.pqkf",
            "--key",
            "key.json",
            "--json",
        ],
        "",
        d,
    );
    assert_eq!(code, 2);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v.get("entries").is_none());
}

#[test]
fn recipient_access_uses_v1_or_v2_key_protection_and_its_factor() {
    for v2 in [false, true] {
        let f = common::rekey::Fixture::new(v2, KeyAlgorithm::Kem(KemAlgorithm::MlKem768));
        let d = f.root.path();
        let payload = Zeroizing::new(String::from_utf8(common::random_secret()).unwrap());
        std::fs::write(d.join("innen.txt"), payload.as_bytes()).unwrap();
        let public = f.key.public_part().unwrap();
        files::encrypt(
            &d.join("innen.txt"),
            &d.join("input.pqkf"),
            &Protection::Recipient(&public),
        )
        .unwrap();
        let before = common::dir_names(d);
        let mut args = vec![
            "--batch",
            "list",
            "input.pqkf",
            "--key",
            "key.json",
            "--passphrase-stdin",
            "--json",
        ];
        if v2 {
            args.extend(["--factor-file", "factor"]);
        }
        let line = Zeroizing::new(format!("{}\n", f.old.as_ref().expose_str()));
        let (code, out, err) = common::pqkeep(&args, &line, d);
        no_secret(&out, &err, f.old.as_ref().expose_str());
        no_secret(&out, &err, &payload);
        assert_eq!(code, 0);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["schema"], "pqkeep-list/1");
        assert_eq!(v["entries"][0]["path"], "innen.txt");
        assert_eq!(common::dir_names(d), before);
        if v2 {
            missing_key_factor(d);
        }
    }
}

#[test]
fn protected_passphrase_file_and_unused_factor_follow_existing_policy() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    let pass = common::random_passphrase();
    let line = Zeroizing::new(format!("{}\n", pass.as_ref().expose_str()));
    std::fs::write(root.join("credential"), line.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.join("credential"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    std::fs::write(root.join("innen.txt"), b"test").unwrap();
    files::encrypt(
        &root.join("innen.txt"),
        &root.join("input.pqkf"),
        &Protection::Passphrase {
            passphrase: &pass,
            params: common::min_params(),
        },
    )
    .unwrap();
    let args = [
        "--batch",
        "--passphrase-file",
        "credential",
        "list",
        "input.pqkf",
        "--json",
    ];
    let (code, out, err) = common::pqkeep(&args, "", root);
    no_secret(&out, &err, pass.as_ref().expose_str());
    assert_eq!(code, 0);
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap()["schema"],
        "pqkeep-list/1"
    );
    pqkeep::crypto::factor::Factor::create(&root.join("factor")).unwrap();
    let extra = [args.as_slice(), &["--factor-file", "factor"]].concat();
    let (code, out, err) = common::pqkeep(&extra, "", root);
    no_secret(&out, &err, pass.as_ref().expose_str());
    assert_eq!(code, 2);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v.get("entries").is_none());
}
