#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{FactorPlan, KeyPlan, suggest};

fn plan() -> KeyPlan {
    KeyPlan {
        algorithm: "ml-kem-1024",
        name: "Anna Muster".to_owned(),
        details: [
            ("organization", Some("Verein e.V.".to_owned())),
            ("company", None),
            ("department", Some("IT".to_owned())),
            ("account-type", None),
        ],
        hardened: true,
        min_bits: 192,
        pass_len: Some(40),
        out: "anna-muster.key.json".to_owned(),
        export: Some("anna-muster.pub.json".to_owned()),
        factor: None,
    }
}

/// DE: U01: Mit Faktordatei kommt `--factor-file` dazu; eine neue wird zuerst erzeugt.
/// EN: U01: with a factor file `--factor-file` is added; a new one is created first.
#[test]
fn u01_factor_file_is_passed_on_and_created_first() {
    let mut p = plan();
    p.factor = Some(FactorPlan {
        path: "/media/usb/anna.factor".to_owned(),
        create: false,
    });
    let args = p.generate_args();
    let at = args.iter().position(|a| a == "--factor-file").unwrap();
    assert_eq!(args[at + 1], "/media/usb/anna.factor");
    assert_eq!(args[at + 2], "--out");
    assert_eq!(p.commands().len(), 3);

    p.factor.as_mut().unwrap().create = true;
    let all = p.commands();
    assert_eq!(all.len(), 4);
    assert_eq!(all[0], ["factor", "--out", "/media/usb/anna.factor"]);
    assert_eq!(all[1][0], "passphrase");
    assert_eq!(all[2], p.generate_args());
}

#[test]
fn commands_match_the_answers() {
    let p = plan();
    assert_eq!(
        p.passphrase_args().unwrap(),
        ["passphrase", "40", "--min-bits", "192"]
    );
    assert_eq!(
        p.generate_args(),
        [
            "generate",
            "--algorithm",
            "ml-kem-1024",
            "--name",
            "Anna Muster",
            "--organization",
            "Verein e.V.",
            "--department",
            "IT",
            "--profile",
            "hardened",
            "--min-bits",
            "192",
            "--out",
            "anna-muster.key.json",
        ]
    );
    assert_eq!(
        p.export_args().unwrap(),
        [
            "export",
            "anna-muster.key.json",
            "--out",
            "anna-muster.pub.json"
        ]
    );
    assert_eq!(p.commands().len(), 3);
}

#[test]
fn defaults_add_no_extra_options() {
    let mut p = plan();
    p.hardened = false;
    p.min_bits = 128;
    p.pass_len = None;
    p.export = None;
    p.details = [
        ("organization", None),
        ("company", None),
        ("department", None),
        ("account-type", None),
    ];
    assert_eq!(
        p.generate_args(),
        [
            "generate",
            "--algorithm",
            "ml-kem-1024",
            "--name",
            "Anna Muster",
            "--out",
            "anna-muster.key.json"
        ]
    );
    assert_eq!(p.commands().len(), 1);
}

#[test]
fn suggested_names_are_safe_and_free() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert_eq!(
        suggest(d, "Anna Müller / IT", ".key.json"),
        "anna-müller-it.key.json"
    );
    assert_eq!(suggest(d, "  !!! ", ".key.json"), "pqkeep.key.json");
    std::fs::write(d.join("anna.key.json"), b"x").unwrap();
    assert_eq!(suggest(d, "Anna", ".key.json"), "anna-2.key.json");
    assert_eq!(suggest(d, "Anna", ".pub.json"), "anna.pub.json");
}
