//! DE: Faktordatei auf der Kommandozeile (U01, U02, U03): `pqkeep factor`, `--factor-file` bei
//! `generate`, `encrypt`, `decrypt`, `sign`; klare Meldungen, wenn die Faktordatei fehlt, nicht
//! passt oder zu offene Rechte hat; ihr Inhalt erscheint nie in Ausgaben; die Sandbox bleibt aktiv.
//! EN: Factor file on the command line (U01, U02, U03): `pqkeep factor`, `--factor-file` with
//! `generate`, `encrypt`, `decrypt`, `sign`; clear messages when the factor file is missing, does
//! not match or has too open permissions; its content never appears in output; the sandbox stays on.

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

fn pass() -> String {
    format!("{}\n", common::random_passphrase().as_ref().expose_str())
}

fn run(dir: &Path, args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut full = vec!["--lang", "de"];
    full.extend_from_slice(args);
    common::pqkeep(&full, stdin, dir)
}

/// DE: Erzeugt `name` im Ordner über `pqkeep factor`. EN: Creates `name` via `pqkeep factor`.
fn factor(dir: &Path, name: &str) {
    let (code, out, err) = run(dir, &["factor", "--out", name], "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Faktordatei erzeugt"), "{out}");
    assert!(err.contains("getrennt von Schlüsseldatei"), "{err}");
}

/// DE: Schlüssel mit Faktordatei und öffentlicher Teil. EN: Key with factor file and public part.
fn key(dir: &Path, algorithm: &str, name: &str, factor_file: Option<&str>, p: &str) {
    let out = format!("{name}.key.json");
    let mut args = vec!["generate", "-a", algorithm, "-n", "Test", "-o", &out];
    args.push("--passphrase-stdin");
    if let Some(f) = factor_file {
        args.extend(["--factor-file", f]);
    }
    let (code, _, err) = run(dir, &args, p);
    assert_eq!(code, 0, "{err}");
    let public = format!("{name}.pub.json");
    assert_eq!(run(dir, &["export", &out, "-o", &public], "").0, 0);
}

#[test]
fn u01_factor_command_creates_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    factor(dir.path(), "a.factor");
    let path = dir.path().join("a.factor");
    let content = std::fs::read(&path).unwrap();
    assert_eq!(content.len(), 32);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let (code, _, err) = run(dir.path(), &["factor", "--out", "a.factor"], "");
    assert_eq!(code, 5, "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), content);
    // DE: Ohne Ziel: Bedienfehler. EN: Without a target: usage error.
    assert_eq!(run(dir.path(), &["factor"], "").0, 2);
    factor(dir.path(), "b.factor");
    assert_ne!(std::fs::read(dir.path().join("b.factor")).unwrap(), content);
}

#[test]
fn u01_file_with_passphrase_and_factor() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    factor(d, "a.factor");
    factor(d, "falsch.factor");
    std::fs::write(d.join("bericht.txt"), b"Inhalt").unwrap();
    let p = pass();
    let enc = ["encrypt", "bericht.txt", "--passphrase-stdin"];
    let (code, _, err) = run(d, &[&enc[..], &["--factor-file", "a.factor"]].concat(), &p);
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = run(d, &["inspect", "bericht.txt.pqkf"], "");
    assert_eq!(code, 0);
    assert!(out.contains("Faktordatei: erforderlich"), "{out}");
    std::fs::remove_file(d.join("bericht.txt")).unwrap();

    let dec = ["decrypt", "bericht.txt.pqkf", "--passphrase-stdin"];
    // DE: Ohne Faktordatei: klare Meldung, Exit 2. EN: Without factor file: clear message, exit 2.
    let (code, _, err) = run(d, &dec, &p);
    assert_eq!(code, 2);
    assert!(err.contains("--factor-file"), "{err}");
    // DE: Falsche Faktordatei wie falsche Passphrase. EN: Wrong factor file like wrong passphrase.
    let wrong = [&dec[..], &["--factor-file", "falsch.factor"]].concat();
    assert_eq!(run(d, &wrong, &p).0, 3);
    assert!(!d.join("bericht.txt").exists());
    let right = [&dec[..], &["--factor-file", "a.factor"]].concat();
    let (code, _, err) = run(d, &right, &p);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(d.join("bericht.txt")).unwrap(), b"Inhalt");
}

#[test]
fn u01_factor_is_never_silently_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    factor(d, "a.factor");
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    let p = pass();
    // DE: v1-Datei (ohne Faktor) + `--factor-file` → Exit 2. EN: v1 file + `--factor-file` → exit 2.
    let (code, _, err) = run(d, &["encrypt", "a.txt", "--passphrase-stdin"], &p);
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = run(d, &["inspect", "a.txt.pqkf"], "");
    assert!(code == 0 && !out.contains("Faktordatei"), "{out}");
    let dec = [
        "decrypt",
        "a.txt.pqkf",
        "--passphrase-stdin",
        "-o",
        "b.txt",
        "--factor-file",
        "a.factor",
    ];
    let (code, _, err) = run(d, &dec, &p);
    assert_eq!(code, 2);
    assert!(err.contains("--factor-file weglassen"), "{err}");
    assert!(!d.join("b.txt").exists());
    // DE: Faktordatei gehört zur Passphrase, nicht zum Empfänger. EN: Factor goes with the passphrase.
    let both = [
        "encrypt",
        "a.txt",
        "--to",
        "x.pub.json",
        "--factor-file",
        "a.factor",
    ];
    assert_eq!(run(d, &both, "").0, 2);
}

#[test]
fn u01_key_file_with_factor_decrypts_and_signs() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    factor(d, "a.factor");
    let p = pass();
    key(d, "ml-kem-768", "kem", Some("a.factor"), &p);
    key(d, "ml-dsa-87", "dsa", Some("a.factor"), &p);
    key(d, "ml-dsa-87", "alt", None, &p);
    let json = std::fs::read_to_string(d.join("kem.key.json")).unwrap();
    assert!(json.contains("\"format_version\": 2") && json.contains("file-32"));
    let (_, out, _) = run(d, &["inspect", "kem.key.json"], "");
    assert!(out.contains("Faktordatei: erforderlich"), "{out}");

    std::fs::write(d.join("a.txt"), b"A").unwrap();
    assert_eq!(
        run(d, &["encrypt", "a.txt", "--to", "kem.pub.json"], "").0,
        0
    );
    let dec = [
        "decrypt",
        "a.txt.pqkf",
        "-k",
        "kem.key.json",
        "-o",
        "b.txt",
        "--passphrase-stdin",
    ];
    let (code, _, err) = run(d, &dec, &p);
    assert_eq!(code, 2);
    assert!(err.contains("--factor-file"), "{err}");
    let (code, _, err) = run(d, &[&dec[..], &["--factor-file", "a.factor"]].concat(), &p);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(d.join("b.txt")).unwrap(), b"A");

    let sign = ["sign", "a.txt", "-k", "dsa.key.json", "--passphrase-stdin"];
    assert_eq!(run(d, &sign, &p).0, 2);
    let (code, _, err) = run(d, &[&sign[..], &["--factor-file", "a.factor"]].concat(), &p);
    assert_eq!(code, 0, "{err}");
    assert_eq!(run(d, &["verify", "a.txt", "-p", "dsa.pub.json"], "").0, 0);
    // DE: Schlüsseldatei Version 1 + Faktordatei → Exit 2. EN: Version 1 key file + factor → exit 2.
    let old = [
        "sign",
        "a.txt",
        "-k",
        "alt.key.json",
        "-o",
        "alt.pqsig",
        "--passphrase-stdin",
        "--factor-file",
        "a.factor",
    ];
    let (code, _, err) = run(d, &old, &p);
    assert_eq!(code, 2);
    assert!(err.contains("weglassen"), "{err}");
}

#[test]
fn u01_several_files_with_one_factor() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    factor(d, "a.factor");
    for name in ["a.txt", "b.txt"] {
        std::fs::write(d.join(name), name).unwrap();
    }
    let p = pass();
    let enc = [
        "encrypt",
        "a.txt",
        "b.txt",
        "--each",
        "--passphrase-stdin",
        "--factor-file",
        "a.factor",
    ];
    let (code, _, err) = run(d, &enc, &p);
    assert_eq!(code, 0, "{err}");
    for name in ["a.txt", "b.txt"] {
        std::fs::remove_file(d.join(name)).unwrap();
    }
    let dec = ["decrypt", "a.txt.pqkf", "b.txt.pqkf", "--passphrase-stdin"];
    let (code, _, err) = run(d, &dec, &p);
    assert_eq!(code, 2);
    assert!(err.contains("--factor-file"), "{err}");
    let (code, _, err) = run(d, &[&dec[..], &["--factor-file", "a.factor"]].concat(), &p);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(d.join("b.txt")).unwrap(), b"b.txt");
}

#[test]
fn u01_help_in_both_languages() {
    let dir = tempfile::tempdir().unwrap();
    for (lang, command, option) in [
        (
            "de",
            "Faktordatei erzeugen",
            "Faktordatei zusätzlich zur Passphrase",
        ),
        (
            "en",
            "Create a factor file",
            "Factor file in addition to the passphrase",
        ),
    ] {
        let (_, out, _) = common::pqkeep(&["--lang", lang, "--help"], "", dir.path());
        assert!(out.contains("factor") && out.contains(command), "{out}");
        for sub in ["generate", "encrypt", "decrypt", "sign"] {
            let (_, out, _) = common::pqkeep(&["--lang", lang, sub, "--help"], "", dir.path());
            assert!(
                out.contains("--factor-file") && out.contains(option),
                "{out}"
            );
        }
        let (_, out, _) = common::pqkeep(&["--lang", lang, "factor", "--help"], "", dir.path());
        common::assert_no_secret_like_words(&out, "factor --help");
    }
    // DE: Befehle ohne Passphrase kennen die Option nicht. EN: Commands without passphrase lack it.
    let (code, ..) = run(dir.path(), &["inspect", "x", "--factor-file", "y"], "");
    assert_eq!(code, 2);
}

#[test]
fn u03_invalid_factor_files_are_rejected_with_clear_messages() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    std::fs::write(d.join("kurz.factor"), [7u8; 31]).unwrap();
    // DE: Rechte werden vor der Länge geprüft – daher hier 0600. EN: Permissions are checked first.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let private = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(d.join("kurz.factor"), private).unwrap();
    }
    std::fs::create_dir(d.join("ordner")).unwrap();
    let p = pass();
    let try_with = |file: &str| {
        let args = [
            "encrypt",
            "a.txt",
            "--passphrase-stdin",
            "--factor-file",
            file,
        ];
        run(d, &args, &p)
    };
    let (code, _, err) = try_with("fehlt.factor");
    assert_eq!(code, 1);
    assert!(err.contains("nicht gefunden"), "{err}");
    for file in ["kurz.factor", "ordner"] {
        let (code, _, err) = try_with(file);
        assert_eq!(code, 1, "{file}");
        assert!(err.contains("genau 32 Bytes"), "{err}");
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        factor(d, "offen.factor");
        let open = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(d.join("offen.factor"), open).unwrap();
        let (code, _, err) = try_with("offen.factor");
        assert_eq!(code, 1);
        assert!(err.contains("chmod 600"), "{err}");
        std::os::unix::fs::symlink("offen.factor", d.join("link.factor")).unwrap();
        assert_eq!(try_with("link.factor").0, 1);
    }
    assert!(!d.join("a.txt.pqkf").exists());
}

#[test]
fn u03_factor_content_never_appears_in_output() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // DE: Faktordatei in einem anderen Ordner (wie auf einem USB-Stick). EN: In another directory.
    let other = tempfile::tempdir().unwrap();
    let file = other.path().join("a.factor");
    let file = file.to_str().unwrap();
    factor(d, file);
    let content = std::fs::read(file).unwrap();
    let hex = hex::encode(&content);
    std::fs::write(d.join("a.txt"), b"A").unwrap();
    let p = pass();
    let enc = [
        "--verbose",
        "encrypt",
        "a.txt",
        "--passphrase-stdin",
        "--factor-file",
        file,
    ];
    let (code, out, err) = run(d, &enc, &p);
    assert_eq!(code, 0, "{err}");
    // DE: U02 – auch mit Faktordatei läuft der Befehl in der Sandbox. EN: U02 – still sandboxed.
    #[cfg(target_os = "linux")]
    assert!(
        err.contains("Sandbox: landlock=") && err.contains("seccomp=full"),
        "{err}"
    );
    let inspect = run(d, &["--verbose", "inspect", "a.txt.pqkf"], "");
    for text in [&out, &err, &inspect.1, &inspect.2] {
        assert!(!text.to_lowercase().contains(&hex), "{text}");
    }
    // DE: Die Option nimmt nur einen Pfad – der Inhalt als Wert ist keine Faktordatei.
    // EN: The option takes a path only – the content as value is not a factor file.
    let as_value = [
        "decrypt",
        "a.txt.pqkf",
        "--passphrase-stdin",
        "--factor-file",
        &hex,
    ];
    let (code, _, err) = run(d, &as_value, &p);
    assert_eq!(code, 1);
    assert!(err.contains("nicht gefunden"), "{err}");
}
