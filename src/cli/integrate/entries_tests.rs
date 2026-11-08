#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{Action, Terminal, dolphin, nautilus, nemo, safe_path};

fn term() -> Terminal {
    Terminal {
        path: "/usr/bin/gnome-terminal".into(),
        exec_flag: "--",
    }
}

#[test]
fn safe_path_rejects_special_characters() {
    for bad in [
        "", "/a\"b", "/a'b", "/a`b", "/a$b", "/a\\b", "/a%b", "/a\nb", "/a\tb",
    ] {
        assert!(!safe_path(bad), "{bad:?}");
    }
    for good in [
        "/home/max/.local/bin/pqkeep",
        "/opt/PQ Keep/bin/pqkeep",
        "/home/jürgen/bin/pqkeep",
    ] {
        assert!(safe_path(good), "{good:?}");
    }
}

#[test]
fn nemo_entry_puts_path_after_double_dash() {
    let e = nemo(Action::Encrypt, "Encrypt", "c", "/opt/PQ Keep/pqkeep");
    assert!(e.contains("Exec=\"/opt/PQ Keep/pqkeep\" context encrypt -- %F\n"));
    assert!(
        e.contains("Selection=s\n")
            && e.contains("Extensions=any;\n")
            && e.contains("Terminal=true\n")
    );
    let d = nemo(Action::Decrypt, "Decrypt", "c", "/x/pqkeep");
    assert!(d.contains("Extensions=pqkf;\n") && d.contains("context decrypt -- %F"));
}

#[test]
fn nautilus_script_passes_exactly_one_argument() {
    let s = nautilus(Action::Decrypt, "/opt/PQ Keep/pqkeep", &term());
    assert!(s.starts_with("#!/bin/sh\n"));
    assert!(s.contains("[ \"$#\" -eq 1 ] || exit 0\n"));
    assert!(s.contains(
        "exec '/usr/bin/gnome-terminal' -- '/opt/PQ Keep/pqkeep' context decrypt -- \"$1\"\n"
    ));
}

#[test]
fn dolphin_entry_uses_single_file_code() {
    let e = dolphin(Action::Encrypt, "Encrypt", "/x/pqkeep", &term());
    assert!(e.contains("MimeType=all/allfiles;inode/directory;\n"));
    assert!(
        e.contains("Exec=\"/usr/bin/gnome-terminal\" -- \"/x/pqkeep\" context encrypt -- %f\n")
    );
    assert!(!e.contains("%F"));
}
