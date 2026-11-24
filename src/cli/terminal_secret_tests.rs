//! DE: Grenzen und ganzes UTF8-Backspace. EN: Bounds and whole UTF8 backspace.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn repeated_unicode_is_bounded_and_backspace_wipes_complete_characters() {
    let input = Input::public_fixture("🚀".as_bytes());
    input.assert_all_locked();
    let mut out = SecretBytes::zeroed(8).unwrap();
    let mut len = 0;
    edit(
        Action::Text { len: 4, repeat: 2 },
        &input,
        &mut out,
        &mut len,
    )
    .unwrap();
    assert_eq!(len, 8);
    assert!(out.expose().iter().eq("🚀🚀".as_bytes()));
    assert!(
        edit(
            Action::Text { len: 4, repeat: 1 },
            &input,
            &mut out,
            &mut len
        )
        .is_err()
    );
    assert_eq!(len, 8);
    edit(Action::Backspace(1), &input, &mut out, &mut len).unwrap();
    assert_eq!(len, 4);
    assert!(out.expose()[4..].iter().all(|byte| *byte == 0));
    assert!(out.expose()[..4].iter().eq("🚀".as_bytes()));
    edit(Action::Backspace(u16::MAX), &input, &mut out, &mut len).unwrap();
    assert_eq!(len, 0);
    assert!(out.expose().iter().all(|byte| *byte == 0));
}

#[test]
fn malformed_internal_actions_fail_before_changing_output() {
    let input = Input::public_fixture(&[]);
    let mut out = SecretBytes::zeroed(4).unwrap();
    let mut len = 0;
    for action in [
        Action::Text { len: 0, repeat: 1 },
        Action::Text { len: 5, repeat: 1 },
        Action::Text { len: 1, repeat: 0 },
        Action::Finish,
        Action::Cancel,
    ] {
        assert!(edit(action, &input, &mut out, &mut len).is_err());
        assert_eq!(len, 0);
        assert!(out.expose().iter().all(|byte| *byte == 0));
    }
    edit(Action::Ignore, &input, &mut out, &mut len).unwrap();
}
