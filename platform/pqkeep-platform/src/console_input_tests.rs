//! DE: Öffentliche Decoder-/Record-Fixtures. EN: Public decoder/record fixtures.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn utf16_decoding_preserves_repeats_and_rejects_malformed_pairs() {
    let mut state = [0; 4];
    let mut text = [0; 4];
    assert_eq!(
        decode(0x03b1, 3, &mut state, &mut text).unwrap(),
        ConsoleInputEvent::Text { len: 2, repeat: 3 }
    );
    assert_eq!(std::str::from_utf8(&text[..2]).unwrap(), "α");
    assert_eq!(
        decode(0xd83d, 2, &mut state, &mut text).unwrap(),
        ConsoleInputEvent::Ignore
    );
    assert_eq!(
        decode(0xde80, 2, &mut state, &mut text).unwrap(),
        ConsoleInputEvent::Text { len: 4, repeat: 2 }
    );
    assert_eq!(std::str::from_utf8(&text).unwrap(), "🚀");
    assert_eq!(state, [0; 4]);
    for unit in [0xdc00, 0xdfff] {
        assert_eq!(
            decode(unit, 1, &mut state, &mut text).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    decode(0xd800, 1, &mut state, &mut text).unwrap();
    assert!(decode(0xdc00, 2, &mut state, &mut text).is_err());
    assert!(decode(13, 1, &mut state, &mut text).is_err());
    assert!(decode(0xd801, 1, &mut state, &mut text).is_err());
    assert_eq!(
        decode(3, 1, &mut state, &mut text).unwrap(),
        ConsoleInputEvent::Cancel
    );
}

#[test]
fn controls_and_pending_state_never_become_error_strings() {
    let mut state = [0; 4];
    let mut text = [0; 4];
    for unit in [0, 9, 0x85] {
        assert_eq!(
            decode(unit, 1, &mut state, &mut text).unwrap(),
            ConsoleInputEvent::Ignore
        );
    }
    for unit in [8, 127] {
        assert_eq!(
            decode(unit, 4, &mut state, &mut text).unwrap(),
            ConsoleInputEvent::Backspace(4)
        );
    }
    for unit in [10, 13] {
        assert_eq!(
            decode(unit, 1, &mut state, &mut text).unwrap(),
            ConsoleInputEvent::Finish
        );
    }
    for unit in [3, 27] {
        assert_eq!(
            decode(unit, 1, &mut state, &mut text).unwrap(),
            ConsoleInputEvent::Cancel
        );
    }
}

#[test]
#[allow(clippy::panic)] // DE/EN: Absichtlicher Unwind-Nachweis / deliberate unwind proof.
fn aligned_record_is_inside_storage_and_wiped_after_return_and_unwind() {
    use windows_sys::Win32::System::Console::INPUT_RECORD;
    for offset in 0..align_of::<INPUT_RECORD>() {
        let mut bytes = [0xa5; crate::CONSOLE_INPUT_STORAGE + align_of::<INPUT_RECORD>()];
        {
            let record = Record::new(&mut bytes[offset..]).unwrap();
            assert!(record.pointer().is_aligned());
            // SAFETY: Test guard provides exclusive aligned full initialized native
            // record space. Public default fixture may have uninitialized padding;
            // guard only writes bytes before safe storage access resumes.
            unsafe { record.pointer().write(INPUT_RECORD::default()) };
        }
        assert!(bytes[offset..].iter().all(|byte| *byte == 0));
        bytes[offset..].fill(0xa5);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _record = Record::new(&mut bytes[offset..]).unwrap();
            panic!("public fixture unwind");
        }));
        assert!(result.is_err());
        assert!(bytes[offset..].iter().all(|byte| *byte == 0));
    }
    assert!(Record::new(&mut []).is_err());
}
