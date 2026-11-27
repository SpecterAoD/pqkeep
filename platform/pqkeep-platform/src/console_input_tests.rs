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
            let mut record = Record::new(&mut bytes[offset..]).unwrap();
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

#[test]
fn exact_record_capacity_preserves_sentinels_at_every_starting_alignment() {
    for offset in 0..align_of::<INPUT_RECORD>() {
        let mut bytes = [0xa5; crate::CONSOLE_INPUT_STORAGE + 2 * align_of::<INPUT_RECORD>()];
        let end = offset + crate::CONSOLE_INPUT_STORAGE;
        let start_address = bytes.as_ptr().addr() + offset;
        {
            let mut record = Record::new(&mut bytes[offset..end]).unwrap();
            let pointer = record.pointer();
            assert!(pointer.is_aligned());
            assert!(pointer.addr() >= start_address);
            assert!(pointer.addr() + size_of::<INPUT_RECORD>() <= start_address + end - offset);
        }
        assert!(bytes[..offset].iter().all(|byte| *byte == 0xa5));
        assert!(bytes[offset..end].iter().all(|byte| *byte == 0));
        assert!(bytes[end..].iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn short_record_storage_is_rejected_before_any_write() {
    for offset in 0..align_of::<INPUT_RECORD>() {
        for len in 0..size_of::<INPUT_RECORD>() {
            let mut bytes = [0xa5; crate::CONSOLE_INPUT_STORAGE + align_of::<INPUT_RECORD>()];
            assert!(Record::new(&mut bytes[offset..offset + len]).is_err());
            assert!(bytes.iter().all(|byte| *byte == 0xa5));
        }
    }
}

#[test]
fn minimum_record_capacity_includes_actual_alignment_padding() {
    let mut bytes = [0xa5; crate::CONSOLE_INPUT_STORAGE + align_of::<INPUT_RECORD>()];
    for offset in 0..align_of::<INPUT_RECORD>() {
        bytes.fill(0xa5);
        let padding = bytes[offset..]
            .as_ptr()
            .align_offset(align_of::<INPUT_RECORD>());
        let required = padding + size_of::<INPUT_RECORD>();
        assert!(Record::new(&mut bytes[offset..offset + required - 1]).is_err());
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
        {
            let mut record = Record::new(&mut bytes[offset..offset + required]).unwrap();
            assert!(record.pointer().is_aligned());
        }
        assert!(bytes[..offset].iter().all(|byte| *byte == 0xa5));
        assert!(
            bytes[offset..offset + required]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(bytes[offset + required..].iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn typed_key_view_checks_event_kind_release_and_repetition_before_decoding() {
    use windows_sys::Win32::System::Console::FOCUS_EVENT;
    let mut pending = [0; 4];
    let mut text = [0; 4];
    for record in [
        public_key(u16::try_from(FOCUS_EVENT).unwrap(), 1, 0, 0xdc00, 0),
        public_key(u16::try_from(KEY_EVENT).unwrap(), 0, 0, 0xdc00, 0),
    ] {
        assert_eq!(
            key_event(&record, &mut pending, &mut text).unwrap(),
            ConsoleInputEvent::Ignore
        );
        assert_eq!(pending, [0; 4]);
        assert_eq!(text, [0; 4]);
    }
    let record = public_key(u16::try_from(KEY_EVENT).unwrap(), 1, 0, 0x03b1, 0);
    assert_eq!(
        key_event(&record, &mut pending, &mut text)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let record = public_key(u16::try_from(KEY_EVENT).unwrap(), 1, 2, 0x03b1, 0);
    assert_eq!(
        key_event(&record, &mut pending, &mut text).unwrap(),
        ConsoleInputEvent::Text { len: 2, repeat: 2 }
    );
    assert_eq!(std::str::from_utf8(&text[..2]).unwrap(), "α");
    let record = public_key(u16::try_from(KEY_EVENT).unwrap(), 1, 1, 0, VK_RETURN);
    assert_eq!(
        key_event(&record, &mut pending, &mut text).unwrap(),
        ConsoleInputEvent::Finish
    );
}

fn public_key(kind: u16, down: i32, repeat: u16, unit: u16, virtual_key: u16) -> INPUT_RECORD {
    use windows_sys::Win32::System::Console::{
        INPUT_RECORD_0, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
    };
    INPUT_RECORD {
        EventType: kind,
        Event: INPUT_RECORD_0 {
            KeyEvent: KEY_EVENT_RECORD {
                bKeyDown: down,
                wRepeatCount: repeat,
                wVirtualKeyCode: virtual_key,
                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                ..KEY_EVENT_RECORD::default()
            },
        },
    }
}

#[test]
fn native_read_error_wipes_the_record_and_pending_state() {
    use std::os::windows::io::AsHandle;
    let file = std::env::current_exe()
        .and_then(std::fs::File::open)
        .unwrap();
    let mut bytes = [0xa5; crate::CONSOLE_INPUT_STORAGE];
    let mut pending = [0xa5; 4];
    let mut text = [0; 4];
    assert!(read_console_input(file.as_handle(), &mut bytes, &mut pending, &mut text).is_err());
    assert!(bytes.iter().all(|byte| *byte == 0));
    assert_eq!(pending, [0; 4]);
    assert_eq!(text, [0; 4]);
}
