//! DE: Gemeinsame lebende Ownerprüfung ohne Secret- oder Adressausgabe.
//! EN: Shared live owner checks without secret or address output.
#![allow(clippy::unwrap_used)]

use crate::hardening::memlock;

pub(super) fn locked<T>(value: &T) {
    let base = std::ptr::from_ref(value).addr();
    assert!(memlock::is_locked(base));
    assert!(memlock::is_locked(base + size_of::<T>() - 1));
    #[cfg(target_os = "linux")]
    {
        assert!(own_mapping_locked(base));
        assert!(own_mapping_locked(base + size_of::<T>() - 1));
    }
}

#[cfg(target_os = "linux")]
fn own_mapping_locked(address: usize) -> bool {
    let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut selected = false;
    for line in maps.lines() {
        if let Some(flags) = line.strip_prefix("VmFlags:") {
            if selected {
                return flags.split_whitespace().any(|flag| flag == "lo");
            }
        } else if let Some(range) = line.split_whitespace().next()
            && let Some((first, last)) = range.split_once('-')
            && let (Ok(first), Ok(last)) = (
                usize::from_str_radix(first, 16),
                usize::from_str_radix(last, 16),
            )
        {
            selected = first <= address && address < last;
        }
    }
    false
}
