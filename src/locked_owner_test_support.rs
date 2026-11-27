//! DE: Gemeinsame lebende Ownerprüfung ohne Secret- oder Adressausgabe.
//! EN: Shared live owner checks without secret or address output.
#![allow(clippy::unwrap_used)]

use crate::hardening::memlock;

pub(crate) fn locked<T>(value: &T) {
    let base = std::ptr::from_ref(value).addr();
    assert!(memlock::is_locked(base));
    assert!(memlock::is_locked(base + size_of::<T>() - 1));
    #[cfg(target_os = "linux")]
    {
        assert!(own_mapping_locked(base));
        assert!(own_mapping_locked(base + size_of::<T>() - 1));
    }
}

// DE: Exakte globale Zähler brauchen einen eigenen Prozess ohne parallele KDFs.
// EN: Exact global counters require a separate process without concurrent KDFs.
pub(crate) fn isolated_test(name: &str, marker: &str) {
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--ignored", "--test-threads=1"])
        .env(marker, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            assert!(
                String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout)
                    .contains("1 passed")
            );
            break;
        }
        let timed_out = Instant::now() >= deadline;
        if timed_out {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(!timed_out);
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn own_mapping_locked(address: usize) -> bool {
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
