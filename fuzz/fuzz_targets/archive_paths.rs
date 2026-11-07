//! DE: Pfadregeln für Archiv-Einträge: nie Panik; angenommene Pfade sind relativ und ohne `..`.
//! EN: Path rules for archive entries: never panic; accepted paths are relative and free of `..`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkeep::files::paths::{PathSet, validate};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut set = PathSet::default();
    for (i, line) in text.split('\n').enumerate() {
        if let Ok(parts) = validate(line) {
            assert!(!line.starts_with('/'));
            assert!(
                parts
                    .iter()
                    .all(|p| !p.is_empty() && *p != ".." && *p != ".")
            );
            let _ = set.insert(&parts, i % 2 == 0);
        }
    }
});
