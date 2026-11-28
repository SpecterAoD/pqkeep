//! DE: Öffentliche Tabelle statt privater Unicode-Expansionsarrays.
//! EN: Public table instead of private Unicode expansion arrays.
include!(concat!(env!("OUT_DIR"), "/unicode_fold.rs"));

fn mapped(c: char) -> Option<&'static [u8]> {
    FOLD.binary_search_by_key(&u32::from(c), |&(key, _)| key)
        .ok()
        .map(|index| FOLD[index].1)
}

pub(super) fn size(c: char) -> usize {
    mapped(c).map_or_else(|| c.len_utf8(), <[u8]>::len)
}

// DE: Ziel ist bereits gesperrt; unveränderte Skalare direkt dorthin kodieren.
// EN: The destination is already locked; encode unchanged scalars directly there.
pub(super) fn write(c: char, target: &mut [u8]) -> usize {
    if let Some(text) = mapped(c) {
        target[..text.len()].copy_from_slice(text);
        text.len()
    } else {
        c.encode_utf8(target).len()
    }
}

#[cfg(test)]
#[path = "unicode_fold_tests.rs"]
mod tests;
