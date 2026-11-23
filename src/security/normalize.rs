//! DE: NFKC mit vorhandenen Unicode-Primitiven und vorab gesperrten Arbeitsbereichen.
//! EN: NFKC using existing Unicode primitives and prelocked workspaces.

use crate::{
    Error, Result,
    crypto::{SecretBytes, secret_buffer::SecretBuffer},
};
use unicode_normalization::char::{canonical_combining_class, compose, decompose_compatible};

fn invalid() -> Error {
    Error::InvalidInput {
        field: "passphrase",
    }
}

fn decompose(input: &str) -> Result<SecretBuffer<char>> {
    let mut count = Some(0usize);
    for ch in input.chars() {
        decompose_compatible(ch, |_| count = count.and_then(|n| n.checked_add(1)));
    }
    let mut chars = SecretBuffer::new(vec!['\0'; count.ok_or_else(invalid)?])?;
    let mut offset = 0;
    for ch in input.chars() {
        decompose_compatible(ch, |value| {
            chars.expose_mut()[offset] = value;
            offset += 1;
        });
    }
    Ok(chars)
}

// DE: Stabiler Counting-Sort; kein heimlicher Heap-Scratch des Standardsorts.
// EN: Stable counting sort, without hidden heap scratch from standard sorting.
fn order_run(run: &mut [char], scratch: &mut [char], counts: &mut [usize]) {
    if run.len() < 2 {
        return;
    }
    counts.fill(0);
    for &ch in run.iter() {
        counts[usize::from(canonical_combining_class(ch))] += 1;
    }
    let mut position = 0;
    for count in counts.iter_mut() {
        let length = *count;
        *count = position;
        position += length;
    }
    for &ch in run.iter() {
        let class = usize::from(canonical_combining_class(ch));
        scratch[counts[class]] = ch;
        counts[class] += 1;
    }
    run.copy_from_slice(&scratch[..run.len()]);
}

fn reorder(chars: &mut [char]) -> Result<()> {
    let mut scratch = SecretBuffer::new(vec!['\0'; chars.len()])?;
    let mut counts = SecretBuffer::new(vec![0usize; 256])?;
    let mut start = 0;
    for end in 0..=chars.len() {
        if end == chars.len() || canonical_combining_class(chars[end]) == 0 {
            order_run(
                &mut chars[start..end],
                scratch.expose_mut(),
                counts.expose_mut(),
            );
            start = end;
        }
    }
    Ok(())
}

fn recompose(chars: &mut [char]) -> usize {
    let mut written = 0;
    let mut starter: Option<usize> = None;
    let mut last_class = 0;
    for index in 0..chars.len() {
        let ch = chars[index];
        let class = canonical_combining_class(ch);
        let combined = starter
            .filter(|_| last_class == 0 || last_class < class)
            .and_then(|start| compose(chars[start], ch).map(|value| (start, value)));
        if let Some((start, value)) = combined {
            chars[start] = value;
        } else {
            if class == 0 {
                starter = Some(written);
            }
            chars[written] = ch;
            written += 1;
            last_class = class;
        }
    }
    written
}

pub(super) fn nfkc(input: &str) -> Result<(SecretBytes, usize)> {
    if input.len() > super::INPUT_LIMIT_CHARS * 4 {
        return Err(invalid());
    }
    let mut chars = decompose(input)?;
    reorder(chars.expose_mut())?;
    let length = recompose(chars.expose_mut());
    chars.truncate(length);
    let bytes = chars.expose().iter().try_fold(0usize, |n, ch| {
        n.checked_add(ch.len_utf8()).ok_or_else(invalid)
    })?;
    let mut output = SecretBytes::zeroed(bytes)?;
    let mut offset = 0;
    for &ch in chars.expose() {
        let end = offset + ch.len_utf8();
        ch.encode_utf8(&mut output.expose_mut()[offset..end]);
        offset = end;
    }
    Ok((output, length))
}

#[cfg(test)]
#[path = "normalize_tests.rs"]
mod tests;
