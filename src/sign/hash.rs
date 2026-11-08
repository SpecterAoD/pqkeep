//! DE: SHA3-512 einer Datei, gestreamt in Blöcken von 64 KiB – die Datei wird nie
//! vollständig in den Speicher geladen.
//! EN: SHA3-512 of a file, streamed in 64 KiB blocks – the file is never loaded
//! into memory as a whole.

use std::io::{ErrorKind, Read};

use sha3::{Digest, Sha3_512};

use crate::Result;

/// DE: Länge des SHA3-512-Hashwerts. EN: Length of the SHA3-512 digest.
pub const DIGEST_LEN: usize = 64;

/// DE: Blockgröße beim Lesen. EN: Block size when reading.
const BLOCK_LEN: usize = 64 * 1024;

/// DE: Hashwert und Anzahl gelesener Bytes. EN: Digest and number of bytes read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDigest {
    /// DE: SHA3-512 des Inhalts. EN: SHA3-512 of the content.
    pub sha3_512: [u8; DIGEST_LEN],
    /// DE: Größe in Bytes. EN: Size in bytes.
    pub size: u64,
}

/// DE: Liest `reader` bis zum Ende und bildet SHA3-512 und Größe.
/// EN: Reads `reader` to the end and computes SHA3-512 and size.
///
/// # Errors
/// DE/EN: [`crate::Error::Io`].
pub fn digest_reader<R: Read>(mut reader: R) -> Result<FileDigest> {
    let mut hasher = Sha3_512::new();
    let mut block = vec![0u8; BLOCK_LEN];
    let mut size = 0u64;
    loop {
        let n = match reader.read(&mut block) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        hasher.update(&block[..n]);
        size += n as u64;
    }
    Ok(FileDigest {
        sha3_512: hasher.finalize().into(),
        size,
    })
}
