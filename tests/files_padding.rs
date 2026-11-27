//! DE: Füllung (Format v4, Bit PAD, #316 Schritt 3): Rundläufe für Datei, Ordner und Strom,
//! gleiche Dateigröße innerhalb einer PADMÉ-Stufe, Größenformel, Downgrade, ohne Option unverändert.
//! EN: Padding (format v4, bit PAD, #316 step 3): round trips for file, directory and stream, equal
//! file size within one PADMÉ bucket, size formula, downgrade, unchanged without the option.

// DE: Tests dürfen unwrap/expect nutzen. EN: Tests may use unwrap/expect.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use pqkeep::files::format_v4::{OPT_PAD, padme};
use pqkeep::files::{self, Content, EncryptOptions, Protection, Unlock};

const CHUNK: u64 = 64 * 1024;
const PAD: EncryptOptions = EncryptOptions {
    pad: true,
    anonymous: false,
};

/// DE: Länge des STREAM-Chiffrats für `plain` Klartextbytes. EN: STREAM ciphertext length.
fn stream_len(plain: u64) -> u64 {
    let chunks = plain.div_ceil(CHUNK).max(1);
    plain + 16 * chunks
}

fn header_len(enc: &Path) -> u64 {
    files::inspect_v2(enc).unwrap().encode().unwrap().len() as u64
}

#[test]
fn padded_stream_size_follows_padme_and_hides_small_differences() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let p = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let unlock = Unlock::Passphrase(pass.as_ref());
    let mut sizes = Vec::new();
    for len in [1001usize, 1050, 70_000] {
        let enc = dir.path().join(format!("s{len}.pqkf"));
        let plain = vec![3u8; len];
        files::encrypt_stream_to(&mut &plain[..], &enc, &p, None, PAD).unwrap();
        let header = files::inspect_v2(&enc).unwrap();
        assert_eq!(header.v4.as_ref().unwrap().options & OPT_PAD, OPT_PAD);
        let total = padme(len as u64 + 24).unwrap();
        let size = std::fs::metadata(&enc).unwrap().len();
        assert_eq!(size, header_len(&enc) + stream_len(total), "{len}");
        sizes.push(size);
        let out = dir.path().join(format!("s{len}.bin"));
        files::decrypt(&enc, &out, &unlock).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);
        assert_eq!(files::check(&enc, &unlock).unwrap().bytes, len as u64);
    }
    // DE: 1001 und 1050 Byte liegen in derselben PADMÉ-Stufe (1088). EN: same PADMÉ bucket.
    assert_eq!(sizes[0], sizes[1]);
}

#[test]
fn padded_file_and_directory_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("brief.txt");
    std::fs::write(&file, vec![7u8; 5000]).unwrap();
    let tree = dir.path().join("baum");
    std::fs::create_dir(&tree).unwrap();
    common::write_sample_tree(&tree);
    let (key, pass) = common::key_file(pqkeep::crypto::KeyAlgorithm::Kem(
        pqkeep::crypto::KemAlgorithm::MlKem768,
    ));
    let public = key.public_part().unwrap();
    let unlocked = key.unlock(pass.as_ref()).unwrap();
    let p = Protection::Recipient(&public);
    for (src, content) in [(&file, Content::File), (&tree, Content::Directory)] {
        let enc = dir.path().join("x.pqkf");
        let _ = std::fs::remove_file(&enc);
        files::encrypt_with_options(src, &enc, &p, None, PAD).unwrap();
        let header = files::inspect_v2(&enc).unwrap();
        assert_eq!((header.version(), header.content), (4, content));
        let out = dir.path().join("zurück");
        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_file(&out);
        files::decrypt(&enc, &out, &Unlock::Key(&unlocked)).unwrap();
        if content == Content::File {
            assert_eq!(std::fs::read(&out).unwrap(), vec![7u8; 5000]);
        } else {
            assert_eq!(common::read_tree(&out), common::read_tree(&tree));
        }
        assert!(files::list(&enc, &Unlock::Key(&unlocked)).is_ok());
    }
    // DE: Ohne Option bleibt es v1 (Byte für Byte wie bisher). EN: Without the option it stays v1.
    let plain = dir.path().join("plain.pqkf");
    files::encrypt_with_options(&file, &plain, &p, None, EncryptOptions::default()).unwrap();
    assert!(files::inspect(&plain).is_ok());
}

#[test]
fn toggling_the_pad_bit_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pass = common::random_passphrase();
    let p = Protection::Passphrase {
        passphrase: &pass,
        params: common::min_params(),
    };
    let unlock = Unlock::Passphrase(pass.as_ref());
    for options in [PAD, EncryptOptions::default()] {
        let enc = dir.path().join("t.pqkf");
        let _ = std::fs::remove_file(&enc);
        files::encrypt_stream_to(&mut &[1u8; 3000][..], &enc, &p, None, options).unwrap();
        let mut bytes = std::fs::read(&enc).unwrap();
        bytes[22] ^= 0x01; // DE/EN: Optionsbits ab Byte 22 / option bits from byte 22
        let bad = dir.path().join("bad.pqkf");
        std::fs::write(&bad, &bytes).unwrap();
        let out = dir.path().join("bad.bin");
        assert!(files::decrypt(&bad, &out, &unlock).is_err());
        assert!(!out.exists());
    }
}
