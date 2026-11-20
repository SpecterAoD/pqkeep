//! DE: Echte STREAM-API ohne Hooks: deterministische Write-/Flush-Fehler und Grenzgrößen.
//! EN: Real STREAM API without hooks: deterministic write/flush errors and boundary sizes.
#![allow(clippy::unwrap_used)]

use std::io::{self, Write};

use pqkeep::Error;
use pqkeep::crypto::{aead, rng, stream};

#[derive(Clone, Copy)]
enum Fault {
    After(usize),
    Flush,
    Short,
    Interrupt,
    Zero,
}

struct Sink {
    bytes: Vec<u8>,
    fault: Fault,
    calls: usize,
    flushes: usize,
}

impl Sink {
    fn new(fault: Fault) -> Self {
        Self {
            bytes: Vec::new(),
            fault,
            calls: 0,
            flushes: 0,
        }
    }
}

impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        let count = match self.fault {
            Fault::After(limit) if self.bytes.len() >= limit => {
                return Err(io::ErrorKind::StorageFull.into());
            }
            Fault::After(limit) => data.len().min(limit - self.bytes.len()),
            Fault::Short => data.len().min(7),
            Fault::Interrupt if self.calls == 1 => return Err(io::ErrorKind::Interrupted.into()),
            Fault::Zero => return Ok(0),
            _ => data.len(),
        };
        self.bytes.extend_from_slice(&data[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if matches!(self.fault, Fault::Flush) {
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn stream_failures_never_report_success_at_boundaries() {
    let key = aead::generate_key().unwrap();
    for length in [
        0,
        1,
        stream::CHUNK_SIZE - 1,
        stream::CHUNK_SIZE,
        stream::CHUNK_SIZE + 1,
    ] {
        let plain = vec![0x41; length];
        for fault in [
            Fault::After(0),
            Fault::After(1),
            Fault::After(stream::CHUNK_SIZE),
            Fault::Flush,
            Fault::Zero,
        ] {
            let mut sink = Sink::new(fault);
            let result = stream::encrypt(
                key.expose(),
                rng::array().unwrap(),
                b"fault-test",
                &mut plain.as_slice(),
                &mut sink,
            );
            let expected = match fault {
                Fault::Flush => io::ErrorKind::Other,
                Fault::Zero => io::ErrorKind::WriteZero,
                _ => io::ErrorKind::StorageFull,
            };
            if matches!(fault, Fault::After(limit) if limit >= length + 16 && length <= stream::CHUNK_SIZE)
            {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(Error::Io(expected)));
            }
        }
    }
}

#[test]
fn short_and_interrupted_writes_preserve_stream_content() {
    let key = aead::generate_key().unwrap();
    let plain = vec![0x42; 2 * stream::CHUNK_SIZE + 1];
    for fault in [Fault::Short, Fault::Interrupt] {
        let prefix = rng::array().unwrap();
        let mut sink = Sink::new(fault);
        assert_eq!(
            stream::encrypt(
                key.expose(),
                prefix,
                b"fault-test",
                &mut plain.as_slice(),
                &mut sink
            )
            .unwrap(),
            plain.len() as u64
        );
        assert_eq!(sink.flushes, 1);
        let mut opened = Vec::new();
        stream::decrypt(
            key.expose(),
            prefix,
            b"fault-test",
            &mut sink.bytes.as_slice(),
            &mut opened,
        )
        .unwrap();
        assert!(opened == plain, "Content changed / Inhalt verändert");
    }
}

#[test]
fn decrypt_writer_failure_is_propagated_without_retry_success() {
    let key = aead::generate_key().unwrap();
    let prefix = rng::array().unwrap();
    let plain = vec![0x43; 2 * stream::CHUNK_SIZE + 1];
    let mut encrypted = Vec::new();
    stream::encrypt(
        key.expose(),
        prefix,
        b"fault-test",
        &mut plain.as_slice(),
        &mut encrypted,
    )
    .unwrap();
    let mut sink = Sink::new(Fault::After(3));
    let result = stream::decrypt(
        key.expose(),
        prefix,
        b"fault-test",
        &mut encrypted.as_slice(),
        &mut sink,
    );
    assert_eq!(result, Err(Error::Io(io::ErrorKind::StorageFull)));
    assert_eq!(sink.bytes.len(), 3);
    // DE: Niedrige STREAM-Ausgabe ist kein Datei-Publish. EN: Low-level STREAM output is not file publication.
}
