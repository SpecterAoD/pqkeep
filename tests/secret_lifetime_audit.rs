//! DE: Synthetische Auditproben, keine Behebung und kein Auslesen freigegebenen Speichers.
//! EN: Synthetic audit probes, not remediation or reads of freed memory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::rc::Rc;

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{Aead, AeadCore, AeadInOut, Error, Nonce, Tag, TagPosition, consts};

// DE: Nur Metadaten des eigenen Prozesses, keine Speicherinhalte oder Adressen ausgeben.
// EN: Own-process metadata only; never print memory contents or addresses.
#[cfg(target_os = "linux")]
fn mapping_locked(address: usize) -> Option<bool> {
    let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut selected = false;
    let result = maps.lines().find_map(|line| {
        if let Some((start, end)) = line.split_whitespace().next().unwrap_or("").split_once('-')
            && let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            )
        {
            selected = start <= address && address < end;
        }
        if selected && line.starts_with("VmFlags:") {
            Some(line.split_whitespace().any(|flag| flag == "lo"))
        } else {
            None
        }
    });
    assert!(
        result.is_some(),
        "Own live allocation mapping must be measurable"
    );
    result
}

#[cfg(not(target_os = "linux"))]
fn mapping_locked(_address: usize) -> Option<bool> {
    // DE: Kein Windows-Sperrbeweis aus einem Linux-Messverfahren ableiten.
    // EN: Do not infer Windows locking from a Linux-only measurement.
    None
}

struct Traced {
    source: Cursor<Vec<u8>>,
    address: Rc<Cell<usize>>,
}

impl Read for Traced {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.address.set(target.as_ptr().addr());
        self.source.read(target)
    }
}

fn reader_probe(size: usize) -> bool {
    let address = Rc::new(Cell::new(0));
    let traced = Traced {
        source: Cursor::new(vec![0x5a; size]),
        address: Rc::clone(&address),
    };
    let mut reader = BufReader::new(traced);
    let mut target = vec![0; size];
    assert_eq!(reader.read(&mut target).unwrap(), size);
    assert!(target.iter().all(|byte| *byte == 0x5a));
    let private = address.get() != target.as_ptr().addr();
    println!(
        "AUDIT147 reader bytes={size} private={private} locked={:?}",
        mapping_locked(address.get())
    );
    private
}

#[test]
fn std_reader_small_input_has_a_separate_copy() {
    assert!(reader_probe(4097));
}

#[test]
fn std_reader_large_input_bypasses_private_buffer_control() {
    assert!(!reader_probe(64 * 1024));
}

#[test]
fn std_writer_small_input_is_staged() {
    let mut writer = BufWriter::new(io::sink());
    let data = vec![0x5a; writer.capacity() - 1];
    writer.write_all(&data).unwrap();
    assert_eq!(writer.buffer(), data.as_slice());
    println!(
        "AUDIT147 writer retained={} locked={:?}",
        writer.buffer().len(),
        mapping_locked(writer.buffer().as_ptr().addr())
    );
}

#[test]
fn std_writer_large_and_empty_input_controls() {
    let mut writer = BufWriter::new(io::sink());
    writer.write_all(&[]).unwrap();
    assert_eq!(writer.buffer().len(), 0);
    writer.write_all(&vec![0x5a; 64 * 1024]).unwrap();
    assert_eq!(writer.buffer().len(), 0);
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn std_writer_error_keeps_live_staging_buffer_observable() {
    let mut writer = BufWriter::new(FailingWriter);
    writer.write_all(&[0x5a; 32]).unwrap();
    assert_eq!(
        writer.flush().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(writer.buffer(), &[0x5a; 32]);
}

// DE: Messadapter bricht vor der Verschlüsselung ab; kein eigener Algorithmus/KAT.
// EN: Measuring adapter fails before encryption; not an algorithm or cryptographic KAT.
#[derive(Default)]
struct Spy {
    address: Cell<usize>,
    bytes: Cell<usize>,
    locked: Cell<Option<bool>>,
}

impl AeadCore for Spy {
    type NonceSize = consts::U12;
    type TagSize = consts::U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for Spy {
    fn encrypt_inout_detached(
        &self,
        _nonce: &Nonce<Self>,
        _aad: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        self.address.set(buffer.get_in().as_ptr().addr());
        self.bytes.set(buffer.len());
        self.locked.set(mapping_locked(self.address.get()));
        assert!(buffer.get_in().iter().all(|byte| *byte == 0x5a));
        Err(Error)
    }

    fn decrypt_inout_detached(
        &self,
        _nonce: &Nonce<Self>,
        _aad: &[u8],
        _buffer: InOutBuf<'_, '_, u8>,
        _tag: &Tag<Self>,
    ) -> Result<(), Error> {
        Err(Error)
    }
}

#[test]
fn pinned_aead_allocating_adapter_copies_before_encrypting() {
    for size in [32, 64 * 1024] {
        let spy = Spy::default();
        let data = vec![0x5a; size];
        assert!(
            spy.encrypt(&Nonce::<Spy>::default(), data.as_slice())
                .is_err()
        );
        assert_eq!(spy.bytes.get(), size);
        assert!(spy.address.get() != data.as_ptr().addr());
        println!(
            "AUDIT147 aead bytes={size} private=true locked={:?}",
            spy.locked.get()
        );
        // DE: Der Adapterpuffer ist nach Rückgabe freigegeben; keine nachträgliche Messung.
        // EN: Adapter allocation is freed on return; never inspect it afterwards.
    }
}

#[test]
fn direct_aead_inout_preserves_caller_storage_control() {
    let spy = Spy::default();
    let mut data = [0x5a; 32];
    let address = data.as_ptr().addr();
    assert!(
        spy.encrypt_inout_detached(&Nonce::<Spy>::default(), &[], data.as_mut_slice().into())
            .is_err()
    );
    assert!(spy.address.get() == address);
}

struct HashInput {
    source: Cursor<Vec<u8>>,
    observed: Rc<Cell<Option<bool>>>,
}

impl Read for HashInput {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.observed
            .set(Some(pqkeep::hardening::memlock::is_locked(
                target.as_ptr().addr(),
            )));
        self.source.read(target)
    }
}

#[test]
fn actual_detached_hash_reports_buffer_registration_without_secret_output() {
    let observed = Rc::new(Cell::new(None));
    let input = HashInput {
        source: Cursor::new(vec![0x5a; 4097]),
        observed: Rc::clone(&observed),
    };
    let digest = pqkeep::sign::digest_reader(input).unwrap();
    assert_eq!(digest.size, 4097);
    assert!(observed.get().is_some());
    println!(
        "AUDIT147 actual_sign_buffer_registered={:?}",
        observed.get()
    );
}
