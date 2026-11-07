//! DE: Interner Test der HKDF-SHA3-256-Ableitung gegen einen unabhängig (Python
//! hashlib/hmac, an RFC 5869 Testfall 1 geprüft) berechneten Referenzwert.
//! Sichert die Verdrahtung: Hashfunktion, Rolle von Salt/IKM/Info, Domänen-Tag.
//!
//! EN: Internal test of the HKDF-SHA3-256 derivation against a reference value
//! computed independently (Python hashlib/hmac, checked against RFC 5869 test
//! case 1). Guards the wiring: hash function, roles of salt/IKM/info, domain tag.

use super::kek_from_shared;

const EXPECTED: &str = "17503d3d557a8cfc3beea7cb11ceaf04aa172d4c2351eb7d417c0394a42ec686";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[test]
fn hkdf_sha3_reference_value() {
    let kek = kek_from_shared(&[0x01; 32], &[0x02; 64], &[0x03; 32]).unwrap();
    assert_eq!(hex(kek.expose()), EXPECTED);
}

#[test]
fn every_input_matters() {
    let base = kek_from_shared(&[0x01; 32], &[0x02; 64], &[0x03; 32]).unwrap();
    let variants = [
        kek_from_shared(&[0x09; 32], &[0x02; 64], &[0x03; 32]).unwrap(),
        kek_from_shared(&[0x01; 32], &[0x09; 64], &[0x03; 32]).unwrap(),
        kek_from_shared(&[0x01; 32], &[0x02; 64], &[0x09; 32]).unwrap(),
        // DE: Vertauschte Rollen von Salt und IKM. EN: Swapped roles of salt and IKM.
        kek_from_shared(&[0x02; 64], &[0x01; 32], &[0x03; 32]).unwrap(),
    ];
    for v in &variants {
        assert_ne!(v.expose(), base.expose());
    }
}
