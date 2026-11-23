//! DE: Typisierte Seeds vor der Providerkonstruktion gesperrt beobachten.
//! EN: Observe typed seed protection before provider construction.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;

fn check<K: FromSeed>() {
    let fixture = rng::secret(SEED_LEN).unwrap();
    let parsed = parse_seed::<K>(fixture.expose()).unwrap();
    let bytes = parsed.expose()[0].as_slice();
    assert!(memlock::is_locked(bytes.as_ptr().addr()));
    assert!(memlock::is_locked(bytes.as_ptr().addr() + bytes.len() - 1));
    assert_eq!(bytes, fixture.expose());
    assert!(matches!(
        parse_seed::<K>(&[]),
        Err(Error::InvalidInput { field: "seed" })
    ));
    assert!(matches!(
        parse_seed::<K>(&[0; SEED_LEN + 1]),
        Err(Error::InvalidInput { field: "seed" })
    ));
}

#[test]
fn all_kem_typed_seeds_are_locked_before_private_copy() {
    check::<MlKem512>();
    check::<MlKem768>();
    check::<MlKem1024>();
}
