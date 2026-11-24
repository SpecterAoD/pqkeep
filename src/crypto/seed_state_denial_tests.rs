//! DE: Echte Sperrverweigerung nur im eigenen kurzlebigen Linux-Kindprozess.
//! EN: Actual lock denial only in our own short-lived Linux child process.
#![allow(clippy::unwrap_used)]

use super::*;
use zeroize::Zeroizing;

#[test]
fn seed_lock_denial_is_checked_in_isolated_child() {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crypto::seed_state::tests::denial::seed_lock_denial_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_SEED_OWNER_DENIAL_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
}

fn denied<N: ArraySize>(public: &Array<u8, N>, fixture: &[u8]) {
    let width = public.len();
    assert!(matches!(
        parse(&fixture[..width], width),
        Err(Error::MemoryLock)
    ));
    assert!(matches!(
        parse(&fixture[..width - 1], width),
        Err(Error::InvalidInput { field: "seed" })
    ));
}

#[test]
#[ignore = "DE: Nur isoliert ausführen. EN: Execute only in an isolated child."]
fn seed_lock_denial_child() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    assert_eq!(
        std::env::var("PQKEEP_SEED_OWNER_DENIAL_CHILD").unwrap(),
        "1"
    );
    // DE: Öffentliche zufällige Testdaten, kein verwalteter Secret-Owner vor dem Limit.
    // EN: Public random fixtures; no managed secret owner precedes the limit.
    let fixture = Zeroizing::new(rng::array::<64>().unwrap());
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    denied(&ml_dsa::Seed::default(), fixture.as_slice());
    denied(
        &ml_kem::kem::Seed::<MlKem512>::default(),
        fixture.as_slice(),
    );
    denied(
        &ml_kem::kem::Seed::<MlKem768>::default(),
        fixture.as_slice(),
    );
    denied(
        &ml_kem::kem::Seed::<MlKem1024>::default(),
        fixture.as_slice(),
    );
}
