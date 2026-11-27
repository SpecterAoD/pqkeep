//! DE: Alle parallelen Worker und komplette Argon2-Operation gegen unabhängige C-Vektoren.
//! EN: Check every parallel worker and complete Argon2 operations against independent C vectors.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::locked_owner_test_support::locked;
use zeroize::Zeroize;

#[path = "argon_workspace_cleanup_tests.rs"]
mod cleanup;

struct Owners {
    blocks: SecretWorkspace<Block>,
    work: SecretState<OperationWorkspace>,
    workers: SecretWorkspace<WorkerWorkspace>,
}

impl Owners {
    fn new(params: &argon2::Params) -> Self {
        Self {
            blocks: SecretWorkspace::zeroed(params.block_count()).unwrap(),
            work: SecretState::new(OperationWorkspace::default()).unwrap(),
            workers: SecretWorkspace::zeroed(usize::try_from(params.p_cost()).unwrap()).unwrap(),
        }
    }

    fn check_locks(&self) {
        locked(self.blocks.expose());
        locked(self.work.get());
        for worker in self.workers.expose() {
            locked(worker);
        }
    }
}

fn pattern(length: usize, multiplier: usize, add: usize) -> SecretBytes {
    let mut out = SecretBytes::zeroed(length).unwrap();
    for (index, byte) in out.expose_mut().iter_mut().enumerate() {
        *byte = u8::try_from((index * multiplier + add) & 255).unwrap();
    }
    out
}

#[test]
fn protected_argon2_matches_76_c_reference_geometries_and_covers_every_lane() {
    report_runtime_backend();
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/kat/argon_operation_workspaces.json"
    ))
    .unwrap();
    let cases = document["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 76);
    for case in cases {
        check_case(case);
    }
}

fn report_runtime_backend() {
    use std::io::Write;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2::Params::new(32, 1, 1, Some(32)).unwrap(),
    );
    let avx2 = argon.protected_compression_uses_avx2();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    assert_eq!(avx2, std::is_x86_feature_detected!("avx2"));
    // DE/EN: Nur öffentlicher Backendnachweis; keine Inhalte/Adressen / public backend proof only.
    writeln!(
        std::io::stdout().lock(),
        "Argon2 workspace runtime AVX2={avx2}"
    )
    .unwrap();
}

fn check_case(case: &serde_json::Value) {
    let memory = u32::try_from(case["memory_kib"].as_u64().unwrap()).unwrap();
    let passes = u32::try_from(case["passes"].as_u64().unwrap()).unwrap();
    let lanes = u32::try_from(case["lanes"].as_u64().unwrap()).unwrap();
    let size = usize::try_from(case["output_length"].as_u64().unwrap()).unwrap();
    let extra = case["extra_inputs"].as_bool().unwrap();
    let params = argon2::Params::new(memory, passes, lanes, Some(size)).unwrap();
    let mut owners = Owners::new(&params);
    let password = pattern(32, 13, 7);
    let salt = pattern(16, 17, 11);
    let secret = pattern(if extra { 8 } else { 0 }, 19, 3);
    let ad = pattern(if extra { 12 } else { 0 }, 23, 5);
    let argon =
        Argon2::new_with_secret(secret.expose(), Algorithm::Argon2id, Version::V0x13, params)
            .unwrap();
    let mut out = SecretBytes::zeroed(size + 4).unwrap();
    out.expose_mut().fill(0xa5);
    let address = std::ptr::from_ref(owners.work.get()).addr();
    owners.check_locks();
    argon
        .hash_password_into_with_workspace(
            WorkspaceInputs {
                password: password.expose(),
                salt: salt.expose(),
                associated_data: ad.expose(),
            },
            &mut out.expose_mut()[2..size + 2],
            owners.blocks.expose_mut(),
            owners.work.get_mut(),
            owners.workers.expose_mut(),
        )
        .unwrap();
    let expected = hex::decode(case["tag"].as_str().unwrap()).unwrap();
    let equal = out.expose()[2..size + 2] == expected;
    assert!(equal);
    assert!(out.expose()[..2].iter().all(|byte| *byte == 0xa5));
    assert!(out.expose()[size + 2..].iter().all(|byte| *byte == 0xa5));
    let stable = std::ptr::from_ref(owners.work.get()).addr() == address;
    assert!(stable);
    owners.check_locks();
    for worker in owners.workers.expose() {
        assert_eq!(
            worker.completed_segments(),
            Some(usize::try_from(passes * 4).unwrap())
        );
    }
}

#[test]
fn invalid_argon2_geometry_and_inputs_refuse_before_output_writes() {
    let params = argon2::Params::new(32, 3, 4, Some(32)).unwrap();
    let mut owners = Owners::new(&params);
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password = pattern(32, 13, 7);
    let salt = pattern(16, 17, 11);
    let ad = pattern(33, 23, 5);
    for mode in 0..5 {
        let mut out = SecretBytes::zeroed(if mode == 0 { 31 } else { 32 }).unwrap();
        out.expose_mut().fill(0xa5);
        let memory_length = owners.blocks.expose().len() - usize::from(mode == 1);
        let lanes = owners.workers.expose().len() - usize::from(mode == 2);
        let inputs = WorkspaceInputs {
            password: password.expose(),
            salt: if mode == 3 { &[] } else { salt.expose() },
            associated_data: if mode == 4 { ad.expose() } else { &[] },
        };
        assert!(
            argon
                .hash_password_into_with_workspace(
                    inputs,
                    out.expose_mut(),
                    &mut owners.blocks.expose_mut()[..memory_length],
                    owners.work.get_mut(),
                    &mut owners.workers.expose_mut()[..lanes],
                )
                .is_err()
        );
        assert!(out.expose().iter().all(|byte| *byte == 0xa5));
        for worker in owners.workers.expose() {
            assert_eq!(worker.completed_segments(), Some(0));
        }
        owners.check_locks();
    }
}
