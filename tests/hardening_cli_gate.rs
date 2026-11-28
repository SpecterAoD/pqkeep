//! DE: Eigene begrenzte CLI-Prozesse bei echter Syscall-Verweigerung prüfen.
//! EN: Test bounded own CLI processes under actual syscall refusal.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::{
    collections::BTreeMap,
    io::Read,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn actual_cli_refuses_before_input_or_output_on_missing_linux_capability() {
    use rustix::process::{Resource, dumpable_behavior, getrlimit};
    let before = (getrlimit(Resource::Core), dumpable_behavior());
    for mode in ["read-core", "set-dumpable", "read-dumpable"] {
        let root = tempfile::tempdir().unwrap();
        let mut child = probe(mode, root.path());
        let (status, stdout, stderr) = child.output();
        assert_eq!(status.code(), Some(1), "{mode}: {stderr}");
        assert!(
            stderr.contains("process protection unavailable"),
            "{mode}: {stderr}"
        );
        assert!(!stderr.contains("panicked"));
        assert!(!root.path().join("must-not-exist.json").exists());
        // DE/EN: libtest schreibt vor exec öffentliche Startzeilen / public libtest startup before exec.
        assert!(!stdout.contains("key") && !stdout.contains("Schlüssel"));
    }
    assert_eq!((getrlimit(Resource::Core), dumpable_behavior()), before);
}

fn probe(mode: &str, root: &std::path::Path) -> Owned {
    Owned(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "denied_cli_entry",
                "--ignored",
                "--test-threads=1",
            ])
            .env("PQKEEP_GATE_DENIAL", mode)
            .env("PQKEEP_GATE_ROOT", root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

impl Owned {
    fn output(&mut self) -> (std::process::ExitStatus, String, String) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "own CLI probe timed out");
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = String::new();
        let mut stderr = String::new();
        self.0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        self.0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        (status, stdout, stderr)
    }
}

fn condition(arg: u8, value: u64) -> SeccompCondition {
    SeccompCondition::new(arg, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, value).unwrap()
}

fn denial(mode: &str) -> BpfProgram {
    let mut rules = BTreeMap::new();
    if mode == "read-core" {
        rules.insert(
            libc::SYS_prlimit64,
            vec![
                SeccompRule::new(vec![
                    condition(1, u64::from(libc::RLIMIT_CORE)),
                    condition(2, 0),
                ])
                .unwrap(),
            ],
        );
    } else {
        let operation = if mode == "set-dumpable" {
            libc::PR_SET_DUMPABLE
        } else {
            libc::PR_GET_DUMPABLE
        };
        rules.insert(
            libc::SYS_prctl,
            vec![SeccompRule::new(vec![condition(0, u64::try_from(operation).unwrap())]).unwrap()],
        );
    }
    BpfProgram::try_from(
        SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(u32::try_from(libc::EPERM).unwrap()),
            TargetArch::try_from(std::env::consts::ARCH).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "DE/EN: Nur eigener begrenzter exec-Prozess / bounded own exec process only"]
fn denied_cli_entry() {
    use std::os::unix::process::CommandExt;
    let mode = std::env::var("PQKEEP_GATE_DENIAL").unwrap();
    let root = std::env::var_os("PQKEEP_GATE_ROOT").unwrap();
    seccompiler::apply_filter(&denial(&mode)).unwrap();
    // DE: exec ersetzt nur diesen eigenen Prozess; kein Enkel bleibt bei Timeout zurück.
    // EN: exec replaces only this own process; timeout leaves no grandchild behind.
    let error = Command::new(env!("CARGO_BIN_EXE_pqkeep"))
        .args([
            "generate",
            "--name",
            "public-gate-fixture",
            "--algorithm",
            "ml-dsa-65",
            "--out",
            "must-not-exist.json",
            "--passphrase-stdin",
        ])
        .current_dir(root)
        .stdin(Stdio::null())
        .exec();
    eprintln!("own fixture exec failed: {}", error.kind());
    std::process::exit(90);
}
