//! DE: Live-Puffer vor Eingabe prüfen. EN: Inspect live buffers before any input.
#![allow(clippy::unwrap_used)]

use super::*;
#[cfg(target_os = "linux")]
use rustix::process::{Resource, Rlimit, setrlimit};

impl Input {
    pub(crate) fn public_fixture(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= 4);
        let mut input = Self::new().unwrap();
        input.scratch.expose_mut()[..bytes.len()].copy_from_slice(bytes);
        input
    }

    pub(crate) fn assert_all_locked(&self) {
        fn locked(bytes: &SecretBytes) {
            for offset in 0..bytes.len() {
                assert!(pqkeep::hardening::memlock::is_locked(
                    bytes.expose().as_ptr() as usize + offset
                ));
            }
        }
        locked(&self.scratch);
        #[cfg(windows)]
        {
            locked(&self.record);
            locked(&self.pending);
        }
    }

    #[cfg(windows)]
    pub(crate) fn assert_record_wiped(&self) {
        assert!(self.record.expose().iter().all(|byte| *byte == 0));
    }
}

#[test]
fn terminal_input_buffers_are_locked_before_any_read() {
    let input = Input::public_fixture(&[]);
    input.assert_all_locked();
    #[cfg(windows)]
    input.assert_record_wiped();
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_input_lock_denial_runs_in_isolated_child() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::terminal_input::tests::terminal_input_denial_child",
            "--ignored",
        ])
        .env("PQKEEP_TERMINAL_INPUT_DENIAL_CHILD", "1")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    successful_child(child);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: nur durch isolierten Elternprozess / isolated parent only"]
fn terminal_input_denial_child() {
    assert_eq!(
        std::env::var("PQKEEP_TERMINAL_INPUT_DENIAL_CHILD").unwrap(),
        "1"
    );
    setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .unwrap();
    assert!(matches!(Input::new(), Err(pqkeep::Error::MemoryLock)));
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_input_truncated_utf8_reports_actual_eof_in_child() {
    use std::io::Write;
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cli::terminal_input::tests::terminal_input_eof_child",
            "--ignored",
        ])
        .env("PQKEEP_TERMINAL_INPUT_EOF_CHILD", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&[0xe2, 0x82])
        .unwrap();
    successful_child(child);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "DE/EN: nur eigener EOF-Elternprozess / own EOF parent only"]
fn terminal_input_eof_child() {
    assert_eq!(
        std::env::var("PQKEEP_TERMINAL_INPUT_EOF_CHILD").unwrap(),
        "1"
    );
    let mut input = Input::new().unwrap();
    input.assert_all_locked();
    assert_eq!(
        input.next().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    input.assert_all_locked();
}

#[cfg(target_os = "linux")]
fn successful_child(mut child: std::process::Child) {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            let output = child.wait_with_output().unwrap();
            assert!(
                std::str::from_utf8(&output.stdout)
                    .unwrap()
                    .contains("1 passed; 0 failed")
            );
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(
                Instant::now() < deadline,
                "isolated terminal input child timed out"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
