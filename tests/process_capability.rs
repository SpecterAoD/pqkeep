//! DE: Prozessbeobachtung ist lesend; Härtung ausschließlich im eigenen Kind.
//! EN: Process observation is read-only; hardening runs only in an owned child.
#![allow(clippy::unwrap_used)]

use pqkeep::hardening::{harden_process, observe_process};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn actual_readback_and_child_hardening_preserve_parent_policy() {
    let before = observe_process();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_readback_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("PQKEEP_PROCESS_READBACK_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            assert!(
                status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            break;
        }
        let timed_out = Instant::now() >= deadline;
        if timed_out {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(
            !timed_out,
            "DE/EN: Prozessabfrage-Timeout / process query timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(observe_process(), before);
}

#[test]
#[ignore = "DE/EN: Nur vom begrenzten Elternprozess / bounded parent invocation only"]
fn process_readback_child() {
    assert_eq!(std::env::var("PQKEEP_PROCESS_READBACK_CHILD").unwrap(), "1");
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};
        let core = getrlimit(Resource::Core);
        let dumpable = dumpable_behavior().unwrap();
        let observed = observe_process();
        assert_eq!(
            observed.core_dumps_disabled,
            core.current == Some(0) && core.maximum == Some(0)
        );
        assert_eq!(
            observed.not_dumpable,
            dumpable == DumpableBehavior::NotDumpable
        );
        assert_eq!(getrlimit(Resource::Core), core);
        assert_eq!(dumpable_behavior().unwrap(), dumpable);
        let applied = harden_process();
        assert!(applied.complete());
        assert_eq!(applied, observe_process());
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        assert_eq!(getrlimit(Resource::Core).maximum, Some(0));
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    }
    #[cfg(windows)]
    {
        use pqkeep_platform::{WerFlags, current_wer_flags};
        let before = current_wer_flags().unwrap();
        let observed = observe_process();
        assert_eq!(current_wer_flags().unwrap(), before);
        assert_eq!(
            observed.wer_heap_reporting_disabled,
            matches!(before, WerFlags::Present(flags) if flags & 1 != 0)
        );
        let applied = harden_process();
        let after = current_wer_flags().unwrap();
        assert!(applied.wer_heap_reporting_disabled);
        assert_eq!(applied, observe_process());
        assert!(!applied.complete());
        if let (WerFlags::Present(old), WerFlags::Present(new)) = (before, after) {
            assert_eq!(new & old, old);
        }
    }
}
