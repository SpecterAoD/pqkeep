//! DE: Sichere eigene native Testkonsole. EN: Safe own native test console.
#![cfg(windows)]
#![allow(clippy::unwrap_used)]

#[path = "../src/cli/terminal_input.rs"]
mod terminal_input;

use pqkeep_platform::input_fixture::{Console, Event};
use std::fs::{File, OpenOptions};
use std::os::windows::io::AsHandle;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use terminal_input::{Action, Input};

#[test]
fn native_protected_input_runs_in_own_console_child() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_protected_input_child", "--ignored"])
        .env("PQKEEP_NATIVE_INPUT_CHILD", "1")
        // DE/EN: Win32 CREATE_NEW_CONSOLE; nur dieser Testprozess / own test process only.
        .creation_flags(0x10)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            // DE/EN: Ausschließlich feste öffentliche Fixture-Ausgabe / fixed public fixture only.
            assert!(
                output.status.success(),
                "own native input child failed ({}): {} {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                std::str::from_utf8(&output.stdout)
                    .unwrap()
                    .contains("1 passed; 0 failed")
            );
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(
                Instant::now() < deadline,
                "own native input child timed out"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn feed(console: &Console, event: Event, input: &mut Input) -> std::io::Result<Action> {
    input.assert_all_locked();
    console.emit(event).unwrap();
    let result = input.next();
    input.assert_record_wiped();
    result
}

#[test]
#[ignore = "DE/EN: nur eigener Konsolen-Elternprozess / own console parent only"]
fn native_protected_input_child() {
    let console = Console::new().unwrap();
    let original = console.mode().unwrap();
    let mut input = Input::new().unwrap();
    input.assert_all_locked();
    let guard = pqkeep_platform::ConsoleInputMode::new(console.handle()).unwrap();
    // DE/EN: PROCESSED/LINE/ECHO/VT_INPUT aus, alle anderen Bits erhalten / off, others preserved.
    assert_eq!(console.mode().unwrap() & 0x0207, 0);
    assert_eq!(console.mode().unwrap() & !0x0207, original & !0x0207);
    characters(&console, &mut input);
    controls(&console, &mut input);
    let not_console = File::open(std::env::current_exe().unwrap()).unwrap();
    assert!(input.windows(not_console.as_handle()).is_err());
    input.assert_record_wiped();
    console.emit(Event::Alpha).unwrap();
    guard.restore().unwrap();
    assert_eq!(console.mode().unwrap(), original);
    assert!(console.queued().unwrap() > 0);
    queued_cleanup(&console, &mut input, original);
    assert!(pqkeep_platform::ConsoleInputMode::new(not_console.as_handle()).is_err());
    {
        let _guard = pqkeep_platform::ConsoleInputMode::new(console.handle()).unwrap();
        assert!(input.windows(not_console.as_handle()).is_err());
    }
    assert_eq!(console.mode().unwrap(), original);
}

fn characters(console: &Console, input: &mut Input) {
    assert_eq!(feed(console, Event::NonKey, input).unwrap(), Action::Ignore);
    assert_eq!(
        feed(console, Event::Alpha, input).unwrap(),
        Action::Text { len: 2, repeat: 3 }
    );
    assert!(input.text(2).iter().eq("α".as_bytes()));
    assert_eq!(
        feed(console, Event::Release, input).unwrap(),
        Action::Ignore
    );
    assert_eq!(feed(console, Event::High, input).unwrap(), Action::Ignore);
    assert_eq!(
        feed(console, Event::Low, input).unwrap(),
        Action::Text { len: 4, repeat: 2 }
    );
    assert!(input.text(4).iter().eq("🚀".as_bytes()));
}

fn controls(console: &Console, input: &mut Input) {
    assert_eq!(
        feed(console, Event::Backspace, input).unwrap(),
        Action::Backspace(4)
    );
    for event in [Event::Enter, Event::VirtualEnter] {
        assert_eq!(feed(console, event, input).unwrap(), Action::Finish);
    }
    for event in [Event::CtrlC, Event::Escape] {
        assert_eq!(feed(console, event, input).unwrap(), Action::Cancel);
    }
    for event in [Event::InvalidLow, Event::LastLow, Event::ZeroRepeat] {
        assert_eq!(
            feed(console, event, input).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
    assert_eq!(feed(console, Event::High, input).unwrap(), Action::Ignore);
    assert_eq!(
        feed(console, Event::Enter, input).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        feed(console, Event::Alpha, input).unwrap(),
        Action::Text { len: 2, repeat: 3 }
    );
}

fn queued_cleanup(console: &Console, input: &mut Input, original: u32) {
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONOUT$")
        .unwrap();
    assert!(pqkeep_platform::ConsoleInputMode::new(output.as_handle()).is_err());
    let guard = pqkeep_platform::ConsoleInputMode::new(console.handle()).unwrap();
    assert_eq!(input.next().unwrap(), Action::Text { len: 2, repeat: 3 });
    console.emit(Event::Alpha).unwrap();
    assert!(console.queued().unwrap() > 0);
    guard.restore_after_error().unwrap();
    assert_eq!(console.queued().unwrap(), 0);
    assert_eq!(console.mode().unwrap(), original);
    let read_only = OpenOptions::new().read(true).open("CONIN$").unwrap();
    let guard = pqkeep_platform::ConsoleInputMode::new(read_only.as_handle()).unwrap();
    assert_eq!(console.mode().unwrap() & 0x0207, 0);
    input.assert_all_locked();
    console.emit(Event::Alpha).unwrap();
    assert_eq!(
        input.windows(read_only.as_handle()).unwrap(),
        Action::Text { len: 2, repeat: 3 }
    );
    input.assert_record_wiped();
    console.emit(Event::Alpha).unwrap();
    guard.restore_after_error().unwrap();
    assert_eq!(console.queued().unwrap(), 0);
    assert_eq!(console.mode().unwrap(), original);
}
