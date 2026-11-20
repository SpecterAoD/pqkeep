//! DE: Nur Libtests: begrenzte Pipes, bestätigte Stopppunkte, Kill-/Wait-Guard.
//! EN: Lib tests only: bounded pipes, acknowledged pause points, kill/wait guard.
#![allow(clippy::unwrap_used, clippy::panic)]

use crate::crypto::factor::Factor;
use crate::fault_io_tests::{Action, Plan, Point, Scope};
use crate::security::{Passphrase, StrongPassphrase};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const READY: &[u8] = b"\nPQK-READY\n";
const DONE: &[u8] = b"\nPQK-DONE\n";
const LIMIT: usize = 8192;
const DEADLINE: Duration = Duration::from_secs(60);
type Bytes = Zeroizing<Vec<u8>>;
type Reader = JoinHandle<Bytes>;
pub(crate) type Credentials<'a> = Option<(&'a [u8], &'a [u8])>;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) enum Operation {
    Key,
    Factor,
    Encrypt,
    Decrypt,
    Many,
    VerifyKey,
    VerifyFactor,
    VerifyArchive,
    VerifyOutput,
    VerifyMany,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub root: PathBuf,
    pub operation: Operation,
    pub point: Option<Point>,
    pub after: Option<usize>,
    pub occurrence: usize,
    pub tag: String,
}

impl Request {
    pub(crate) fn new(root: &std::path::Path, operation: Operation, point: Option<Point>) -> Self {
        Self {
            root: root.to_path_buf(),
            operation,
            point,
            after: None,
            occurrence: 1,
            tag: crate::envelope::hex_encode(&crate::crypto::rng::array::<8>().unwrap()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Ready,
    Eof,
}

struct Running {
    child: Child,
    input: Option<ChildStdin>,
    writer: Option<JoinHandle<()>>,
    out: Option<Reader>,
    err: Option<Reader>,
    events: Receiver<Event>,
    reaped: Arc<AtomicBool>,
}

pub(crate) struct Captured {
    pub out: Bytes,
    pub err: Bytes,
}

fn reader(mut pipe: impl Read + Send + 'static, events: Option<mpsc::Sender<Event>>) -> Reader {
    thread::spawn(move || {
        let mut output = Zeroizing::new(Vec::new());
        let mut block = Zeroizing::new([0; 256]);
        let mut ready = false;
        while output.len() <= LIMIT {
            let n = pipe.read(&mut *block).unwrap();
            if n == 0 {
                break;
            }
            for byte in &block[..n] {
                output.push(*byte);
                if !ready && output.ends_with(READY) {
                    if let Some(tx) = &events {
                        let _ = tx.send(Event::Ready);
                    }
                    ready = true;
                }
            }
        }
        if let Some(tx) = &events {
            let _ = tx.send(Event::Eof);
        }
        output
    })
}

impl Running {
    fn start(request: &Request, credentials: Credentials<'_>) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crash_driver_tests::crash_child_entry",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let (tx, events) = mpsc::channel();
        let out = reader(child.stdout.take().unwrap(), Some(tx));
        let err = reader(child.stderr.take().unwrap(), None);
        let mut running = Self {
            child,
            input: None,
            writer: None,
            out: Some(out),
            err: Some(err),
            events,
            reaped: Arc::new(AtomicBool::new(false)),
        };
        running.send(input, encode(request, credentials));
        running
    }

    fn send(&mut self, mut input: ChildStdin, bytes: Bytes) {
        let (tx, rx) = mpsc::channel();
        self.writer = Some(thread::spawn(move || {
            let result = input.write_all(&bytes).map(|()| input);
            let _ = tx.send(result);
        }));
        self.input = Some(rx.recv_timeout(DEADLINE).unwrap().unwrap());
    }

    fn await_ready(&self) {
        assert_eq!(
            self.events.recv_timeout(DEADLINE).unwrap(),
            Event::Ready,
            "Missing checkpoint / Fehlender Fehlerpunkt"
        );
    }

    fn finish(mut self, kill: bool) -> Captured {
        if kill {
            self.child.kill().unwrap();
        } else if let Some(input) = &mut self.input {
            input.write_all(b"C").unwrap();
        }
        self.input.take();
        let status = self.wait();
        assert_eq!(status.success(), !kill);
        #[cfg(target_os = "linux")]
        if kill {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGKILL));
        }
        let out = self.out.take().unwrap().join().unwrap();
        let err = self.err.take().unwrap().join().unwrap();
        assert!(out.len() <= LIMIT && err.len() <= LIMIT);
        assert_eq!(out.windows(DONE.len()).any(|w| w == DONE), !kill);
        validate_stdout(&out, kill);
        Captured { out, err }
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.reaped.store(true, Ordering::SeqCst);
                return status;
            }
            assert!(Instant::now() < deadline, "Child watchdog / Kind-Watchdog");
            // DE: Nur Exit-Watchdog; Kill folgt ACK. EN: Exit watchdog only; ACK selects kill.
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        if self.child.wait().is_ok() {
            self.reaped.store(true, Ordering::SeqCst);
        }
        self.input.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(out) = self.out.take() {
            let _ = out.join();
        }
        if let Some(err) = self.err.take() {
            let _ = err.join();
        }
    }
}

pub(crate) fn run(request: &Request, credentials: Credentials<'_>, kill: bool) -> Captured {
    assert!(!kill || request.point.is_some());
    let child = Running::start(request, credentials);
    if request.point.is_some() {
        child.await_ready();
    }
    child.finish(kill)
}

fn encode(request: &Request, credentials: Credentials<'_>) -> Bytes {
    let descriptor = serde_json::to_vec(request).unwrap();
    let (pass, factor) = credentials.unwrap_or((&[], &[]));
    let mut out = Zeroizing::new(Vec::new());
    for (data, max) in [(&descriptor[..], 4096), (pass, 256), (factor, 32)] {
        assert!(data.len() <= max);
        out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn frame(input: &mut impl Read, max: usize) -> io::Result<Bytes> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_le_bytes(length)).unwrap();
    if length > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut data = Zeroizing::new(vec![0; length]);
    input.read_exact(&mut data)?;
    Ok(data)
}

pub(crate) fn pause() -> io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(READY)?;
    out.flush()?;
    drop(out);
    let mut command = [0];
    std::io::stdin().read_exact(&mut command)?;
    if command != *b"C" {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

#[test]
#[ignore = "Private subprocess entry only; parent crash tests execute it explicitly"]
fn crash_child_entry() {
    let report = crate::hardening::harden_process();
    #[cfg(target_os = "linux")]
    assert!(report.complete(), "Child hardening / Kind-Härtung");
    #[cfg(not(target_os = "linux"))]
    let _ = report;
    let (request, pass, factor) = read_request();
    crate::files::set_temp_tag(&request.tag).unwrap();
    let scope = request.point.map(|point| {
        Scope::new(
            &request.root,
            Plan {
                point,
                occurrence: request.occurrence,
                action: request.after.map_or(Action::Pause, Action::PauseAfter),
            },
        )
    });
    crate::crash_recovery_tests::execute(&request, pass.as_ref(), factor.as_ref()).unwrap();
    if let Some(scope) = scope {
        scope.finish();
    }
    std::io::stdout().write_all(DONE).unwrap();
    std::io::stdout().flush().unwrap();
}

fn read_request() -> (Request, Option<StrongPassphrase>, Option<Factor>) {
    let mut input = std::io::stdin().lock();
    let descriptor = frame(&mut input, 4096).unwrap();
    let request: Request = serde_json::from_slice(&descriptor).unwrap();
    assert!(request.root.is_absolute() && request.root.symlink_metadata().unwrap().is_dir());
    let pass = frame(&mut input, 256).unwrap();
    let factor = frame(&mut input, 32).unwrap();
    let pass = (!pass.is_empty()).then(|| {
        StrongPassphrase::try_from(Passphrase::new(std::str::from_utf8(&pass).unwrap()).unwrap())
            .unwrap()
    });
    let factor = (!factor.is_empty()).then(|| Factor::from_bytes(&factor).unwrap());
    (request, pass, factor)
}

#[test]
fn rec015_child_guard_reaps_on_parent_unwinding() {
    let root = tempfile::tempdir().unwrap();
    let request = Request::new(root.path(), Operation::Factor, Some(Point::AfterTempCreate));
    let child = Running::start(&request, None);
    let reaped = child.reaped.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            child.await_ready();
            let _guard = child;
            panic!("Synthetic parent failure / Synthetischer Parentfehler");
        }))
        .is_err()
    );
    assert!(reaped.load(Ordering::SeqCst));
}

#[test]
fn rec015_unreached_child_point_is_failure_not_skip() {
    let root = tempfile::tempdir().unwrap();
    let request = Request::new(root.path(), Operation::Factor, Some(Point::BeforeFlush));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&request, None, true)))
            .is_err()
    );
    let mut oversized = std::io::Cursor::new(4097u32.to_le_bytes());
    assert_eq!(
        frame(&mut oversized, 4096).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

// DE: Auch unbekannte Kind-Geheimnisse dürfen keine zusätzlichen Logs erzeugen.
// EN: Even child-only secrets must not introduce additional log output.
fn validate_stdout(out: &[u8], killed: bool) {
    let prefix = b"\nrunning 1 test\ntest crash_driver_tests::crash_child_entry ... ";
    let rest = out.strip_prefix(prefix).unwrap();
    if killed {
        assert!(
            rest == READY,
            "Unexpected child output / Unerwartete Kind-Ausgabe"
        );
    } else {
        let rest = rest.strip_prefix(READY).unwrap_or(rest);
        let tail = rest.strip_prefix(DONE).unwrap();
        let tail = tail
            .strip_prefix(b"ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
            .unwrap();
        let tail = std::str::from_utf8(tail).unwrap();
        let (filtered, time) = tail.split_once(" filtered out; finished in ").unwrap();
        assert!(!filtered.is_empty() && filtered.bytes().all(|b| b.is_ascii_digit()));
        let time = time.strip_suffix("s\n\n").unwrap();
        let (whole, fraction) = time.split_once('.').unwrap();
        assert!(!whole.is_empty() && !fraction.is_empty());
        assert!(
            whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit())
        );
    }
}
