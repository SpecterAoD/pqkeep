//! DE: Ohne Speichersperre wird die Secret-Verarbeitung verweigert.
//! Eigene Testdatei, da die Grenze den ganzen Testprozess betrifft (nur Linux).
//! EN: Secret processing is refused when memory locking is unavailable.
//! Own test file because the limit affects the whole test process (Linux only).

// DE: Tests dürfen unwrap/expect nutzen (auch in Hilfsfunktionen); Produktionscode nicht.
// EN: Tests may use unwrap/expect (also in helpers); production code may not.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(target_os = "linux")]
struct Unread<'a>(&'a mut bool);
#[cfg(target_os = "linux")]
impl std::io::Read for Unread<'_> {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        *self.0 = true;
        Ok(0)
    }
}

#[cfg(target_os = "linux")]
#[test]
fn locking_failure_refuses_secret_processing() {
    use pqkeep::crypto::{SecretBytes, aead};
    use pqkeep::hardening::memlock;
    use rustix::process::{Resource, Rlimit, setrlimit};

    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    setrlimit(Resource::Memlock, zero).unwrap();

    let before = memlock::stats();
    assert!(matches!(
        SecretBytes::new(vec![1u8; 4096]),
        Err(pqkeep::Error::MemoryLock)
    ));
    assert!(memlock::stats().failed_attempts > before.failed_attempts);
    assert!(matches!(
        aead::generate_key(),
        Err(pqkeep::Error::MemoryLock)
    ));
    assert_metadata_refused();
    let mut called = false;
    assert!(matches!(
        pqkeep::sign::digest_reader(Unread(&mut called)),
        Err(pqkeep::Error::MemoryLock)
    ));
    assert!(!called);
    assert!(matches!(
        aead::seal(&[0; 32], b"synthetic", b""),
        Err(pqkeep::Error::MemoryLock)
    ));
    #[cfg(feature = "api")]
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        assert!(matches!(
            pqkeep::api::token::create(&path, pqkeep::envelope::Overwrite::No),
            Err(pqkeep::Error::MemoryLock)
        ));
        assert!(!path.exists());
        assert_server_rejects_before_any_input();
    }
}

#[cfg(target_os = "linux")]
fn assert_metadata_refused() {
    use pqkeep::files::{ConfidentialText, paths::PathSet};
    assert!(matches!(
        ConfidentialText::from_text("fixture"),
        Err(pqkeep::Error::MemoryLock)
    ));
    assert!(matches!(
        PathSet::default().insert(&["fixture"], true),
        Err(pqkeep::Error::MemoryLock)
    ));
}

#[cfg(all(target_os = "linux", feature = "api"))]
fn assert_server_rejects_before_any_input() {
    use pqkeep::api::{self, AppState, Limits, TokenHash};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            format!("pqkeep-token-v1 sha3-256 {}\n", "00".repeat(32)),
        )
        .unwrap();
        let state = AppState::new(TokenHash::load(file.path()).unwrap(), Limits::default());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(api::serve(listener, state, async {
            let _ = rx.await;
        }));
        let mut client = TcpStream::connect(addr).await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read(&mut [0u8; 1]),
        )
        .await
        .unwrap();
        assert!(matches!(result, Ok(0)));
        tx.send(()).unwrap();
        assert!(task.await.unwrap().is_ok());
    });
}
