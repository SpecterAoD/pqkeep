//! DE: Echtes assess-Blocking-Queue-Ownership bei Caller-Abbruch beobachten.
//! EN: Observe actual assess blocking-queue ownership when its caller cancels.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use std::{
    future::{Future, poll_fn},
    sync::mpsc,
    task::Poll,
    time::Duration,
};

#[test]
fn cancelled_assessment_keeps_queued_passphrase_locked_until_worker_runs() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (release, wait) = mpsc::channel();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            let _ = wait.recv_timeout(Duration::from_secs(5));
        });
        ready.await.unwrap();
        let req: ValidateRequest = serde_json::from_str(r#"{"passphrase":"synthetic"}"#).unwrap();
        let address = req.passphrase.0.expose().as_ptr().addr();
        assert!(memlock::is_locked(address));
        let mut assessment = Box::pin(assess(req));
        poll_fn(|cx| {
            assert!(assessment.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // DE: Job ist hinter blockiertem Worker eingeplant; Caller-Future abbrechen.
        // EN: Job is queued behind the blocked worker; cancel the caller future.
        drop(assessment);
        assert!(memlock::is_locked(address));
        release.send(()).unwrap();
        blocker.await.unwrap();
    });
    // DE: Runtime wartet auf eingeplante Jobs; keinen freigegebenen Speicher lesen.
    // EN: Runtime waits for queued jobs; never inspect freed memory.
    runtime.shutdown_timeout(Duration::from_secs(5));
}
