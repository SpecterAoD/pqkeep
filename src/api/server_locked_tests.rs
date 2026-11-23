//! DE: Tatsächlich geparste Header, Body-Frames und Trailer im Server messen.
//! EN: Inspect actual parsed headers, body frames and trailers in the server.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    routing::post,
};
use hyper::body::Body as _;
use std::{
    future::poll_fn,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn protected(bytes: &[u8]) {
    assert_ne!(bytes.len(), 0);
    assert!(memlock::is_locked(bytes.as_ptr().addr()));
    assert!(memlock::is_locked(bytes.as_ptr().addr() + bytes.len() - 1));
}

async fn observe(State(count): State<Arc<AtomicUsize>>, mut req: Request) -> StatusCode {
    let auth = req.headers().get("authorization").unwrap();
    protected(auth.as_bytes());
    assert_eq!(auth.to_str().unwrap(), "Bearer synthetic");
    let mut total = 0;
    while let Some(frame) = poll_fn(|cx| Pin::new(req.body_mut()).poll_frame(cx)).await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref()
            && !data.is_empty()
        {
            protected(data);
            assert!(b"synthetic"[total..].starts_with(data));
            total += data.len();
        }
        if let Some(trailers) = frame.trailers_ref() {
            let value = trailers.get("x-fixture").unwrap();
            protected(value.as_bytes());
            assert_eq!(value.to_str().unwrap(), "synthetic");
            count.fetch_add(1, Ordering::SeqCst);
        }
    }
    assert_eq!(total, 9);
    count.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

async fn exchange(app: Router, wire: &[u8]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        connection(stream, peer, app, Duration::from_secs(5)).await;
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    for fragment in wire.chunks(3) {
        client.write_all(fragment).await.unwrap();
        tokio::task::yield_now().await;
    }
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    out
}

#[tokio::test]
async fn actual_server_parsing_retains_locks_for_header_body_and_trailer_owners() {
    let count = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/", post(observe))
        .with_state(count.clone());
    let response = exchange(app, b"POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic\r\nTransfer-Encoding: chunked\r\nTrailer: x-fixture\r\n\r\n3\r\nsyn\r\n6\r\nthetic\r\n0\r\nX-Fixture: synthetic\r\n\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(!response.windows(9).any(|part| part == b"synthetic"));
    assert_eq!(count.load(Ordering::SeqCst), 2);
}
