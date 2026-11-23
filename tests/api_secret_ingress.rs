//! DE: Fragmentierter/Chunked-Eingang mit Escapes und Trailern am echten Server.
//! EN: Fragmented/chunked input with escapes and trailers through the real server.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pqkeep::api::{self, AppState, Limits, TokenHash};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

async fn start() -> (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        validate_min: Duration::ZERO,
        ..Limits::default()
    };
    let state = AppState::new(TokenHash::of("synthetic-fixture").unwrap(), limits);
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(api::serve(listener, state, async {
        let _ = rx.await;
    }));
    (addr, tx, task)
}

async fn response(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(out).unwrap()
}

#[tokio::test]
async fn fragmented_chunked_escaped_input_and_trailers_preserve_http_semantics() {
    let (addr, tx, task) = start().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let header = b"POST /v1/validate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-fixture\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: X-Fixture\r\n\r\n";
    for part in header.chunks(7) {
        stream.write_all(part).await.unwrap();
    }
    for part in br#"{"passphrase":"syn\u0074hetic","lang":"en"}"#.chunks(3) {
        stream
            .write_all(format!("{:x}\r\n", part.len()).as_bytes())
            .await
            .unwrap();
        stream.write_all(part).await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
    }
    stream
        .write_all(b"0\r\nX-Fixture: synthetic-trailer\r\n\r\n")
        .await
        .unwrap();
    let result = response(&mut stream).await;
    assert!(result.starts_with("HTTP/1.1 200"));
    assert!(!result.contains("synthetic"));
    tx.send(()).unwrap();
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn malformed_partial_request_is_generic_and_server_accepts_a_fresh_connection() {
    let (addr, tx, task) = start().await;
    let body = br#"{"passphrase":"syn\u0074hetic","unknown":1}"#;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let header = format!(
        "POST /v1/validate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let result = response(&mut stream).await;
    assert!(result.starts_with("HTTP/1.1 400"));
    assert!(result.contains("bad_request") && !result.contains("synthetic"));
    let mut health = TcpStream::connect(addr).await.unwrap();
    health
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert!(response(&mut health).await.starts_with("HTTP/1.1 200"));
    tx.send(()).unwrap();
    assert!(task.await.unwrap().is_ok());
}
