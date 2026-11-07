//! DE: Echter Server auf `127.0.0.1:0`: Anfrage über TCP, kein Keep-Alive,
//! Header-Timeout (Slowloris), Verbindungslimit, sauberes Beenden.
//! EN: Real server on `127.0.0.1:0`: request over TCP, no keep-alive,
//! header timeout (Slowloris), connection limit, clean shutdown.
#![cfg(feature = "api")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use pqc_keyforge::api::{self, AppState, Limits, TokenHash};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

type Server = (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<std::io::Result<()>>,
);

async fn start(limits: Limits) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::new(TokenHash::of("kf1_x"), limits);
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(api::serve(listener, state, async {
        let _ = rx.await;
    }));
    (addr, tx, handle)
}

async fn read_all(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "Server hat nicht geschlossen / server did not close"
    );
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn health_over_tcp_and_connection_closes() {
    let (addr, tx, handle) = start(Limits::default()).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let response = read_all(&mut s).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("{\"status\":\"ok\"}"));
    assert!(response.to_ascii_lowercase().contains("connection: close"));
    tx.send(()).unwrap();
    assert!(handle.await.unwrap().is_ok());
}

#[tokio::test]
async fn slow_headers_are_cut_off() {
    let limits = Limits {
        header_timeout: Duration::from_millis(200),
        ..Limits::default()
    };
    let (addr, tx, _handle) = start(limits).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let response = read_all(&mut s).await;
    assert!(!response.contains("200 OK"), "{response}");
    tx.send(()).unwrap();
}

#[tokio::test]
async fn excess_connections_are_closed() {
    let limits = Limits {
        max_connections: 1,
        ..Limits::default()
    };
    let (addr, tx, _handle) = start(limits).await;
    // DE: Erste Verbindung belegt den einzigen Platz (sendet nichts).
    // EN: First connection takes the only slot (sends nothing).
    let _hold = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = TcpStream::connect(addr).await.unwrap();
    let _ = second
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    let response = read_all(&mut second).await;
    assert!(response.is_empty(), "{response}");
    tx.send(()).unwrap();
}
