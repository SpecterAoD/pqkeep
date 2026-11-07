//! DE: Eigene Accept-Schleife mit hyper (HTTP/1.1), weil `axum::serve` keinen
//! Header-Timeout setzt (Slowloris). Je Verbindung genau eine Anfrage (kein
//! Keep-Alive), Gesamt-Timeout, begrenzte Puffer und begrenzte Zahl gleichzeitiger
//! Verbindungen; überzählige Verbindungen werden sofort geschlossen.
//!
//! EN: Own accept loop with hyper (HTTP/1.1) because `axum::serve` sets no header
//! timeout (Slowloris). Exactly one request per connection (no keep-alive), overall
//! timeout, bounded buffers and a bounded number of concurrent connections; excess
//! connections are closed immediately.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tower::ServiceExt;

use super::{AppState, router};

/// DE: Puffergröße für Header (hyper-Minimum ist 8 KiB). EN: Header buffer size.
const MAX_BUF: usize = 16 * 1024;

/// DE: Nimmt Verbindungen an, bis `shutdown` fertig ist.
/// EN: Accepts connections until `shutdown` completes.
///
/// # Errors
/// DE/EN: Nur Fehler beim Abfragen der lokalen Adresse; Accept-Fehler werden
/// übersprungen / only errors querying the local address; accept errors are skipped.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let _ = listener.local_addr()?;
    let limits = state.limits().clone();
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let app = router(state);
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut shutdown => return Ok(()),
        };
        let Ok((stream, addr)) = accepted else {
            // DE: z. B. zu viele offene Dateien: kurz warten. EN: e.g. EMFILE: back off.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let app = app.clone();
        let (timeout, header_timeout) = (limits.request_timeout, limits.header_timeout);
        tokio::spawn(async move {
            let conn = connection(stream, addr, app, header_timeout);
            let _ = tokio::time::timeout(timeout, conn).await;
            drop(permit);
        });
    }
}

/// DE: Bedient eine Verbindung. EN: Serves one connection.
async fn connection(stream: TcpStream, addr: SocketAddr, app: Router, header_timeout: Duration) {
    let service = service_fn(move |mut req: hyper::Request<Incoming>| {
        req.extensions_mut().insert(ConnectInfo(addr));
        app.clone().oneshot(req.map(Body::new))
    });
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .keep_alive(false)
        .max_buf_size(MAX_BUF)
        .serve_connection(TokioIo::new(stream), service)
        .await;
}
