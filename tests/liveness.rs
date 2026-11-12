//! A connection always ends, and its tasks let go of the transport, even when the peer stops reading.
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{duplex, split, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use xumux::frame::code;
use xumux::{Acceptor, ChannelSpec, Incoming, MessageReader, MessageWriter, Options, Session};

fn frame(channel: u16, ty: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = channel.to_be_bytes().to_vec();
    f.extend([ty, flags]);
    f.extend((payload.len() as u32).to_be_bytes());
    f.extend(payload);
    f
}

const HELLO: &[u8] = br#"{"version":[0,3,0],"pingInterval":0}"#;
const OPEN: &[u8] = br#"{"id":1,"name":"x","reliable":true,"ordered":true}"#;
// A reserved flag is a protocol error, so the server fails with 1002.
const BAD: [u8; 8] = [0, 0, 0x10, 0x80, 0, 0, 0, 0];

fn opts() -> Options {
    Options { close_timeout: Duration::from_millis(200), ping_interval: 0, ..Options::default() }
}

fn acceptor() -> Acceptor {
    Acceptor::default().policy(|_| Ok(()))
}

/// A server over a small duplex, with the test playing the peer by hand: HELLO, then one channel.
async fn raw_server() -> (Session, DuplexStream) {
    let (a, mut peer) = duplex(4096);
    let (r, w) = split(a);
    let srv = tokio::spawn(Session::accept(r, w, opts(), acceptor()));
    peer.write_all(b"XMUX").await.unwrap();
    peer.write_all(&frame(0, 0x01, 0, HELLO)).await.unwrap();
    peer.write_all(&frame(0, 0x03, 0, OPEN)).await.unwrap();
    // Take the magic, WELCOME and CHANNEL_ACK, then stop reading.
    let mut buf = vec![0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_millis(300), peer.read(&mut buf)).await;
    (srv.await.unwrap().unwrap(), peer)
}

/// Fills the duplex and the writer's batch, so the server's writer is stuck in write_all.
async fn block_writer(s: &Session) {
    let ch = s.accept_channel().await.unwrap();
    for _ in 0..8 {
        ch.queue(1, Bytes::from(vec![0u8; 32768])).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn a_failure_with_a_blocked_writer_still_ends_the_connection() {
    let (s, mut peer) = raw_server().await;
    block_writer(&s).await;
    peer.write_all(&BAD).await.unwrap();
    let info = tokio::time::timeout(Duration::from_secs(2), s.closed()).await.expect("ends within the close timeout");
    assert_eq!(info.code, code::PROTOCOL_ERROR);
}

#[tokio::test]
async fn a_peer_close_with_a_blocked_writer_still_ends_the_connection() {
    let (s, mut peer) = raw_server().await;
    block_writer(&s).await;
    peer.write_all(&frame(0, 0x20, 0, br#"{"code":1000}"#)).await.unwrap();
    let info = tokio::time::timeout(Duration::from_secs(2), s.closed()).await.expect("ends within the close timeout");
    assert_eq!(info.code, code::NORMAL);
}

#[tokio::test]
async fn the_transport_is_released_once_the_connection_ends() {
    let (s, mut peer) = raw_server().await;
    peer.write_all(&frame(0, 0x20, 0, br#"{"code":1000}"#)).await.unwrap();
    // The reply CLOSE, then the server's end of the stream.
    let mut buf = vec![0u8; 4096];
    while tokio::time::timeout(Duration::from_secs(2), peer.read(&mut buf)).await.expect("server ends its write side").unwrap() > 0 {}
    tokio::time::timeout(Duration::from_secs(2), s.closed()).await.unwrap();
    // Both halves gone means the stream is closed, and writing to it fails. One byte is too few
    // for a header, so it can't be what wakes the reader.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(peer.write_all(b"x").await.is_err(), "the server still holds its read half");
}

/// A writer that can be made to fail.
struct Breakable<W> {
    inner: W,
    broken: Arc<AtomicBool>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Breakable<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.broken.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken")));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn send_reports_a_failed_write() {
    let (a, b) = duplex(1 << 16);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let broken = Arc::new(AtomicBool::new(false));
    let bw = Breakable { inner: bw, broken: broken.clone() };
    let srv = tokio::spawn(Session::accept(ar, aw, opts(), acceptor()));
    let (c, _) = Session::connect(br, bw, opts(), acceptor(), vec![]).await.unwrap();
    let _s = srv.await.unwrap().unwrap();
    let ch = c.open_channel(ChannelSpec::reliable("x")).await.unwrap();
    broken.store(true, Ordering::SeqCst);
    let r = tokio::time::timeout(Duration::from_secs(2), ch.send(1, Bytes::from_static(b"lost"))).await.unwrap();
    assert!(r.is_err(), "a message that never reached the transport was reported as sent");
}

// --- Message pipes ---

struct MemReader {
    rx: mpsc::Receiver<Incoming>,
    dropped: Arc<AtomicBool>,
}

impl Drop for MemReader {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl MessageReader for MemReader {
    async fn read(&mut self) -> Option<Incoming> {
        self.rx.recv().await
    }
}

struct MemWriter {
    tx: mpsc::Sender<Incoming>,
    broken: Arc<AtomicBool>,
}

impl MessageWriter for MemWriter {
    async fn write(&mut self, message: Bytes) -> io::Result<()> {
        if self.broken.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken"));
        }
        self.tx.send(Incoming::Binary(message)).await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
    }

    async fn close(&mut self) {}
}

/// One direction of a message pipe that holds at most `cap` messages.
fn mem(cap: usize) -> (MemWriter, MemReader, Arc<AtomicBool>, Arc<AtomicBool>) {
    let (tx, rx) = mpsc::channel(cap);
    let broken = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    (MemWriter { tx, broken: broken.clone() }, MemReader { rx, dropped: dropped.clone() }, broken, dropped)
}

/// A message-pipe server, with the test as the peer: HELLO, then one channel.
async fn raw_message_server(out_cap: usize) -> (Session, mpsc::Sender<Incoming>, mpsc::Receiver<Incoming>, Arc<AtomicBool>) {
    let (in_tx, in_rx) = mpsc::channel(64);
    let dropped = Arc::new(AtomicBool::new(false));
    let reader = MemReader { rx: in_rx, dropped: dropped.clone() };
    let (out_tx, mut out_rx) = mpsc::channel(out_cap);
    let writer = MemWriter { tx: out_tx, broken: Arc::new(AtomicBool::new(false)) };
    let srv = tokio::spawn(Session::accept_messages(reader, writer, opts(), acceptor()));
    in_tx.send(Incoming::Binary(frame(0, 0x01, 0, HELLO).into())).await.unwrap();
    in_tx.send(Incoming::Binary(frame(0, 0x03, 0, OPEN).into())).await.unwrap();
    // WELCOME and CHANNEL_ACK.
    for _ in 0..2 {
        out_rx.recv().await.unwrap();
    }
    (srv.await.unwrap().unwrap(), in_tx, out_rx, dropped)
}

#[tokio::test]
async fn a_failure_with_a_blocked_message_writer_still_ends_the_connection() {
    let (s, in_tx, _out_rx, _) = raw_message_server(1).await;
    block_writer(&s).await;
    in_tx.send(Incoming::Binary(BAD.to_vec().into())).await.unwrap();
    let info = tokio::time::timeout(Duration::from_secs(2), s.closed()).await.expect("ends within the close timeout");
    assert_eq!(info.code, code::PROTOCOL_ERROR);
}

#[tokio::test]
async fn a_message_reader_is_released_once_the_connection_ends() {
    let (s, _in_tx, _out_rx, dropped) = raw_message_server(64).await;
    // The peer never answers, so the close timeout ends it.
    tokio::time::timeout(Duration::from_secs(2), s.close(code::NORMAL, "")).await.unwrap();
    let released = tokio::time::timeout(Duration::from_secs(2), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(released.is_ok(), "the reader is still held after the connection ended");
}

#[tokio::test]
async fn send_reports_a_failed_message_write() {
    let (cw, sr, broken, _) = mem(64);
    let (sw, cr, _, _) = mem(64);
    let srv = tokio::spawn(Session::accept_messages(sr, sw, opts(), acceptor()));
    let (c, _) = Session::connect_messages(cr, cw, opts(), acceptor(), vec![]).await.unwrap();
    let _s = srv.await.unwrap().unwrap();
    let ch = c.open_channel(ChannelSpec::reliable("x")).await.unwrap();
    broken.store(true, Ordering::SeqCst);
    let r = tokio::time::timeout(Duration::from_secs(2), ch.send(1, Bytes::from_static(b"lost"))).await.unwrap();
    assert!(r.is_err(), "a message that never reached the transport was reported as sent");
}
