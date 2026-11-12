//! The QUIC binding: one session stream, ALPN `xumux`, no magic. With quic-multistream/1, channels
//! can also travel on datagrams, which makes them natively unreliable and unordered.
//!
//! Dedicated streams aren't implemented. The draft lets a responder place a channel on the session
//! stream instead of the stream it asked for, and report that, which is what happens here.
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::core::{ChannelSpec, Core, Options, Role, QUIC_MULTISTREAM};
use crate::error::{Error, Result};
use crate::session::{Acceptor, Channel, DatagramPath, Session};

pub const ALPN: &[u8] = b"xumux";

/// Transport settings for interactive use: xumux decides when a connection is dead, so QUIC's idle
/// timeout must be longer than its keepalive (binding §5), and datagrams get room to queue briefly.
pub fn transport_config() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(120).try_into().expect("in range")));
    t.datagram_receive_buffer_size(Some(4 << 20));
    t.datagram_send_buffer_size(4 << 20);
    t
}

#[derive(Clone)]
struct Datagrams(quinn::Connection);

impl DatagramPath for Datagrams {
    async fn read(&self) -> Option<Bytes> {
        self.0.read_datagram().await.ok()
    }

    fn write(&self, b: Bytes) {
        let _ = self.0.send_datagram(b);
    }

    fn max_size(&self) -> Option<usize> {
        self.0.max_datagram_size()
    }
}

fn io(e: impl std::fmt::Display) -> Error {
    Error::Io(e.to_string())
}

/// Ends the QUIC connection once the xumux connection has ended. Holds no handle, so it doesn't keep
/// the connection open.
fn close_with(session: &Session, conn: quinn::Connection) {
    let ended = session.on_end();
    tokio::spawn(async move {
        ended.await;
        conn.close(0u32.into(), b"");
    });
}

/// Runs the server side on an established connection.
pub async fn accept(conn: quinn::Connection, mut opts: Options, acceptor: Acceptor) -> Result<Session> {
    opts.max_datagram = conn.max_datagram_size();
    if !opts.extensions.iter().any(|e| e == QUIC_MULTISTREAM) && opts.max_datagram.is_some() {
        opts.extensions.push(QUIC_MULTISTREAM.into());
    }
    // The first stream carries HELLO. Without dedicated streams, others are refused.
    let timeout = opts.handshake_timeout;
    let (send, recv) = tokio::time::timeout(timeout, conn.accept_bi()).await.map_err(|_| Error::Timeout)?.map_err(io)?;
    let refuse = conn.clone();
    tokio::spawn(async move {
        while let Ok((mut s, mut r)) = refuse.accept_bi().await {
            let _ = r.stop(0u32.into());
            let _ = s.reset(0u32.into());
        }
    });
    let core = Core::new(Role::Server, opts, acceptor.policy, acceptor.authorize, Instant::now())?;
    let session = Session::spawn_quic(core, recv, send, Datagrams(conn.clone()));
    // Before the handshake, so a cancelled one still ends the QUIC connection.
    close_with(&session, conn.clone());
    session.finish_handshake_pub().await.inspect_err(|_| conn.close(0u32.into(), b""))?;
    Ok(session)
}

/// Runs the client side on an established connection. Returns the session and the channels opened
/// in HELLO, or their refusals, in order.
pub async fn connect(conn: quinn::Connection, mut opts: Options, acceptor: Acceptor, channels: Vec<ChannelSpec>) -> Result<(Session, Vec<Result<Channel>>)> {
    opts.max_datagram = conn.max_datagram_size();
    if !opts.extensions.iter().any(|e| e == QUIC_MULTISTREAM) && opts.max_datagram.is_some() {
        opts.extensions.push(QUIC_MULTISTREAM.into());
    }
    let (send, recv) = conn.open_bi().await.map_err(io)?;
    let now = Instant::now();
    let mut core = Core::new(Role::Client, opts, acceptor.policy, acceptor.authorize, now)?;
    let opened = core.start_client(&channels, now)?;
    let waits: Vec<_> = opened.iter().map(|(id, sig)| (*id, sig.clone(), core.hello_channel_waiter(*id).expect("just inserted"))).collect();
    let session = Session::spawn_quic(core, recv, send, Datagrams(conn.clone()));
    // Before the handshake, so a cancelled one still ends the QUIC connection.
    close_with(&session, conn.clone());
    session.finish_handshake_pub().await.inspect_err(|_| conn.close(0u32.into(), b""))?;
    let out = session.hello_channels(waits, channels).await;
    Ok((session, out))
}
