//! The QUIC binding over WebTransport, which is how browsers reach it: one session stream, opened by
//! the client, at the path `/xumux`. Everything else is as in [`crate::quic`], including datagram
//! channels. The caller runs the endpoint, because it decides who may connect.
use std::time::Instant;

use bytes::Bytes;
use wtransport::{Connection, VarInt};

use crate::core::{Core, Options, Role, QUIC_MULTISTREAM};
use crate::error::{Error, Result};
use crate::session::{Acceptor, DatagramPath, Session};

pub const PATH: &str = "/xumux";

#[derive(Clone)]
struct Datagrams(Connection);

impl DatagramPath for Datagrams {
    async fn read(&self) -> Option<Bytes> {
        self.0.receive_datagram().await.ok().map(|d| d.payload())
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

/// Runs the server side on an accepted WebTransport session.
pub async fn accept(conn: Connection, mut opts: Options, acceptor: Acceptor) -> Result<Session> {
    opts.max_datagram = conn.max_datagram_size();
    if !opts.extensions.iter().any(|e| e == QUIC_MULTISTREAM) && opts.max_datagram.is_some() {
        opts.extensions.push(QUIC_MULTISTREAM.into());
    }
    // The first stream carries HELLO. Without dedicated streams, others are refused.
    let timeout = opts.handshake_timeout;
    let (send, recv) = tokio::time::timeout(timeout, conn.accept_bi()).await.map_err(|_| Error::Timeout)?.map_err(io)?;
    let refuse = conn.clone();
    tokio::spawn(async move {
        while let Ok((mut s, r)) = refuse.accept_bi().await {
            r.stop(VarInt::from_u32(0));
            let _ = s.reset(VarInt::from_u32(0));
        }
    });
    let core = Core::new(Role::Server, opts, acceptor.policy, acceptor.authorize, Instant::now())?;
    let session = Session::spawn_quic(core, recv, send, Datagrams(conn.clone()));
    session.finish_handshake_pub().await.inspect_err(|_| conn.close(VarInt::from_u32(0), b""))?;
    let s = session.clone();
    tokio::spawn(async move {
        s.closed().await;
        conn.close(VarInt::from_u32(0), b"");
    });
    Ok(session)
}

/// Runs the client side, for tools and tests. Browsers use their own WebTransport and a xumux library.
pub async fn connect(conn: Connection, mut opts: Options, acceptor: Acceptor) -> Result<Session> {
    opts.max_datagram = conn.max_datagram_size();
    if !opts.extensions.iter().any(|e| e == QUIC_MULTISTREAM) && opts.max_datagram.is_some() {
        opts.extensions.push(QUIC_MULTISTREAM.into());
    }
    let (send, recv) = conn.open_bi().await.map_err(io)?.await.map_err(io)?;
    let now = Instant::now();
    let mut core = Core::new(Role::Client, opts, acceptor.policy, acceptor.authorize, now)?;
    core.start_client(&[], now)?;
    let session = Session::spawn_quic(core, recv, send, Datagrams(conn.clone()));
    session.finish_handshake_pub().await.inspect_err(|_| conn.close(VarInt::from_u32(0), b""))?;
    let s = session.clone();
    tokio::spawn(async move {
        s.closed().await;
        conn.close(VarInt::from_u32(0), b"");
    });
    Ok(session)
}
