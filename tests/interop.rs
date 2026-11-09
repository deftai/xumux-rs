//! Talks to libxumux-go, an independent implementation, in both directions. Needs XUMUX_GO_PEER: the
//! path to a built `interop-peer` from interop/go. Skipped when it's not set.
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use xumux::{Acceptor, ChannelSpec, Options, Session};

fn peer() -> Option<String> {
    std::env::var("XUMUX_GO_PEER").ok()
}

#[tokio::test]
async fn rust_client_to_go_server() {
    let Some(go) = peer() else { return eprintln!("skipped: XUMUX_GO_PEER not set") };
    let mut child = Command::new(go).arg("serve").stdout(Stdio::piped()).kill_on_drop(true).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).await.unwrap();
    let sock = TcpStream::connect(line.trim()).await.unwrap();
    let (r, w) = sock.into_split();
    let opts = Options { ping_interval: 0, ..Options::default() };
    let (s, _) = Session::connect(r, w, opts, Acceptor::default(), vec![]).await.unwrap();
    let ch = s.open_channel(ChannelSpec::reliable("echo")).await.unwrap();
    for size in [0usize, 1, 16385, 65536, 200_000] {
        let data = Bytes::from(vec![(size % 251) as u8; size]);
        ch.send(3, data.clone()).await.unwrap();
        let m = tokio::time::timeout(Duration::from_secs(5), ch.receive()).await.unwrap().unwrap().unwrap();
        assert_eq!((m.ty, m.payload), (3, data));
    }
    // More than the initial window, so WINDOW_UPDATEs must work both ways.
    let (tx, rx) = (ch.clone(), ch.clone());
    let sender = tokio::spawn(async move {
        for _ in 0..20 {
            tx.send(4, Bytes::from(vec![7u8; 200_000])).await.unwrap();
        }
    });
    for _ in 0..20 {
        assert_eq!(rx.receive().await.unwrap().unwrap().payload.len(), 200_000);
    }
    sender.await.unwrap();
    assert!(ch.ping().await.unwrap() < Duration::from_secs(1));
    ch.close(1000, None).await;
    s.close(1000, "").await;
}

#[tokio::test]
async fn go_client_to_rust_server() {
    let Some(go) = peer() else { return eprintln!("skipped: XUMUX_GO_PEER not set") };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let (r, w) = sock.into_split();
        let opts = Options { ping_interval: 0, ..Options::default() };
        let s = Session::accept(r, w, opts, Acceptor::default().policy(|_| Ok(()))).await.unwrap();
        while let Some(ch) = s.accept_channel().await {
            tokio::spawn(async move {
                while let Ok(Some(m)) = ch.receive().await {
                    if ch.send(m.ty, m.payload).await.is_err() {
                        break;
                    }
                }
            });
        }
        s.closed().await
    });
    let out = Command::new(go).arg("dial").arg(addr.to_string()).output().await.unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let info = tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    assert_eq!(info.code, 1000);
}
