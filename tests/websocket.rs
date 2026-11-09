//! The WebSocket binding over a real socket.
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
use xumux::frame::code;
use xumux::{ws, Acceptor, ChannelSpec, Options, Session};

async fn server() -> (std::net::SocketAddr, tokio::task::JoinHandle<xumux::Result<Session>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let (sock, _) = l.accept().await.unwrap();
        ws::accept(sock, Options::default(), Acceptor::default().policy(|_| Ok(())), |o| o.is_none() || o == Some("https://good.example")).await
    });
    (addr, h)
}

async fn raw(addr: std::net::SocketAddr) -> tokio_tungstenite::WebSocketStream<TcpStream> {
    let mut req = format!("ws://{addr}/xumux").into_client_request().unwrap();
    req.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static("xumux"));
    tokio_tungstenite::client_async(req, TcpStream::connect(addr).await.unwrap()).await.unwrap().0
}

#[tokio::test]
async fn messages_cross_and_the_close_exchange_completes() {
    let (addr, h) = server().await;
    let sock = TcpStream::connect(addr).await.unwrap();
    let opts = Options::default();
    let w = ws::client_handshake(sock, &format!("ws://{addr}/xumux"), &opts).await.unwrap();
    let (c, _) = ws::connect(w, opts, Acceptor::default(), vec![]).await.unwrap();
    let s = h.await.unwrap().unwrap();
    let tx = c.open_channel(ChannelSpec::reliable("a")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    let big = Bytes::from(vec![3u8; 200_000]);
    tx.send(5, big.clone()).await.unwrap();
    let m = rx.receive().await.unwrap().unwrap();
    assert_eq!((m.ty, m.payload), (5, big));
    assert!(tx.ping().await.unwrap() < Duration::from_secs(1));
    c.close(code::NORMAL, "").await;
    assert_eq!(tokio::time::timeout(Duration::from_secs(2), s.closed()).await.unwrap().code, code::NORMAL);
}

async fn expect_close(mut w: tokio_tungstenite::WebSocketStream<TcpStream>, send: Message, want: u64) {
    w.send(send).await.unwrap();
    while let Some(Ok(m)) = tokio::time::timeout(Duration::from_secs(2), w.next()).await.unwrap() {
        if let Message::Binary(b) = m {
            if b[2] == 0x20 {
                let v: serde_json::Value = serde_json::from_slice(&b[8..]).unwrap();
                assert_eq!(v["code"].as_u64(), Some(want));
                return;
            }
        }
    }
    panic!("no CLOSE arrived");
}

#[tokio::test]
async fn a_text_message_closes_with_1002() {
    let (addr, h) = server().await;
    expect_close(raw(addr).await, Message::text("hello"), 1002).await;
    assert!(h.await.unwrap().is_err());
}

#[tokio::test]
async fn a_length_mismatch_closes_with_4001() {
    // The spec's `length-mismatch` vector: declares 8 bytes, carries 4.
    let (addr, _h) = server().await;
    let wire = hex::decode("000101000000000800000000").unwrap();
    expect_close(raw(addr).await, Message::binary(wire), 4001).await;
}

#[tokio::test]
async fn upgrades_need_the_subprotocol_and_an_allowed_origin() {
    let (addr, _h) = server().await;
    let req = format!("ws://{addr}/xumux").into_client_request().unwrap();
    assert!(tokio_tungstenite::client_async(req, TcpStream::connect(addr).await.unwrap()).await.is_err());

    let (addr, _h) = server().await;
    let mut req = format!("ws://{addr}/xumux").into_client_request().unwrap();
    req.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static("xumux"));
    req.headers_mut().insert("origin", HeaderValue::from_static("https://evil.example"));
    assert!(tokio_tungstenite::client_async(req, TcpStream::connect(addr).await.unwrap()).await.is_err());
}
