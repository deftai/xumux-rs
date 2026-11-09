//! The WebTransport binding, over real loopback UDP, with a WebTransport client standing in for a browser.
use std::time::Duration;

use bytes::Bytes;
use wtransport::{ClientConfig, Endpoint, Identity, ServerConfig};
use xumux::{webtransport, Acceptor, ChannelSpec, Options, Session};

async fn pair() -> (Session, Session) {
    let id = Identity::self_signed(["localhost"]).unwrap();
    let hash = id.certificate_chain().as_slice()[0].hash();
    let server = Endpoint::server(ServerConfig::builder().with_bind_default(0).with_identity(id).build()).unwrap();
    let port = server.local_addr().unwrap().port();
    let accepted = tokio::spawn(async move {
        let req = server.accept().await.await.unwrap();
        assert_eq!(req.path(), webtransport::PATH);
        let conn = req.accept().await.unwrap();
        let s = webtransport::accept(conn, Options::default(), Acceptor::default().policy(|_| Ok(()))).await.unwrap();
        (s, server)
    });
    let cfg = ClientConfig::builder().with_bind_default().with_server_certificate_hashes([hash]).build();
    let client = Endpoint::client(cfg).unwrap();
    let conn = client.connect(format!("https://localhost:{port}{}", webtransport::PATH)).await.unwrap();
    let c = webtransport::connect(conn, Options::default(), Acceptor::default().policy(|_| Ok(()))).await.unwrap();
    let (s, server) = accepted.await.unwrap();
    std::mem::forget(server);
    std::mem::forget(client);
    (s, c)
}

#[tokio::test(flavor = "multi_thread")]
async fn reliable_channels_and_datagrams_both_work() {
    let (s, c) = pair().await;
    let tx = s.open_channel(ChannelSpec::reliable("r")).await.unwrap();
    let rx = c.accept_channel().await.unwrap();
    let big = Bytes::from(vec![7u8; 100_000]);
    tx.send(4, big.clone()).await.unwrap();
    let m = rx.receive().await.unwrap().unwrap();
    assert_eq!((m.ty, m.payload), (4, big));

    let tx = s.open_channel(ChannelSpec::datagram("d")).await.unwrap();
    let rx = c.accept_channel().await.unwrap();
    assert!(!tx.properties().unwrap().reliable);
    let max = tx.max_datagram_payload().unwrap();
    assert!(max >= 1000, "room for a slice of video: {max}");
    tx.send(9, vec![1u8; max]).await.unwrap();
    let m = tokio::time::timeout(Duration::from_secs(2), rx.receive()).await.unwrap().unwrap().unwrap();
    assert_eq!((m.ty, m.payload.len()), (9, max));
}
