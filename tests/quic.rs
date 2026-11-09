//! The QUIC binding and datagram channels, over real loopback UDP.
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use xumux::frame::code;
use xumux::{quic, Acceptor, ChannelSpec, Error, Options, Session};

async fn endpoints() -> (quinn::Endpoint, quinn::Endpoint, std::net::SocketAddr) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();

    let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![der.clone()], key).unwrap();
    tls.alpn_protocols = vec![quic::ALPN.to_vec()];
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()));
    server.transport_config(Arc::new(quic::transport_config()));
    let s = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = s.local_addr().unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let mut tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![quic::ALPN.to_vec()];
    let mut client = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap()));
    client.transport_config(Arc::new(quic::transport_config()));
    let mut c = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    c.set_default_client_config(client);
    (s, c, addr)
}

async fn pair_with(server_opts: Options, client_opts: Options) -> (Session, Session, quinn::Endpoint, quinn::Endpoint) {
    let (se, ce, addr) = endpoints().await;
    let accepting = se.clone();
    let server = tokio::spawn(async move {
        let conn = accepting.accept().await.unwrap().await.unwrap();
        quic::accept(conn, server_opts, Acceptor::default().policy(|_| Ok(()))).await.unwrap()
    });
    let conn = ce.connect(addr, "localhost").unwrap().await.unwrap();
    let (c, _) = quic::connect(conn, client_opts, Acceptor::default().policy(|_| Ok(())), vec![]).await.unwrap();
    (server.await.unwrap(), c, se, ce)
}

async fn pair() -> (Session, Session, quinn::Endpoint, quinn::Endpoint) {
    pair_with(Options::default(), Options::default()).await
}

#[tokio::test]
async fn the_session_stream_carries_reliable_channels_of_any_size() {
    let (s, c, _a, _b) = pair().await;
    let tx = c.open_channel(ChannelSpec::reliable("a")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    assert_eq!(tx.properties().unwrap().reliable, true);
    let big = Bytes::from(vec![9u8; 200_000]);
    tx.send(4, big.clone()).await.unwrap();
    let m = rx.receive().await.unwrap().unwrap();
    assert_eq!((m.ty, m.payload), (4, big));
    assert!(tx.ping().await.unwrap() < Duration::from_secs(1));
}

#[tokio::test]
async fn a_datagram_channel_is_unreliable_and_carries_messages() {
    let (s, c, _a, _b) = pair().await;
    let tx = c.open_channel(ChannelSpec::datagram("pointer")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    let p = tx.properties().unwrap();
    assert_eq!((p.reliable, p.ordered), (false, false));
    assert_eq!(rx.properties().unwrap().reliable, false);
    assert!(tx.max_datagram_payload().unwrap() > 1000);
    assert_eq!(tx.send_credit().unwrap(), u64::MAX, "not flow-controlled");

    tx.send(1, Bytes::from_static(b"move")).await.unwrap();
    let m = tokio::time::timeout(Duration::from_secs(2), rx.receive()).await.unwrap().unwrap().unwrap();
    assert_eq!((m.ty, &m.payload[..]), (1, &b"move"[..]));

    // Both directions, and probes travel the same path.
    rx.send(2, Bytes::from_static(b"back")).await.unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(2), tx.receive()).await.unwrap().unwrap().unwrap().ty, 2);
    assert!(tokio::time::timeout(Duration::from_secs(2), tx.ping()).await.unwrap().unwrap() < Duration::from_secs(1));
}

#[tokio::test]
async fn a_message_too_large_for_a_datagram_is_refused_not_fragmented() {
    let (s, c, _a, _b) = pair().await;
    let tx = c.open_channel(ChannelSpec::datagram("video")).await.unwrap();
    let _rx = s.accept_channel().await.unwrap();
    let max = tx.max_datagram_payload().unwrap();
    assert!(tx.send(1, Bytes::from(vec![0u8; max])).await.is_ok());
    assert!(matches!(tx.send(1, Bytes::from(vec![0u8; max + 1])).await, Err(Error::TooLarge { .. })));
}

#[tokio::test]
async fn datagrams_stay_on_their_channels_beside_a_bulk_stream() {
    let (s, c, _a, _b) = pair().await;
    let bulk = c.open_channel(ChannelSpec::reliable("bulk")).await.unwrap();
    let bulk_rx = s.accept_channel().await.unwrap();
    let dg = c.open_channel(ChannelSpec::datagram("input")).await.unwrap();
    let dg_rx = s.accept_channel().await.unwrap();
    let sender = tokio::spawn(async move {
        for _ in 0..30 {
            bulk.send(1, Bytes::from(vec![1u8; 200_000])).await.unwrap();
        }
    });
    let reader = tokio::spawn(async move {
        for _ in 0..30 {
            assert_eq!(bulk_rx.receive().await.unwrap().unwrap().payload.len(), 200_000);
        }
    });
    let mut got = 0;
    for i in 0..50u8 {
        dg.send(2, Bytes::copy_from_slice(&[i])).await.unwrap();
        if let Ok(Ok(Some(m))) = tokio::time::timeout(Duration::from_millis(100), dg_rx.receive()).await {
            assert_eq!(m.ty, 2);
            got += 1;
        }
    }
    assert!(got > 40, "{got} of 50 arrived");
    reader.await.unwrap();
    sender.await.unwrap();
}

#[tokio::test]
async fn a_request_for_a_dedicated_stream_lands_on_the_session_stream() {
    let (s, c, _a, _b) = pair().await;
    let spec = ChannelSpec { quic: Some("stream".into()), ..ChannelSpec::reliable("s") };
    let tx = c.open_channel(spec).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    assert_eq!(tx.properties().unwrap().reliable, true);
    assert!(tx.max_datagram_payload().is_none());
    tx.send(1, Bytes::from(vec![0u8; 100_000])).await.unwrap();
    assert_eq!(rx.receive().await.unwrap().unwrap().payload.len(), 100_000);
}

#[tokio::test]
async fn a_closed_datagram_channels_id_waits_before_reuse() {
    let (s, c, _a, _b) = pair().await;
    let first = c.open_channel(ChannelSpec::datagram("a")).await.unwrap();
    let _rx = s.accept_channel().await.unwrap();
    assert_eq!(first.id(), 1);
    first.close(code::NORMAL, None).await;
    let next = c.open_channel(ChannelSpec::reliable("b")).await.unwrap();
    let _rx2 = s.accept_channel().await.unwrap();
    assert_eq!(next.id(), 3, "ID 1 is in quarantine");
    // A reliable channel's ID is free as soon as both sides have closed.
    next.close(code::NORMAL, None).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(c.open_channel(ChannelSpec::reliable("c")).await.unwrap().id(), 1, "the wait is over");
}

#[tokio::test]
async fn closing_ends_both_sides() {
    let (s, c, _a, _b) = pair().await;
    c.close(4600, "bye").await;
    assert_eq!(tokio::time::timeout(Duration::from_secs(2), s.closed()).await.unwrap().code, 4600);
}

/// What datagrams are for. A lost packet delays everything on one stream, but not a datagram.
/// Latency here is only what the local stack adds, as there's no loss on loopback.
#[tokio::test]
async fn input_on_datagrams_gets_through_beside_flat_out_bulk() {
    let (s, c, _a, _b) = pair().await;
    let bulk = c.open_channel(ChannelSpec::reliable("bulk")).await.unwrap();
    let bulk_rx = s.accept_channel().await.unwrap();
    let dg = c.open_channel(ChannelSpec::datagram("input")).await.unwrap();
    let dg_srv = s.accept_channel().await.unwrap();
    tokio::spawn(async move { while let Ok(Some(_)) = bulk_rx.receive().await {} });
    tokio::spawn(async move {
        while let Ok(Some(m)) = dg_srv.receive().await {
            let _ = dg_srv.send(m.ty, m.payload).await;
        }
    });
    let sender = tokio::spawn(async move {
        let msg = Bytes::from(vec![0u8; 200_000]);
        while bulk.send(1, msg.clone()).await.is_ok() {}
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut rtts = Vec::new();
    for _ in 0..100 {
        let t = Instant::now();
        dg.send(2, Bytes::from_static(b"xxxxxxxx")).await.unwrap();
        if tokio::time::timeout(Duration::from_millis(500), dg.receive()).await.is_ok() {
            rtts.push(t.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    sender.abort();
    assert!(rtts.len() > 50, "{} of 100 came back", rtts.len());
    rtts.sort();
    eprintln!("datagram round trip beside bulk: p50 {:?}, p99 {:?}, {} of 100", rtts[rtts.len() / 2], rtts[rtts.len() * 99 / 100], rtts.len());
}
