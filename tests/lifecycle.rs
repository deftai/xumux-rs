//! What dropping handles does, cancelled opens, and callbacks that are slow or panic.
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{duplex, split};
use xumux::frame::code;
use xumux::pipe::{self, Pipe};
use xumux::{Acceptor, ChannelSpec, Error, Options, Refusal, Session};

const SHORT: Duration = Duration::from_secs(2);

fn opts() -> Options {
    Options { close_timeout: Duration::from_millis(200), ping_interval: 0, ..Options::default() }
}

async fn pair_with(acceptor: Acceptor) -> (Session, Session) {
    let (a, b) = duplex(1 << 20);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let server = tokio::spawn(Session::accept(ar, aw, opts(), acceptor));
    let (client, _) = Session::connect(br, bw, opts(), Acceptor::default(), vec![]).await.unwrap();
    (server.await.unwrap().unwrap(), client)
}

async fn pair() -> (Session, Session) {
    pair_with(Acceptor::default().policy(|_| Ok(()))).await
}

/// The accepting side drops its only handle, so the opener must learn the channel is gone.
#[tokio::test]
async fn a_dropped_channel_closes_and_the_opener_sees_it() {
    let (s, c) = pair().await;
    let ch = c.open_channel(ChannelSpec::reliable("x")).await.unwrap();
    drop(s.accept_channel().await.unwrap());
    tokio::time::timeout(SHORT, ch.closed()).await.expect("the channel closes once the peer drops it");
    assert!(ch.send(1, Bytes::from(vec![0u8; 1000])).await.is_err());
    // A normal close: the opener's reads end cleanly.
    assert!(ch.receive().await.unwrap().is_none());
}

#[tokio::test]
async fn a_channel_closes_only_when_its_last_handle_goes() {
    let (s, c) = pair().await;
    let a = Pipe::new(c.open_channel(pipe::spec("p", None)).await.unwrap()).unwrap();
    let rx = s.accept_channel().await.unwrap();
    let clone = a.channel().clone();
    drop(a);
    clone.send(pipe::DATA, Bytes::from_static(b"still open")).await.unwrap();
    assert_eq!(&rx.receive().await.unwrap().unwrap().payload[..], b"still open");
    drop(clone);
    tokio::time::timeout(SHORT, rx.closed()).await.expect("the last handle closes it");
    assert!(rx.receive().await.unwrap().is_none());
}

#[tokio::test]
async fn dropping_the_last_session_handle_closes_the_connection_with_1001() {
    let (s, c) = pair().await;
    let extra = c.clone();
    drop(c);
    extra.ping().await.unwrap();
    drop(extra);
    let info = tokio::time::timeout(SHORT, s.closed()).await.expect("the peer sees CLOSE");
    assert_eq!(info.code, code::GOING_AWAY);
}

#[tokio::test]
async fn a_live_channel_keeps_its_session_open() {
    let (s, c) = pair().await;
    let ch = c.open_channel(ChannelSpec::reliable("x")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    drop(c);
    ch.send(1, Bytes::from_static(b"after the session handle")).await.unwrap();
    assert_eq!(rx.receive().await.unwrap().unwrap().ty, 1);
    assert!(s.close_info().is_none());
    drop(ch);
    let info = tokio::time::timeout(SHORT, s.closed()).await.expect("the last handle closes the connection");
    assert_eq!(info.code, code::GOING_AWAY);
}

/// The open is abandoned before the answer arrives. The opener may not send CLOSE_CHANNEL for a
/// channel that is opening (core §5.2), so it must close it once the ACK lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_open_channel_future_closes_the_channel_once_it_opens() {
    let (s, c) = pair_with(Acceptor::default().policy(|_| {
        std::thread::sleep(Duration::from_millis(200));
        Ok(())
    }))
    .await;
    let abandoned = tokio::time::timeout(Duration::from_millis(20), c.open_channel(ChannelSpec::reliable("x"))).await;
    assert!(abandoned.is_err(), "the open should still be waiting for the policy");
    let rx = tokio::time::timeout(SHORT, s.accept_channel()).await.unwrap().unwrap();
    tokio::time::timeout(SHORT, rx.closed()).await.expect("the opener closes the channel it no longer wants");
    // The ID was freed by the close exchange, not leaked. The PONG comes after the server's reply
    // CLOSE_CHANNEL, so the client has seen the exchange finish by then.
    c.ping().await.unwrap();
    let again = tokio::time::timeout(SHORT, c.open_channel(ChannelSpec::reliable("y"))).await.unwrap().unwrap();
    assert_eq!(again.id(), 1);
}

/// While a policy runs for one channel, the session keeps sending on the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_policy_does_not_block_other_channels() {
    let (s, c) = pair_with(Acceptor::default().policy(|spec| {
        if spec.name == "slow" {
            std::thread::sleep(Duration::from_millis(800));
        }
        Ok(())
    }))
    .await;
    let ch = c.open_channel(ChannelSpec::reliable("fast")).await.unwrap();
    let srv_ch = s.accept_channel().await.unwrap();
    let slow = tokio::spawn({
        let c = c.clone();
        async move { c.open_channel(ChannelSpec::reliable("slow")).await.map(|ch| ch.id()) }
    });
    // Let the OPEN_CHANNEL reach the policy.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let start = Instant::now();
    // Timed rather than raced with a timeout: a send stuck on the core lock blocks its thread, and
    // the timeout with it.
    srv_ch.send(1, Bytes::from_static(b"not stuck")).await.unwrap();
    ch.receive().await.unwrap().unwrap();
    assert!(start.elapsed() < Duration::from_millis(400), "traffic waited {:?} for another channel's policy", start.elapsed());
    assert!(tokio::time::timeout(SHORT, slow).await.unwrap().unwrap().is_ok());
}

#[tokio::test]
async fn a_panicking_policy_refuses_the_channel_and_the_session_carries_on() {
    let (s, c) = pair_with(Acceptor::default().policy(|spec| {
        if spec.name == "boom" {
            panic!("policy bug");
        }
        Ok(())
    }))
    .await;
    let e = tokio::time::timeout(SHORT, c.open_channel(ChannelSpec::reliable("boom"))).await.expect("answered").err().unwrap();
    assert!(matches!(e, Error::Refused(ref i) if i.code == code::CHANNEL_REFUSED), "{e}");
    let ch = tokio::time::timeout(SHORT, c.open_channel(ChannelSpec::reliable("fine"))).await.unwrap().unwrap();
    let rx = s.accept_channel().await.unwrap();
    ch.send(1, Bytes::from_static(b"ok")).await.unwrap();
    assert_eq!(&rx.receive().await.unwrap().unwrap().payload[..], b"ok");
    assert!(s.ping().await.is_ok());
}

#[tokio::test]
async fn a_panicking_authorize_refuses_the_hello() {
    let (a, b) = duplex(1 << 16);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let acceptor = Acceptor::default().authorize(|_| panic!("authorize bug"));
    let server = tokio::spawn(Session::accept(ar, aw, opts(), acceptor));
    let e = tokio::time::timeout(SHORT, Session::connect(br, bw, opts(), Acceptor::default(), vec![])).await.expect("answered").err().unwrap();
    assert!(matches!(e, Error::Closed(ref i) if i.code == code::AUTH_FAILED), "{e}");
    assert!(server.await.unwrap().is_err());
}

/// Every HELLO channel is decided before WELCOME, in order, with the slow one in the middle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_channels_are_all_decided_before_welcome() {
    let (a, b) = duplex(1 << 16);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let acceptor = Acceptor::default().policy(|spec| match spec.name.as_str() {
        "slow" => {
            std::thread::sleep(Duration::from_millis(100));
            Ok(())
        }
        "boom" => panic!("policy bug"),
        _ => Err(Refusal::new(4010, "no")),
    });
    let server = tokio::spawn(Session::accept(ar, aw, opts(), acceptor));
    let specs = vec![ChannelSpec::reliable("slow"), ChannelSpec::reliable("boom"), ChannelSpec::reliable("nope")];
    let (_c, chans) = tokio::time::timeout(SHORT, Session::connect(br, bw, opts(), Acceptor::default(), specs)).await.unwrap().unwrap();
    let s = server.await.unwrap().unwrap();
    assert_eq!(chans[0].as_ref().unwrap().id(), 1);
    assert!(matches!(chans[1], Err(Error::Refused(ref i)) if i.code == code::CHANNEL_REFUSED));
    assert!(matches!(chans[2], Err(Error::Refused(ref i)) if i.code == 4010 && i.reason == "no"));
    assert_eq!(s.accept_channel().await.unwrap().name(), "slow");
}

/// The reader stops while a callback runs, so the peer's PONGs wait unread. That time must not
/// count against the peer as silence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_policy_is_not_mistaken_for_a_silent_peer() {
    let (a, b) = duplex(1 << 20);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let keepalive = Options { ping_interval: 1, ping_timeout: 1, ..opts() };
    let acceptor = Acceptor::default().policy(|_| {
        std::thread::sleep(Duration::from_millis(2300));
        Ok(())
    });
    let server = tokio::spawn(Session::accept(ar, aw, keepalive.clone(), acceptor));
    let (c, _) = Session::connect(br, bw, keepalive, Acceptor::default(), vec![]).await.unwrap();
    let s = server.await.unwrap().unwrap();
    let ch = tokio::time::timeout(Duration::from_secs(5), c.open_channel(ChannelSpec::reliable("x"))).await.unwrap();
    assert!(ch.is_ok(), "{:?}", ch.err());
    assert!(s.close_info().is_none(), "closed with {:?}", s.close_info());
    assert!(s.ping().await.is_ok());
}
