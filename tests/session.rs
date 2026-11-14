//! End-to-end behaviour over an in-process byte stream.
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{duplex, split};
use xumux::frame::code;
use xumux::pipe::{self, Pipe};
use xumux::{Acceptor, ChannelSpec, Error, Limits, Options, Refusal, Session};

async fn pair_with(server_opts: Options, client_opts: Options, buffer: usize) -> (Session, Session) {
    let (a, b) = duplex(buffer);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let acceptor = Acceptor::default().policy(|s| {
        if s.name == "nope" {
            Err(Refusal::new(code::CHANNEL_REFUSED, "no"))
        } else {
            Ok(())
        }
    });
    let server = tokio::spawn(Session::accept(ar, aw, server_opts, acceptor.clone()));
    let (client, _) = Session::connect(br, bw, client_opts, acceptor, vec![]).await.unwrap();
    (server.await.unwrap().unwrap(), client)
}

async fn pair() -> (Session, Session) {
    pair_with(Options::default(), Options::default(), 1 << 20).await
}

#[tokio::test]
async fn messages_keep_their_type_and_boundaries() {
    let (s, c) = pair().await;
    let tx = c.open_channel(ChannelSpec::reliable("a")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    assert_eq!(rx.name(), "a");
    assert!(tx.properties().unwrap().reliable);
    tx.send(7, Bytes::from_static(b"hello")).await.unwrap();
    tx.send(8, Bytes::new()).await.unwrap();
    let big = Bytes::from(vec![9u8; 200_000]);
    tx.send(9, big.clone()).await.unwrap();
    let m = rx.receive().await.unwrap().unwrap();
    assert_eq!((m.ty, &m.payload[..]), (7, &b"hello"[..]));
    let m = rx.receive().await.unwrap().unwrap();
    assert_eq!((m.ty, m.payload.len()), (8, 0));
    let m = rx.receive().await.unwrap().unwrap();
    assert_eq!((m.ty, m.payload), (9, big));
}

#[tokio::test]
async fn a_refused_channel_reports_why_and_frees_its_id() {
    let (_s, c) = pair().await;
    let e = c.open_channel(ChannelSpec::reliable("nope")).await.err().unwrap();
    assert!(matches!(e, Error::Refused(ref i) if i.code == code::CHANNEL_REFUSED), "{e}");
    assert_eq!(c.open_channel(ChannelSpec::reliable("yes")).await.unwrap().id(), 1);
}

#[tokio::test]
async fn too_large_is_refused_locally() {
    let (_s, c) = pair().await;
    let ch = c.open_channel(ChannelSpec::reliable("a")).await.unwrap();
    let e = ch.send(1, Bytes::from(vec![0u8; 300_000])).await.unwrap_err();
    assert!(matches!(e, Error::TooLarge { .. }));
}

#[tokio::test]
async fn a_reader_that_stops_pauses_only_its_own_channel() {
    let limits = Limits { max_frame_payload: 16384, max_message_size: 65536, initial_window: 65536 };
    let opts = Options { limits, max_channel_window: 0, ..Options::default() };
    let (s, c) = pair_with(opts.clone(), opts, 1 << 20).await;
    let stuck = c.open_channel(ChannelSpec::reliable("stuck")).await.unwrap();
    let _stuck_rx = s.accept_channel().await.unwrap();
    let free = c.open_channel(ChannelSpec::reliable("free")).await.unwrap();
    let free_rx = s.accept_channel().await.unwrap();

    stuck.send(1, Bytes::from(vec![0u8; 65536])).await.unwrap();
    assert_eq!(stuck.send_credit().unwrap(), 0);
    let blocked = tokio::spawn({
        let stuck = stuck.clone();
        async move { stuck.send(1, Bytes::from(vec![0u8; 100])).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!blocked.is_finished(), "the send should wait for credit");

    free.send(2, Bytes::from_static(b"still moving")).await.unwrap();
    assert_eq!(free_rx.receive().await.unwrap().unwrap().ty, 2);
    blocked.abort();
}

#[tokio::test]
async fn credit_comes_back_and_a_long_transfer_finishes() {
    let (s, c) = pair().await;
    let tx = c.open_channel(ChannelSpec::reliable("a")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    let total = 50usize;
    let sender = tokio::spawn(async move {
        for _ in 0..total {
            tx.send(1, Bytes::from(vec![1u8; 200_000])).await.unwrap();
        }
    });
    for _ in 0..total {
        assert_eq!(rx.receive().await.unwrap().unwrap().payload.len(), 200_000);
    }
    sender.await.unwrap();
}

/// Input must overtake video on a shared path: that's the point of priority.
#[tokio::test]
async fn a_lower_priority_number_goes_first_even_behind_a_bulk_sender() {
    let limits = Limits { max_frame_payload: 16384, max_message_size: 8 << 20, initial_window: 8 << 20 };
    let opts = Options { limits, ..Options::default() };
    // A tiny transport buffer, so the bulk sender really is queued when input arrives.
    let (s, c) = pair_with(opts.clone(), opts, 4096).await;
    let video = c.open_channel(ChannelSpec::reliable("video")).await.unwrap();
    let video_rx = s.accept_channel().await.unwrap();
    let input = c.open_channel(ChannelSpec::reliable("input")).await.unwrap();
    let input_rx = s.accept_channel().await.unwrap();
    video.set_priority(200);
    input.set_priority(0);

    let sending = tokio::spawn({
        let video = video.clone();
        async move { video.send(1, Bytes::from(vec![0u8; 4 << 20])).await.unwrap() }
    });
    let reading = tokio::spawn(async move { video_rx.receive().await.unwrap().unwrap().payload.len() });
    tokio::time::sleep(Duration::from_millis(1)).await;

    input.send(2, Bytes::from_static(b"key")).await.unwrap();
    let m = tokio::time::timeout(Duration::from_secs(5), input_rx.receive()).await.unwrap().unwrap().unwrap();
    assert_eq!(m.ty, 2);
    assert!(!reading.is_finished(), "input should arrive before the bulk message completes");
    assert_eq!(reading.await.unwrap(), 4 << 20);
    sending.await.unwrap();
}

#[tokio::test]
async fn ping_measures_each_channel() {
    let (s, c) = pair().await;
    let ch = c.open_channel(ChannelSpec::reliable("a")).await.unwrap();
    let _rx = s.accept_channel().await.unwrap();
    assert!(ch.ping().await.unwrap() < Duration::from_secs(1));
    assert!(c.ping().await.unwrap() < Duration::from_secs(1));
    assert_eq!(ch.stats().probes_sent, 1);
    assert!(ch.stats().srtt.is_some());
    assert!(c.stats().srtt.is_some());
}

#[tokio::test]
async fn close_exchanges_and_reports_the_code_on_both_sides() {
    let (s, c) = pair().await;
    let ch = c.open_channel(ChannelSpec::reliable("a")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    ch.send(1, Bytes::from_static(b"last")).await.unwrap();
    c.close(4600, "bye").await;
    assert_eq!(s.closed().await.code, 4600);
    assert_eq!(c.closed().await.code, 4600);
    // What arrived before the close can still be read.
    assert_eq!(&rx.receive().await.unwrap().unwrap().payload[..], b"last");
    assert!(ch.send(1, Bytes::new()).await.is_err());
    assert!(s.accept_channel().await.is_none());
}

#[tokio::test]
async fn a_dead_transport_ends_everything() {
    let (a, b) = duplex(4096);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let acceptor = Acceptor::default().policy(|_| Ok(()));
    let server = tokio::spawn(Session::accept(ar, aw, Options::default(), acceptor.clone()));
    let (client, _) = Session::connect(br, bw, Options::default(), acceptor, vec![]).await.unwrap();
    let server = server.await.unwrap().unwrap();
    server.close(code::GOING_AWAY, "").await;
    assert_eq!(tokio::time::timeout(Duration::from_secs(2), client.closed()).await.unwrap().code, code::GOING_AWAY);
}

#[tokio::test]
async fn keepalive_notices_a_silent_peer() {
    // A peer that does the handshake and then never answers.
    let (a, b) = duplex(1 << 16);
    let (ar, aw) = split(a);
    let opts = Options { ping_interval: 1, ping_timeout: 1, ..Options::default() };
    let server = tokio::spawn(Session::accept(ar, aw, opts, Acceptor::default()));
    let (mut br, mut bw) = split(b);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    bw.write_all(b"XMUX").await.unwrap();
    let hello = br#"{"version":[0,3,0]}"#;
    bw.write_all(&[0, 0, 1, 0, 0, 0, 0, hello.len() as u8]).await.unwrap();
    bw.write_all(hello).await.unwrap();
    let s = server.await.unwrap().unwrap();
    let drain = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while br.read(&mut buf).await.unwrap_or(0) > 0 {}
    });
    let info = tokio::time::timeout(Duration::from_secs(8), s.closed()).await.unwrap();
    assert_eq!(info.code, code::KEEPALIVE_TIMEOUT);
    drain.abort();
}

#[tokio::test]
async fn pipe_does_not_wrap_a_channel_that_has_already_closed() {
    let (s, c) = pair().await;
    let a = c.open_channel(pipe::spec("closed", None)).await.unwrap();
    let b = s.accept_channel().await.unwrap();
    a.close(code::NORMAL, None).await;
    b.closed().await;
    assert!(a.properties().is_none());
    assert!(Pipe::new(a).is_err());
}

#[tokio::test]
async fn pipe_rejects_invalid_requested_properties_even_on_a_reliable_path() {
    let (s, c) = pair().await;
    for (reliable, ordered) in [(false, true), (true, false), (false, false)] {
        let mut spec = pipe::spec("invalid", None);
        spec.reliable = reliable;
        spec.ordered = ordered;
        let a = c.open_channel(spec).await.unwrap();
        let b = s.accept_channel().await.unwrap();
        assert!(a.properties().unwrap().reliable && a.properties().unwrap().ordered);
        assert!(Pipe::new(a).is_err(), "the request itself must meet pipe/1 requirements");
        assert!(Pipe::new(b).is_err());
    }
}

#[tokio::test]
async fn a_pipe_carries_bytes_with_half_close_and_backpressure() {
    let (s, c) = pair().await;
    let a = Pipe::new(c.open_channel(pipe::spec("p", Some("tcp:localhost:1"))).await.unwrap()).unwrap();
    let b = Pipe::new(s.accept_channel().await.unwrap()).unwrap();
    assert_eq!(b.channel().spec().metadata.as_ref().unwrap()["target"], "tcp:localhost:1");

    let data = Bytes::from(vec![5u8; 1 << 20]);
    let writer = tokio::spawn({
        let data = data.clone();
        async move {
            a.write(data).await.unwrap();
            a.write_eof().await.unwrap();
            a
        }
    });
    let mut got = 0;
    let mut stalled = false;
    while let Some(chunk) = b.read().await.unwrap() {
        assert!(chunk.len() <= 16384, "DATA is never fragmented, and fits one scheduling unit");
        got += chunk.len();
        // Not consuming stalls the writer once the window is full.
        if got > 300_000 && !stalled {
            stalled = true;
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(!writer.is_finished());
        }
        b.consumed(chunk.len());
    }
    assert_eq!(got, data.len());
    let a = writer.await.unwrap();
    // The other direction is still open after a half-close.
    b.write(Bytes::from_static(b"reply")).await.unwrap();
    b.write_eof().await.unwrap();
    assert_eq!(&a.read().await.unwrap().unwrap()[..], b"reply");
    a.consumed(b"reply".len());
    assert!(a.read().await.unwrap().is_none());
}

#[tokio::test]
async fn pipe_write_after_eof_is_refused_without_sending_data() {
    let (s, c) = pair().await;
    let a = Pipe::new(c.open_channel(pipe::spec("p", None)).await.unwrap()).unwrap();
    let b = s.accept_channel().await.unwrap();
    a.write_eof().await.unwrap();
    assert_eq!(b.receive().await.unwrap().unwrap().ty, pipe::EOF);
    assert!(a.write(Bytes::from_static(b"too late")).await.is_err());
    assert!(tokio::time::timeout(Duration::from_millis(30), b.receive()).await.is_err());
}

#[tokio::test]
async fn pipe_eof_waits_until_previous_bytes_are_consumed() {
    let (s, c) = pair().await;
    let a = Pipe::new(c.open_channel(pipe::spec("p", None)).await.unwrap()).unwrap();
    let b = Pipe::new(s.accept_channel().await.unwrap()).unwrap();
    a.write(Bytes::from_static(b"drain me")).await.unwrap();
    a.write_eof().await.unwrap();
    let data = b.read().await.unwrap().unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(30), b.read()).await.is_err(), "EOF must not take effect before the local write");
    b.consumed(data.len());
    assert!(tokio::time::timeout(Duration::from_secs(1), b.read()).await.unwrap().unwrap().is_none());
}

#[tokio::test]
async fn pipe_channel_close_without_eof_is_not_successful_end_of_stream() {
    let (s, c) = pair().await;
    let a = c.open_channel(pipe::spec("p", None)).await.unwrap();
    let b = Pipe::new(s.accept_channel().await.unwrap()).unwrap();
    a.close(code::NORMAL, None).await;
    assert!(b.read().await.is_err(), "a close without EOF does not confirm a complete byte stream");
}

#[tokio::test]
async fn pipe_rejects_nonempty_eof() {
    let (s, c) = pair().await;
    let a = c.open_channel(pipe::spec("p", None)).await.unwrap();
    let b = Pipe::new(s.accept_channel().await.unwrap()).unwrap();
    a.send(pipe::EOF, Bytes::from_static(b"not empty")).await.unwrap();
    assert!(b.read().await.is_err());
}

#[tokio::test]
async fn pipe_read_does_not_close_before_queued_eof_is_sent() {
    for cancel_writer in [true, false] {
        let (s, c) = pair().await;
        let a = Pipe::new(c.open_channel(pipe::spec("p", None)).await.unwrap()).unwrap();
        let b = s.accept_channel().await.unwrap();
        b.send(pipe::EOF, Bytes::new()).await.unwrap();
        assert!(a.read().await.unwrap().is_none());
        let mut eof = Box::pin(a.write_eof());
        // Queue EOF without allowing the transport task to send it yet.
        std::future::poll_fn(|cx| {
            assert!(eof.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        }).await;
        if cancel_writer {
            drop(eof);
            assert!(a.write(Bytes::from_static(b"after EOF")).await.is_err());
            assert!(a.read().await.unwrap().is_none());
        } else {
            let (received, sent) = tokio::join!(biased; a.read(), eof);
            assert!(received.unwrap().is_none());
            sent.unwrap();
        }
        assert_eq!(b.receive().await.unwrap().unwrap().ty, pipe::EOF, "the committed EOF must reach the peer even after caller cancellation");
    }
}

#[tokio::test]
async fn pipe_local_write_queue_survives_the_close_exchange() {
    let (s, c) = pair().await;
    let a = Pipe::new(c.open_channel(pipe::spec("p", None)).await.unwrap()).unwrap();
    let b = Pipe::new(s.accept_channel().await.unwrap()).unwrap();
    a.write(Bytes::from_static(b"still owned")).await.unwrap();
    a.write_eof().await.unwrap();
    let queued = b.read().await.unwrap().unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(30), b.read()).await.is_err());
    let (sent, received) = tokio::join!(b.write_eof(), a.read());
    sent.unwrap();
    assert!(received.unwrap().is_none());
    b.channel().closed().await;
    assert!(tokio::time::timeout(Duration::from_millis(30), b.read()).await.is_err(), "channel close must not discard the pending local write");
    assert_eq!(&queued[..], b"still owned");
    b.consumed(queued.len());
    assert!(b.read().await.unwrap().is_none());
}

#[tokio::test]
async fn a_pipe_reset_code_above_16_bits_is_not_truncated() {
    let (s, c) = pair().await;
    let a = Pipe::new(c.open_channel(pipe::spec("p", None)).await.unwrap()).unwrap();
    let b = Pipe::new(s.accept_channel().await.unwrap()).unwrap();
    // 66536 as u16 is 1000, which would read as a normal close.
    a.channel().send(pipe::RESET, br#"{"code":66536}"#.to_vec()).await.unwrap();
    match b.read().await {
        Err(Error::ChannelClosed(info)) => assert_eq!(info.code, code::INVALID_MESSAGE),
        other => panic!("expected ChannelClosed, got {other:?}"),
    }
}

#[tokio::test]
async fn hello_channels_are_opened_or_refused_in_order() {
    let (a, b) = duplex(1 << 16);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let acceptor = Acceptor::default().policy(|s| if s.name == "nope" { Err(Refusal::new(4010, "no")) } else { Ok(()) });
    let server = tokio::spawn(Session::accept(ar, aw, Options::default(), acceptor));
    let (client, chans) = Session::connect(
        br,
        bw,
        Options::default(),
        Acceptor::default(),
        vec![ChannelSpec::reliable("x"), ChannelSpec::reliable("nope"), ChannelSpec::reliable("y")],
    )
    .await
    .unwrap();
    let s = server.await.unwrap().unwrap();
    assert_eq!(chans[0].as_ref().unwrap().id(), 1);
    assert!(matches!(chans[1], Err(Error::Refused(_))));
    assert_eq!(chans[2].as_ref().unwrap().id(), 5);
    let ch = s.accept_channel().await.unwrap();
    assert_eq!(ch.name(), "x");
    let _ = client;
}

#[tokio::test]
async fn a_refused_hello_is_reported_to_the_client_with_its_code() {
    let (a, b) = duplex(1 << 16);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let acceptor = Acceptor::default().authorize(|_| Err(Refusal::new(code::AUTH_FAILED, "bad token")));
    let server = tokio::spawn(Session::accept(ar, aw, Options::default(), acceptor));
    let e = Session::connect(br, bw, Options::default(), Acceptor::default(), vec![]).await.err().unwrap();
    assert!(matches!(e, Error::Closed(ref i) if i.code == code::AUTH_FAILED), "{e}");
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn wrong_magic_closes_the_transport_without_sending_a_frame() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (a, b) = duplex(1 << 16);
    let (ar, aw) = split(a);
    let (mut br, mut bw) = split(b);
    let server = tokio::spawn(Session::accept(ar, aw, Options::default(), Acceptor::default()));
    bw.write_all(b"OMUX").await.unwrap();
    assert!(server.await.unwrap().is_err());
    let mut got = Vec::new();
    br.read_to_end(&mut got).await.unwrap();
    // Our own magic may already be out, since both sides send it first. No frame may follow.
    assert!(got == b"XMUX" || got.is_empty(), "{got:?}");
}
