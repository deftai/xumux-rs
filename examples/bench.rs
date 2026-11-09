//! Throughput, and input latency during a bulk transfer, over TCP loopback.
//!
//!     cargo run --release --example bench
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use xumux::{Acceptor, ChannelSpec, Limits, Options, Session};

async fn pair(tuned: bool) -> (Session, Session) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits { max_frame_payload: 65536, max_message_size: 8 << 20, initial_window: 8 << 20 };
    let opts = Options { limits, ping_interval: 0, ..Options::default() };
    let server_opts = opts.clone();
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        if tuned {
            xumux::transport::tune_tcp(&sock).unwrap();
        } else {
            sock.set_nodelay(true).unwrap();
        }
        let (r, w) = sock.into_split();
        Session::accept(r, w, server_opts, Acceptor::default().policy(|_| Ok(()))).await.unwrap()
    });
    let sock = TcpStream::connect(addr).await.unwrap();
    if tuned {
        xumux::transport::tune_tcp(&sock).unwrap();
    } else {
        sock.set_nodelay(true).unwrap();
    }
    let (r, w) = sock.into_split();
    let (client, _) = Session::connect(r, w, opts, Acceptor::default(), vec![]).await.unwrap();
    (server.await.unwrap(), client)
}

fn pct(v: &mut [Duration], p: f64) -> f64 {
    v.sort();
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)].as_secs_f64() * 1e6
}

async fn throughput(tuned: bool) {
    let (s, c) = pair(tuned).await;
    let tx = c.open_channel(ChannelSpec::reliable("bulk")).await.unwrap();
    let rx = s.accept_channel().await.unwrap();
    let msg = Bytes::from(vec![0u8; 1 << 20]);
    let n = 2000u64;
    let start = Instant::now();
    let sender = tokio::spawn(async move {
        for _ in 0..n {
            tx.send(1, msg.clone()).await.unwrap();
        }
    });
    for _ in 0..n {
        rx.receive().await.unwrap().unwrap();
    }
    sender.await.unwrap();
    let t = start.elapsed().as_secs_f64();
    print!("tuned={tuned} ");
    println!("throughput: {:.0} MB/s, {:.2} Gbit/s", n as f64 / t, n as f64 * 8.0 / 1024.0 / t);
}

/// `input` echoes small messages while `video` sends flat out on the same connection.
async fn input_latency(input_priority: u8, video_priority: u8, tuned: bool) -> (f64, f64, f64) {
    let (s, c) = pair(tuned).await;
    let video = c.open_channel(ChannelSpec::reliable("video")).await.unwrap();
    let video_rx = s.accept_channel().await.unwrap();
    let input = c.open_channel(ChannelSpec::reliable("input")).await.unwrap();
    let input_srv = s.accept_channel().await.unwrap();
    video.set_priority(video_priority);
    input.set_priority(input_priority);
    input_srv.set_priority(input_priority);
    tokio::spawn(async move { while let Ok(Some(_)) = video_rx.receive().await {} });
    tokio::spawn(async move {
        while let Ok(Some(m)) = input_srv.receive().await {
            if input_srv.send(m.ty, m.payload).await.is_err() {
                break;
            }
        }
    });
    let msg = Bytes::from(vec![0u8; 256 * 1024]);
    let bulk = tokio::spawn({
        let video = video.clone();
        async move { while video.send(1, msg.clone()).await.is_ok() {} }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut samples = Vec::new();
    for _ in 0..2000 {
        let t = Instant::now();
        input.send(2, Bytes::from_static(b"12345678")).await.unwrap();
        input.receive().await.unwrap().unwrap();
        samples.push(t.elapsed());
        tokio::time::sleep(Duration::from_micros(500)).await;
    }
    bulk.abort();
    (pct(&mut samples, 0.5), pct(&mut samples, 0.99), pct(&mut samples, 0.999))
}

#[tokio::main]
async fn main() {
    for tuned in [false, true] {
        throughput(tuned).await;
        for (name, ip, vp) in [("same priority", 128, 128), ("input first  ", 0, 200)] {
            let (a, b, c) = input_latency(ip, vp, tuned).await;
            println!("  tuned={tuned} input round trip, {name}: p50 {a:.0} us  p99 {b:.0} us  p99.9 {c:.0} us");
        }
    }
}
