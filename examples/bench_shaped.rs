//! Input latency during a bulk transfer on a link slower than the sender, which is where queues form.
//! A local proxy limits the client-to-server direction to 50 Mbit/s.
//!
//!     cargo run --release --example bench_shaped
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use xumux::{Acceptor, ChannelSpec, Limits, Options, Session};

const LINK_BYTES_PER_SEC: u64 = 50_000_000 / 8;

async fn proxy(listener: TcpListener, target: std::net::SocketAddr) {
    let (client, _) = listener.accept().await.unwrap();
    let server = TcpStream::connect(target).await.unwrap();
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4 * 1024];
        // Each chunk takes real time on the link.
        let mut free_at = Instant::now();
        loop {
            let Ok(n) = cr.read(&mut buf).await else { return };
            if n == 0 {
                return;
            }
            // Timers overshoot by about a millisecond, so keep up to 2 ms of credit to make up for it.
            // Any more would let an idle link deliver a whole frame instantly.
            let now = Instant::now();
            free_at = free_at.max(now - Duration::from_millis(2)) + Duration::from_secs_f64(n as f64 / LINK_BYTES_PER_SEC as f64);
            if free_at > now {
                tokio::time::sleep_until(free_at.into()).await;
            }
            if sw.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let Ok(n) = sr.read(&mut buf).await else { return };
            if n == 0 || cw.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
    });
}

async fn run(priority: bool, tuned: bool, window: u32, pace_mbps: Option<u64>) -> (f64, f64, f64, f64) {
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = server_listener.local_addr().unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(proxy(proxy_listener, target));
    let limits = Limits { max_frame_payload: 65536, max_message_size: window, initial_window: window };
    let opts = Options { limits, ping_interval: 0, write_batch: if tuned { 16 * 1024 } else { 64 * 1024 }, ..Options::default() };
    let server_opts = opts.clone();
    let server = tokio::spawn(async move {
        let (sock, _) = server_listener.accept().await.unwrap();
        sock.set_nodelay(true).unwrap();
        let (r, w) = sock.into_split();
        Session::accept(r, w, server_opts, Acceptor::default().policy(|_| Ok(()))).await.unwrap()
    });
    let sock = TcpStream::connect(proxy_addr).await.unwrap();
    if tuned {
        xumux::transport::tune_tcp(&sock).unwrap();
    } else {
        sock.set_nodelay(true).unwrap();
    }
    let (r, w) = sock.into_split();
    let (c, _) = Session::connect(r, w, opts, Acceptor::default(), vec![]).await.unwrap();
    let s = server.await.unwrap();

    let video = c.open_channel(ChannelSpec::reliable("video")).await.unwrap();
    let video_rx = s.accept_channel().await.unwrap();
    let input = c.open_channel(ChannelSpec::reliable("input")).await.unwrap();
    let input_srv = s.accept_channel().await.unwrap();
    if priority {
        video.set_priority(200);
        input.set_priority(0);
    }
    let received = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = received.clone();
    tokio::spawn(async move {
        while let Ok(Some(m)) = video_rx.receive().await {
            counted.fetch_add(m.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
    });
    tokio::spawn(async move {
        while let Ok(Some(m)) = input_srv.receive().await {
            if input_srv.send(m.ty, m.payload).await.is_err() {
                break;
            }
        }
    });
    let bulk = tokio::spawn({
        let video = video.clone();
        async move {
            match pace_mbps {
                // Video-like: 60 frames a second, below the link's capacity.
                Some(mbps) => {
                    let frame = Bytes::from(vec![0u8; (mbps * 1_000_000 / 8 / 60) as usize]);
                    let mut tick = tokio::time::interval(Duration::from_micros(16_667));
                    loop {
                        tick.tick().await;
                        if video.send(1, frame.clone()).await.is_err() {
                            return;
                        }
                    }
                }
                None => {
                    let msg = Bytes::from(vec![0u8; 256 * 1024]);
                    while video.send(1, msg.clone()).await.is_ok() {}
                }
            }
        }
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let start_bytes = received.load(std::sync::atomic::Ordering::Relaxed);
    let started = Instant::now();
    let mut v = Vec::new();
    while started.elapsed() < Duration::from_secs(6) {
        let t = Instant::now();
        input.send(2, Bytes::from_static(b"12345678")).await.unwrap();
        input.receive().await.unwrap().unwrap();
        v.push(t.elapsed());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mbps = (received.load(std::sync::atomic::Ordering::Relaxed) - start_bytes) as f64 * 8.0 / 1e6 / started.elapsed().as_secs_f64();
    bulk.abort();
    v.sort();
    let p = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)].as_secs_f64() * 1e3;
    (p(0.5), p(0.95), p(0.99), mbps)
}

#[tokio::main]
async fn main() {
    let window = 8 << 20;
    println!("50 Mbit/s link, bulk sender flat out. Input round trip in ms.");
    for (name, priority, tuned, pace) in [
        ("flat out: neither", false, false, None),
        ("flat out: priority only", true, false, None),
        ("flat out: low-water mark only", false, true, None),
        ("flat out: priority + low-water mark", true, true, None),
        ("40 Mbit/s video: neither", false, false, Some(40)),
        ("40 Mbit/s video: priority + low-water mark", true, true, Some(40)),
        ("20 Mbit/s video: neither", false, false, Some(20)),
        ("20 Mbit/s video: priority + low-water mark", true, true, Some(20)),
    ] {
        for _ in 0..3 {
            let (a, b, c, m) = run(priority, tuned, window, pace).await;
            println!("{name:44} p50 {a:7.1}  p95 {b:7.1}  p99 {c:7.1}   bulk {m:5.1} Mbit/s");
        }
    }
}
