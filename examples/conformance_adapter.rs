//! Runs this implementation as the server under test for xumux's behavioural conformance suite.
//!
//!     python3 -I run.py --features core,pipe -- target/debug/examples/conformance_adapter
use std::time::Duration;

use bytes::Bytes;
use serde_json::Value;
use xumux::frame::code;
use xumux::pipe::Pipe;
use xumux::{Acceptor, Channel, Limits, Options, Refusal, Session};

fn options(cfg: &Value) -> Options {
    let d = Limits::default();
    let lim = |k: &str, def: u32| cfg[k].as_u64().map_or(def, |v| v as u32);
    let mut o = Options {
        limits: Limits {
            max_frame_payload: lim("maxFramePayload", d.max_frame_payload),
            max_message_size: lim("maxMessageSize", d.max_message_size),
            initial_window: lim("initialWindow", d.initial_window),
        },
        ping_interval: 0,
        ..Options::default()
    };
    if let Some(n) = cfg["maxChannels"].as_u64() {
        o.max_channels = n as usize;
    }
    if let Some(n) = cfg["handshakeTimeoutMs"].as_u64() {
        o.handshake_timeout = Duration::from_millis(n);
    }
    o
}

async fn serve(ch: Channel) {
    match ch.name() {
        "echo" => {
            while let Ok(Some(m)) = ch.receive().await {
                if ch.send(m.ty, m.payload).await.is_err() {
                    return;
                }
            }
        }
        "sink" => while let Ok(Some(_)) = ch.receive().await {},
        "hold" => ch.closed().await,
        "pipe-echo" => {
            let Ok(p) = Pipe::new(ch) else { return };
            loop {
                match p.read().await {
                    Ok(Some(data)) => {
                        let n = data.len();
                        if p.write(Bytes::clone(&data)).await.is_err() {
                            return;
                        }
                        p.consumed(n);
                    }
                    Ok(None) => {
                        let _ = p.write_eof().await;
                        p.channel().closed().await;
                        return;
                    }
                    Err(_) => return,
                }
            }
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() {
    let cfg: Value = std::env::args().nth(1).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
    let acceptor = Acceptor::default().policy(|spec| match spec.name.as_str() {
        "echo" | "sink" | "hold" => Ok(()),
        "pipe-echo" if spec.metadata.as_ref().and_then(|m| m.get("profile")).and_then(Value::as_str) == Some("pipe/1") => Ok(()),
        _ => Err(Refusal::new(code::CHANNEL_REFUSED, "refused")),
    });
    let s = match Session::accept(tokio::io::stdin(), tokio::io::stdout(), options(&cfg), acceptor).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("adapter: handshake: {e}");
            std::process::exit(0);
        }
    };
    let accepting = s.clone();
    tokio::spawn(async move {
        while let Some(ch) = accepting.accept_channel().await {
            tokio::spawn(serve(ch));
        }
    });
    s.closed().await;
    // stdin's blocking read can't be cancelled.
    std::process::exit(0);
}
