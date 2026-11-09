# xumux-rs

A Rust implementation of the [xumux](https://github.com/deftai/xumux) 0.3 core protocol: many channels, each with its own flow control, over one connection.

## Status

| | |
|---|---|
| Core 0.3 | Implemented |
| Stream bindings (TCP, Unix sockets, stdio) | Implemented: any `AsyncRead` and `AsyncWrite` pair |
| `pipe/1` | Implemented, as a read and write API. Not yet `AsyncRead` and `AsyncWrite` |
| Local strict-priority scheduling | Implemented |
| WebSocket binding | Implemented |
| QUIC binding (session stream) | Implemented, over native QUIC with quinn. Not yet WebTransport |
| `quic-multistream/1` | Datagram channels implemented. Requests for dedicated streams are placed on the session stream, which the draft allows |
| WebRTC binding, `session-resume/1`, `webrtc-multichannel/1` | Not yet |

`quic-multistream/1` is a design draft in the spec, so this implements a proposal that may change. Checked against the spec's conformance vectors, all 57 behavioural scenarios, and [libxumux-go](https://github.com/deftai/libxumux-go) v0.4.0 in both directions.

## Design

`core` is the whole protocol as a state machine with no I/O and no clock of its own: frames go in, frames come out. `Session` runs it on tokio. New paths such as QUIC streams can be added without changing how the session behaves, and tests can feed it bytes directly.

## Use

```rust
use bytes::Bytes;
use xumux::{Acceptor, ChannelSpec, Options, Session};

let (r, w) = socket.into_split();
let (session, _) = Session::connect(r, w, Options::default(), Acceptor::default(), vec![]).await?;
let channel = session.open_channel(ChannelSpec::reliable("data")).await?;
channel.send(0x01, Bytes::from_static(b"hello")).await?;
let reply = channel.receive().await?;
```

A server passes `Acceptor::default().policy(|spec| ...)` to `Session::accept`, then takes channels from `session.accept_channel()`.

For latency-sensitive traffic, call `Channel::set_priority` (lower goes first) and `transport::tune_tcp` on TCP sockets. Video senders can use `send_credit`, `queued` and `queue` to decide what to drop before it is encoded.

## Testing

```sh
cargo test                                  # unit, session and vector tests
cargo build --examples
python3 -I $XUMUX_DIR/conformance/behaviour/run.py --features core,pipe -- target/debug/examples/conformance_adapter

(cd interop/go && go build -o /tmp/interop-peer .)
XUMUX_GO_PEER=/tmp/interop-peer cargo test --test interop
```

## Latency

`cargo run --release --example bench` reports about 20-35 Gbit/s over TCP loopback on an Apple M4. It runs flat out, so its latency numbers mostly reflect CPU contention, and they are too noisy to compare settings.

`cargo run --release --example bench_shaped` is the useful one: small input messages on a 50 Mbit/s link shared with a bulk or video channel. Input round trip in ms, three runs each:

| Other traffic | Settings | p50 | p99 |
|---|---|---|---|
| Flat out | Any combination of priority and low-water mark | 80-340 | 124-365 |
| 40 Mbit/s, 60 fps | Default | 10 | 13 |
| 40 Mbit/s, 60 fps | Priority and low-water mark | 10 | 12-13 |
| 20 Mbit/s, 60 fps | Default | 0.4 | 6 |
| 20 Mbit/s, 60 fps | Priority and low-water mark | 0.3 | 5-6 |

The lesson is that a sender must stay well under the link's capacity. Priority can't overtake bytes already in flight, which queue at the bottleneck. The link here is a local proxy with no propagation delay, loss or competing traffic, and its fixed-size frames have no keyframe bursts, so real links will be worse.

## License

MIT
