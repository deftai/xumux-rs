//! The spec's conformance vectors, fed straight to the state machine with no transport.
use std::time::Instant;

use serde_json::Value;
use xumux::core::{Core, Options, Role};
use xumux::frame::{ctl, parse_header, Frame, HEADER_LEN, MAGIC, MORE};

fn vectors() -> Value {
    serde_json::from_str(include_str!("data/vectors.json")).unwrap()
}

fn bytes_of(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.replace(' ', "")).unwrap()
}

fn frame(b: &[u8]) -> Frame {
    let h: [u8; HEADER_LEN] = b[..HEADER_LEN].try_into().unwrap();
    let h = parse_header(&h);
    Frame { channel: h.channel, ty: h.ty, flags: h.flags, payload: bytes::Bytes::copy_from_slice(&b[HEADER_LEN..]) }
}

fn server() -> Core {
    let policy: xumux::core::Policy = std::sync::Arc::new(|_| Ok(()));
    Core::new(Role::Server, Options::default(), Some(policy), None, Instant::now()).unwrap()
}

fn connected() -> Core {
    let mut c = server();
    c.on_frame(Frame::new(0, ctl::HELLO, 0, br#"{"version":[0,3,0]}"#.to_vec()), Instant::now());
    assert!(c.is_open());
    drain(&mut c);
    c
}

fn drain(c: &mut Core) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut done = Vec::new();
    while let Some(f) = c.next_frame(&mut done) {
        out.push(f);
    }
    out
}

fn close_code(frames: &[Frame]) -> Option<u64> {
    frames.iter().find(|f| f.channel == 0 && f.ty == ctl::CLOSE).map(|f| {
        let v: Value = serde_json::from_slice(&f.payload).unwrap();
        v["code"].as_u64().unwrap()
    })
}

fn client_connected() -> Core {
    let mut c = Core::new(Role::Client, Options::default(), None, None, Instant::now()).unwrap();
    drain(&mut c);
    c.on_frame(Frame::new(0, ctl::WELCOME, 0, br#"{"version":[0,3,0]}"#.to_vec()), Instant::now());
    assert!(c.is_open());
    drain(&mut c);
    c
}

/// Splits wire bytes into frames, re-encoding each to check both directions.
fn frames_of(wire: &[u8], name: &str) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        let h: [u8; HEADER_LEN] = rest[..HEADER_LEN].try_into().unwrap();
        let end = HEADER_LEN + parse_header(&h).len as usize;
        let f = frame(&rest[..end]);
        let mut again = Vec::new();
        f.encode_into(&mut again);
        assert_eq!(again, &rest[..end], "{name}");
        out.push(f);
        rest = &rest[end..];
    }
    out
}

#[test]
fn valid_vectors_round_trip() {
    let v = vectors();
    let mut checked = 0;
    for e in v["valid"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let wire = bytes_of(e["hex"].as_str().unwrap());
        let d = &e["decoded"];
        if d.get("magic").is_some() {
            assert_eq!(wire, MAGIC);
            continue;
        }
        let frames = frames_of(&wire, name);
        if let Some(want) = d.get("reassembledHex") {
            let got: Vec<u8> = frames.iter().flat_map(|f| f.payload.to_vec()).collect();
            assert_eq!(got, bytes_of(want.as_str().unwrap()), "{name}");
            let last = frames.last().unwrap();
            assert_eq!(last.flags & MORE, 0, "{name}");
            assert!(frames[..frames.len() - 1].iter().all(|f| f.flags & MORE != 0), "{name}");
            checked += 1;
            continue;
        }
        assert_eq!(frames.len(), 1, "{name}");
        let f = &frames[0];
        assert_eq!(u64::from(f.channel), d["channel"].as_u64().unwrap(), "{name}");
        assert_eq!(u64::from(f.ty), d["type"].as_u64().unwrap(), "{name}");
        assert_eq!(u64::from(f.flags), d["flags"].as_u64().unwrap_or(0), "{name}");
        if let Some(want) = d.get("payloadJson") {
            let got: Value = serde_json::from_slice(&f.payload).unwrap();
            assert_eq!(&got, want, "{name}");
        }
        if let Some(want) = d.get("payloadHex") {
            assert_eq!(f.payload.to_vec(), bytes_of(want.as_str().unwrap()), "{name}");
        }
        checked += 1;
    }
    assert!(checked >= 15, "only {checked} vectors checked");
}

#[test]
fn invalid_vectors_get_the_required_action() {
    let v = vectors();
    let mut checked = 0;
    for e in v["invalid"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let state = e["state"].as_str().unwrap();
        let wire = bytes_of(e["hex"].as_str().unwrap());
        let expect = &e["expect"];
        if state == "start" {
            // The driver checks magic before any frame exists: see tests/session.rs.
            assert_ne!(&wire[..4], &MAGIC, "{name}");
            continue;
        }
        if expect.get("bindings").is_some() {
            continue; // Message-pipe framing: no such binding here yet.
        }
        let mut c = match (state, expect.get("receiver").and_then(Value::as_str)) {
            ("awaiting-hello", _) => server(),
            (_, Some("client")) => client_connected(),
            _ => connected(),
        };
        let channel = u16::from_be_bytes([wire[0], wire[1]]);
        let declared = u32::from_be_bytes(wire[4..8].try_into().unwrap());
        if declared > c.frame_limit(channel) {
            // Framing refuses these before reading the payload: see the driver's read loop.
            assert_eq!(expect["code"].as_u64(), Some(4005), "{name}");
            checked += 1;
            continue;
        }
        c.on_frame(frame(&wire), Instant::now());
        let out = drain(&mut c);
        assert_eq!(close_code(&out), expect["code"].as_u64(), "{name}: {out:?}");
        checked += 1;
    }
    assert_eq!(checked, 14, "vectors checked");
}
