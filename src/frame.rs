//! Frames: core §2. Layer 2 of the xumux stack.
use bytes::{BufMut, Bytes};

pub const MAGIC: [u8; 4] = *b"XMUX";
pub const HEADER_LEN: usize = 8;
pub const CONTROL_MAX: u32 = 65536;
pub const RESERVED_CHANNEL: u16 = 0xFFFF;

pub const MORE: u8 = 0x01;
pub const PROBE: u8 = 0x02;

pub const PING: u8 = 0x10;
pub const PONG: u8 = 0x11;

/// Control message types (channel 0, PROBE clear).
pub mod ctl {
    pub const HELLO: u8 = 0x01;
    pub const WELCOME: u8 = 0x02;
    pub const OPEN_CHANNEL: u8 = 0x03;
    pub const CHANNEL_ACK: u8 = 0x04;
    pub const CLOSE_CHANNEL: u8 = 0x05;
    pub const CHANNEL_REJECT: u8 = 0x06;
    pub const WINDOW_UPDATE: u8 = 0x07;
    pub const CLOSE: u8 = 0x20;
    pub const ERROR: u8 = 0xF0;
}

/// Codes: core §10.
pub mod code {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const UNSUPPORTED: u16 = 1003;
    pub const AUTH_FAILED: u16 = 4000;
    pub const INVALID_MESSAGE: u16 = 4001;
    pub const CHANNEL_LIMIT: u16 = 4002;
    pub const CHANNEL_NOT_FOUND: u16 = 4003;
    pub const RATE_LIMITED: u16 = 4004;
    pub const MESSAGE_TOO_LARGE: u16 = 4005;
    pub const VERSION_MISMATCH: u16 = 4006;
    pub const HELLO_TIMEOUT: u16 = 4007;
    pub const KEEPALIVE_TIMEOUT: u16 = 4008;
    pub const FLOW_CONTROL_ERROR: u16 = 4009;
    pub const CHANNEL_REFUSED: u16 = 4010;
    pub const BUSY: u16 = 4011;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel: u16,
    pub ty: u8,
    pub flags: u8,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(channel: u16, ty: u8, flags: u8, payload: impl Into<Bytes>) -> Self {
        Frame { channel, ty, flags, payload: payload.into() }
    }

    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    pub fn encode_into(&self, out: &mut impl BufMut) {
        out.put_u16(self.channel);
        out.put_u8(self.ty);
        out.put_u8(self.flags);
        out.put_u32(self.payload.len() as u32);
        out.put_slice(&self.payload);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub channel: u16,
    pub ty: u8,
    pub flags: u8,
    pub len: u32,
}

pub fn parse_header(b: &[u8; HEADER_LEN]) -> Header {
    Header {
        channel: u16::from_be_bytes([b[0], b[1]]),
        ty: b[2],
        flags: b[3],
        len: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
    }
}
