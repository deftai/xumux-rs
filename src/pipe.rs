//! The pipe/1 profile: one byte stream per channel, with half-close.
use bytes::Bytes;
use serde_json::{json, Value};
use std::sync::Mutex;

use crate::core::ChannelSpec;
use crate::error::{CloseInfo, Error, Result};
use crate::frame::code;
use crate::session::Channel;

pub const PROFILE: &str = "pipe/1";
pub const DATA: u8 = 0x01;
pub const EOF: u8 = 0x02;
pub const RESET: u8 = 0x03;
pub const TARGET_UNREACHABLE: u16 = 4500;

/// A channel request for a pipe.
pub fn spec(name: &str, target: Option<&str>) -> ChannelSpec {
    let s = ChannelSpec::reliable(name).profile(PROFILE);
    match target {
        Some(t) => s.meta("target", json!(t)),
        None => s,
    }
}

/// Bytes read from a pipe. Dropping them doesn't return credit: call [`Pipe::consumed`] once they are
/// written to the local end, because that is what gives a pipe its backpressure.
pub struct Pipe {
    ch: Channel,
    state: Mutex<PipeState>,
}

#[derive(Default)]
struct PipeState {
    sent_eof: bool,
    recv_eof: bool,
}

impl Pipe {
    pub fn new(ch: Channel) -> Result<Pipe> {
        if ch.profile() != Some(PROFILE) {
            return Err(Error::Invalid("not a pipe/1 channel"));
        }
        ch.set_manual_credit(true);
        Ok(Pipe { ch, state: Mutex::new(PipeState::default()) })
    }

    pub fn channel(&self) -> &Channel {
        &self.ch
    }

    /// The next bytes, or `None` after the peer's EOF. Call [`Pipe::consumed`] after writing them out.
    pub async fn read(&self) -> Result<Option<Bytes>> {
        let Some(m) = self.ch.receive().await? else {
            return Ok(None);
        };
        match m.ty {
            DATA => Ok(Some(m.payload)),
            EOF => {
                let both = {
                    let mut s = self.state.lock().unwrap();
                    s.recv_eof = true;
                    s.sent_eof
                };
                if both {
                    self.ch.close(code::NORMAL, None).await;
                }
                Ok(None)
            }
            RESET => {
                let v: Value = serde_json::from_slice(&m.payload).unwrap_or(Value::Null);
                let reason = v["reason"].as_str().unwrap_or("").to_owned();
                // Still a RESET, so the channel closes with 1001 as pipe/1 says, but a code wider
                // than 16 bits is reported as invalid rather than cast down (66536 would read as 1000).
                let info = match u16::try_from(v["code"].as_u64().unwrap_or(u64::from(code::GOING_AWAY))) {
                    Ok(c) => CloseInfo { code: c, reason },
                    Err(_) => CloseInfo { code: code::INVALID_MESSAGE, reason: "RESET code out of range".into() },
                };
                self.ch.close(code::GOING_AWAY, None).await;
                Err(Error::ChannelClosed(info))
            }
            _ => {
                self.ch.close(code::PROTOCOL_ERROR, Some("unknown pipe message")).await;
                Err(Error::Invalid("unknown pipe message"))
            }
        }
    }

    /// Returns credit for bytes written to the local end.
    pub fn consumed(&self, n: usize) {
        self.ch.return_credit(n);
    }

    /// Writes all the bytes. DATA is never fragmented: each message is sized to the free credit and
    /// the peer's frame limit (pipe/1, implementation notes).
    pub async fn write(&self, mut data: Bytes) -> Result<()> {
        let frame_limit = self.ch.max_unfragmented() as u64;
        while !data.is_empty() {
            let credit = self.ch.wait_credit().await?;
            let n = credit.min(frame_limit).min(data.len() as u64) as usize;
            self.ch.send(DATA, data.split_to(n)).await?;
        }
        Ok(())
    }

    /// Half-close: no more data from this side, like TCP FIN.
    pub async fn write_eof(&self) -> Result<()> {
        self.ch.send(EOF, Bytes::new()).await?;
        let both = {
            let mut s = self.state.lock().unwrap();
            s.sent_eof = true;
            s.recv_eof
        };
        if both {
            self.ch.close(code::NORMAL, None).await;
        }
        Ok(())
    }

    pub async fn reset(&self, c: u16, reason: &str) -> Result<()> {
        self.ch.send(RESET, serde_json::to_vec(&json!({ "code": c, "reason": reason })).expect("JSON encodes")).await?;
        self.ch.close(code::GOING_AWAY, None).await;
        Ok(())
    }
}
