//! The pipe/1 profile: one byte stream per channel, with half-close.
use bytes::Bytes;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::{future::Future, pin::Pin};
use tokio::sync::{Mutex as AsyncMutex, Notify};

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
    reader: AsyncMutex<()>,
    writer: AsyncMutex<()>,
    eof_send: AsyncMutex<EofSend>,
    drained: Notify,
}

enum EofSend {
    New,
    Pending(Pin<Box<dyn Future<Output = Result<()>> + Send>>),
    Done(Result<()>),
}

#[derive(Default)]
struct PipeState {
    sent_eof: bool,
    recv_eof: bool,
    pending: usize,
}

impl Pipe {
    pub fn new(ch: Channel) -> Result<Pipe> {
        if ch.profile() != Some(PROFILE) {
            return Err(Error::Invalid("not a pipe/1 channel"));
        }
        ch.set_manual_credit(true);
        Ok(Pipe {
            ch,
            state: Mutex::new(PipeState::default()),
            reader: AsyncMutex::new(()),
            writer: AsyncMutex::new(()),
            eof_send: AsyncMutex::new(EofSend::New),
            drained: Notify::new(),
        })
    }

    pub fn channel(&self) -> &Channel {
        &self.ch
    }

    /// The next bytes, or `None` after the peer's EOF and all earlier bytes have been consumed.
    /// Call [`Pipe::consumed`] after writing them out. Reads and writes are independently serialized.
    pub async fn read(&self) -> Result<Option<Bytes>> {
        let _reader = self.reader.lock().await;
        if self.state.lock().unwrap().recv_eof {
            return self.finish_read().await;
        }
        let Some(m) = self.ch.receive().await? else {
            return Err(Error::Invalid("pipe closed without EOF"));
        };
        match m.ty {
            DATA => {
                self.state.lock().unwrap().pending += m.payload.len();
                Ok(Some(m.payload))
            }
            EOF => {
                if !m.payload.is_empty() {
                    self.ch.close(code::PROTOCOL_ERROR, Some("nonempty pipe EOF")).await;
                    return Err(Error::Invalid("nonempty pipe EOF"));
                }
                self.state.lock().unwrap().recv_eof = true;
                self.finish_read().await
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

    // Remember EOF before waiting: cancellation of read must not lose it. Bytes already handed to
    // the caller remain owned by its local write queue even if the channel closes in the meantime.
    async fn finish_read(&self) -> Result<Option<Bytes>> {
        loop {
            let drained = self.drained.notified();
            tokio::pin!(drained);
            drained.as_mut().enable();
            if self.state.lock().unwrap().pending == 0 {
                break;
            }
            drained.await;
        }
        let both = self.state.lock().unwrap().sent_eof;
        if both {
            self.finish_eof_send().await?;
            self.ch.close(code::NORMAL, None).await;
        }
        Ok(None)
    }

    /// Returns credit for bytes written to the local end, up to the outstanding bytes read.
    pub fn consumed(&self, n: usize) {
        let n = {
            let mut state = self.state.lock().unwrap();
            let n = n.min(state.pending);
            state.pending -= n;
            n
        };
        self.ch.return_credit(n);
        self.drained.notify_waiters();
    }

    /// Writes all the bytes. DATA is never fragmented: each message is sized to the free credit and
    /// the peer's frame limit (pipe/1, implementation notes).
    pub async fn write(&self, mut data: Bytes) -> Result<()> {
        let _writer = self.writer.lock().await;
        if self.state.lock().unwrap().sent_eof {
            return Err(Error::Invalid("pipe already sent EOF"));
        }
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
        let _writer = self.writer.lock().await;
        self.state.lock().unwrap().sent_eof = true;
        self.finish_eof_send().await?;
        let both = self.state.lock().unwrap().recv_eof;
        if both {
            self.ch.close(code::NORMAL, None).await;
        }
        Ok(())
    }

    // Keep the actual send future in the Pipe, rather than the caller's write_eof future. A
    // cancelled writer cannot lose completion, and a reader must finish this send before CLOSE
    // can discard queued messages. Dropping the Pipe drops the send and its channel clone too.
    async fn finish_eof_send(&self) -> Result<()> {
        let mut send = self.eof_send.lock().await;
        if matches!(*send, EofSend::New) {
            let ch = self.ch.clone();
            *send = EofSend::Pending(Box::pin(async move { ch.send(EOF, Bytes::new()).await }));
        }
        if let EofSend::Pending(pending) = &mut *send {
            let result = pending.await;
            *send = EofSend::Done(result);
        }
        match &*send {
            EofSend::Done(result) => result.clone(),
            _ => unreachable!("EOF send completed"),
        }
    }

    pub async fn reset(&self, c: u16, reason: &str) -> Result<()> {
        self.ch.send(RESET, serde_json::to_vec(&json!({ "code": c, "reason": reason })).expect("JSON encodes")).await?;
        self.ch.close(code::GOING_AWAY, None).await;
        Ok(())
    }
}
