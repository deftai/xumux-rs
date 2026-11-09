//! The session: core §3-§10, as a state machine with no I/O and no clock of its own.
//!
//! A driver feeds it received frames with [`Core::on_frame`], takes frames to write with
//! [`Core::next_frame`], and calls [`Core::tick`] with the time. It never asks what transport it is
//! on (core §1.2, rule 1).
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use serde_json::{json, Map, Value};
use tokio::sync::{oneshot, Notify};

use crate::error::{CloseInfo, Error, Result};
use crate::frame::{code, ctl, Frame, CONTROL_MAX, MORE, PING, PONG, PROBE, RESERVED_CHANNEL};

pub const PROTOCOL_VERSION: [u64; 3] = [0, 3, 0];
const MAX_CREDIT: u64 = (1 << 31) - 1;
const WINDOW_ENTRIES_PER_FRAME: usize = (CONTROL_MAX as usize) / 6;

/// What a receiver declares: core §3.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_frame_payload: u32,
    pub max_message_size: u32,
    pub initial_window: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_frame_payload: 65536, max_message_size: 262144, initial_window: 262144 }
    }
}

impl Limits {
    fn valid(&self) -> bool {
        self.max_frame_payload >= 4096
            && self.max_message_size >= self.max_frame_payload
            && self.initial_window >= self.max_message_size
            && u64::from(self.initial_window) <= MAX_CREDIT
    }
}

#[derive(Clone)]
pub struct Options {
    pub limits: Limits,
    /// Seconds. 0 turns keepalive off. On a server, this applies to both sides.
    pub ping_interval: u64,
    pub ping_timeout: u64,
    pub max_channels: usize,
    pub handshake_timeout: Duration,
    pub close_timeout: Duration,
    /// Fragment size on a shared path, for fair interleaving (core §7).
    pub fragment_size: u32,
    /// How far a channel's receive window may grow. Windows don't grow at or below `initial_window`.
    pub max_channel_window: u64,
    pub connection_window: u64,
    pub max_control_queue: usize,
    /// Most bytes handed to the transport at once. Smaller lets a high-priority channel overtake
    /// sooner; larger costs fewer system calls.
    pub write_batch: usize,
    pub application: Option<String>,
    pub auth: Option<Value>,
    pub extensions: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            limits: Limits::default(),
            ping_interval: 30,
            ping_timeout: 10,
            max_channels: 1024,
            handshake_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(5),
            fragment_size: 16384,
            max_channel_window: 16 << 20,
            connection_window: 64 << 20,
            max_control_queue: 1 << 20,
            write_batch: 64 * 1024,
            application: None,
            auth: None,
            extensions: Vec::new(),
        }
    }
}

/// A request for a channel: the body of OPEN_CHANNEL.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelSpec {
    pub name: String,
    pub reliable: bool,
    pub ordered: bool,
    pub max_retransmits: Option<u64>,
    pub max_packet_life_time: Option<u64>,
    pub metadata: Option<Map<String, Value>>,
}

impl ChannelSpec {
    pub fn reliable(name: impl Into<String>) -> Self {
        ChannelSpec {
            name: name.into(),
            reliable: true,
            ordered: true,
            max_retransmits: None,
            max_packet_life_time: None,
            metadata: None,
        }
    }

    pub fn profile(mut self, profile: &str) -> Self {
        self.metadata.get_or_insert_with(Map::new).insert("profile".into(), json!(profile));
        self
    }

    pub fn meta(mut self, key: &str, value: Value) -> Self {
        self.metadata.get_or_insert_with(Map::new).insert(key.into(), value);
        self
    }

    fn to_json(&self, id: u16) -> Value {
        let mut o = json!({ "id": id, "name": self.name, "reliable": self.reliable, "ordered": self.ordered });
        if let Some(v) = self.max_retransmits {
            o["maxRetransmits"] = json!(v);
        }
        if let Some(v) = self.max_packet_life_time {
            o["maxPacketLifeTime"] = json!(v);
        }
        if let Some(m) = &self.metadata {
            o["metadata"] = Value::Object(m.clone());
        }
        o
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Properties {
    pub reliable: bool,
    pub ordered: bool,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub ty: u8,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ProbeStats {
    pub rtt: Option<Duration>,
    pub srtt: Option<Duration>,
    pub rttvar: Option<Duration>,
    pub probes_sent: u64,
    pub probes_lost: u64,
}

impl ProbeStats {
    fn sample(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
        match (self.srtt, self.rttvar) {
            (Some(s), Some(v)) => {
                let delta = s.abs_diff(rtt);
                self.rttvar = Some(v * 3 / 4 + delta / 4);
                self.srtt = Some(s * 7 / 8 + rtt / 8);
            }
            _ => {
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
        }
    }
}

/// A server's decision on HELLO (`authorize`) or on a channel (`policy`).
#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: u16,
    pub reason: String,
}

impl Refusal {
    pub fn new(code: u16, reason: impl Into<String>) -> Self {
        Refusal { code, reason: reason.into() }
    }
}

pub type Policy = Arc<dyn Fn(&ChannelSpec) -> std::result::Result<(), Refusal> + Send + Sync>;
pub type Authorize = Arc<dyn Fn(&Map<String, Value>) -> std::result::Result<(), Refusal> + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Waiting for HELLO (server) or WELCOME (client).
    Handshake,
    Open,
    /// We sent CLOSE and are waiting for the peer's.
    CloseSent,
    Done,
}

/// Wakes a channel's users, and holds what is left when the channel ends. Shared with the handle, so
/// a handle can still drain its messages after the ID has been reused by another channel.
pub(crate) struct Signals {
    pub recv: Notify,
    pub credit: Notify,
    pub closed: Notify,
    pub finished: Mutex<Option<Finished>>,
}

pub(crate) struct Finished {
    pub recv: VecDeque<Message>,
    pub info: CloseInfo,
    pub stats: ProbeStats,
}

struct OutMsg {
    ty: u8,
    payload: Bytes,
    sent_any: bool,
    done: Option<oneshot::Sender<Result<()>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChanState {
    Opening,
    Open,
    /// CLOSE_CHANNEL sent or received, not yet both.
    Closing,
}

struct Chan {
    state: ChanState,
    sent_close: bool,
    recv_close: bool,
    props: Properties,
    priority: u8,
    send_credit: u64,
    outq: VecDeque<OutMsg>,
    recv: VecDeque<Message>,
    reasm: Option<(u8, BytesMut)>,
    /// Bytes the peer may still send.
    recv_credit: u64,
    /// Consumed and not yet returned.
    unreturned: u64,
    manual_credit: bool,
    window: u64,
    window_consumed: u64,
    window_started: Instant,
    probing_for_growth: bool,
    close_info: Option<CloseInfo>,
    stats: ProbeStats,
    sig: Arc<Signals>,
    open_waiter: Option<oneshot::Sender<Result<Properties>>>,
    close_waiters: Vec<oneshot::Sender<()>>,
}

struct PendingPing {
    channel: u16,
    sig: Option<Arc<Signals>>,
    sent: Instant,
    waiter: Option<oneshot::Sender<Result<Duration>>>,
}

/// One accepted peer-opened channel, for the driver to hand to the application.
pub(crate) struct Accepted {
    pub id: u16,
    pub spec: ChannelSpec,
    pub sig: Arc<Signals>,
}

pub struct Core {
    role: Role,
    phase: Phase,
    opts: Options,
    remote: Limits,
    policy: Option<Policy>,
    authorize: Option<Authorize>,
    channels: BTreeMap<u16, Chan>,
    ctrl_out: VecDeque<Frame>,
    ctrl_bytes: usize,
    probes_out: VecDeque<Frame>,
    grants: BTreeMap<u16, u64>,
    /// Channels with something to send, by priority then ID.
    sendable: BTreeSet<(u8, u16)>,
    /// Where each priority's round robin last stopped.
    cursor: HashMap<u8, u16>,
    pings: HashMap<u32, PendingPing>,
    epoch: Instant,
    last_recv: Instant,
    keepalive_sent: Option<Instant>,
    ping_interval: u64,
    ping_timeout: u64,
    total_window: u64,
    close_info: Option<CloseInfo>,
    close_sent_at: Option<Instant>,
    /// CLOSE has been queued; nothing may follow it.
    close_queued: bool,
    close_frame_taken: bool,
    /// The peer sent CLOSE first, so writing our reply ends the connection.
    peer_closed: bool,
    started: Instant,
    pub(crate) accepted: VecDeque<Accepted>,
    pub(crate) welcome: Option<Map<String, Value>>,
    pub(crate) hello: Option<Map<String, Value>>,
    pub(crate) handshake_done: Arc<Notify>,
    pub(crate) rejected: Vec<(u16, u16, String)>,
    pub(crate) stats: ProbeStats,
    pub(crate) wake_accept: Arc<Notify>,
    pub(crate) session_closed: Arc<Notify>,
}

fn new_signals() -> Arc<Signals> {
    Arc::new(Signals { recv: Notify::new(), credit: Notify::new(), closed: Notify::new(), finished: Mutex::new(None) })
}

fn int_field(o: &Map<String, Value>, key: &str) -> std::result::Result<u64, Refusal> {
    o.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(code::INVALID_MESSAGE, format!("{key} must be a non-negative integer")))
}

fn opt_int(o: &Map<String, Value>, key: &str) -> std::result::Result<Option<u64>, Refusal> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| Refusal::new(code::INVALID_MESSAGE, format!("{key} must be a non-negative integer"))),
    }
}

fn bool_field(o: &Map<String, Value>, key: &str) -> std::result::Result<bool, Refusal> {
    o.get(key).and_then(Value::as_bool).ok_or_else(|| Refusal::new(code::INVALID_MESSAGE, format!("{key} must be a boolean")))
}

fn str_field(o: &Map<String, Value>, key: &str) -> std::result::Result<String, Refusal> {
    o.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new(code::INVALID_MESSAGE, format!("{key} must be a string")))
}

fn opt_str(o: &Map<String, Value>, key: &str) -> std::result::Result<Option<String>, Refusal> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(Refusal::new(code::INVALID_MESSAGE, format!("{key} must be a string"))),
    }
}

fn parse_object(payload: &[u8]) -> std::result::Result<Map<String, Value>, Refusal> {
    match serde_json::from_slice::<Value>(payload) {
        Ok(Value::Object(o)) => Ok(o),
        _ => Err(Refusal::new(code::INVALID_MESSAGE, "control payload is not a JSON object")),
    }
}

fn parse_spec(o: &Map<String, Value>) -> std::result::Result<(u64, ChannelSpec), Refusal> {
    let id = int_field(o, "id")?;
    let spec = ChannelSpec {
        name: str_field(o, "name")?,
        reliable: bool_field(o, "reliable")?,
        ordered: bool_field(o, "ordered")?,
        max_retransmits: opt_int(o, "maxRetransmits")?,
        max_packet_life_time: opt_int(o, "maxPacketLifeTime")?,
        metadata: match o.get("metadata") {
            None | Some(Value::Null) => None,
            Some(Value::Object(m)) => Some(m.clone()),
            _ => return Err(Refusal::new(code::INVALID_MESSAGE, "metadata must be an object")),
        },
    };
    Ok((id, spec))
}

fn limits_from(o: &Map<String, Value>) -> std::result::Result<Limits, Refusal> {
    let d = Limits::default();
    let get = |k: &str, def: u32| -> std::result::Result<u32, Refusal> {
        Ok(match opt_int(o, k)? {
            Some(v) => u32::try_from(v).map_err(|_| Refusal::new(code::INVALID_MESSAGE, format!("{k} is out of range")))?,
            None => def,
        })
    };
    let l = Limits {
        max_frame_payload: get("maxFramePayload", d.max_frame_payload)?,
        max_message_size: get("maxMessageSize", d.max_message_size)?,
        initial_window: get("initialWindow", d.initial_window)?,
    };
    if !l.valid() {
        return Err(Refusal::new(code::INVALID_MESSAGE, "declared limits are out of bounds"));
    }
    Ok(l)
}

impl Core {
    pub fn new(role: Role, opts: Options, policy: Option<Policy>, authorize: Option<Authorize>, now: Instant) -> Result<Core> {
        if !opts.limits.valid() {
            return Err(Error::Invalid("declared limits are out of bounds"));
        }
        Ok(Core {
            role,
            phase: Phase::Handshake,
            ping_interval: opts.ping_interval,
            ping_timeout: opts.ping_timeout,
            opts,
            remote: Limits::default(),
            policy,
            authorize,
            channels: BTreeMap::new(),
            ctrl_out: VecDeque::new(),
            ctrl_bytes: 0,
            probes_out: VecDeque::new(),
            grants: BTreeMap::new(),
            sendable: BTreeSet::new(),
            cursor: HashMap::new(),
            pings: HashMap::new(),
            epoch: now,
            last_recv: now,
            keepalive_sent: None,
            total_window: 0,
            close_info: None,
            close_sent_at: None,
            close_queued: false,
            close_frame_taken: false,
            peer_closed: false,
            started: now,
            accepted: VecDeque::new(),
            welcome: None,
            hello: None,
            handshake_done: Arc::new(Notify::new()),
            rejected: Vec::new(),
            stats: ProbeStats::default(),
            wake_accept: Arc::new(Notify::new()),
            session_closed: Arc::new(Notify::new()),
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn is_open(&self) -> bool {
        self.phase == Phase::Open
    }

    pub fn is_handshaking(&self) -> bool {
        self.phase == Phase::Handshake
    }

    /// The transport can be closed: the exchange finished, or the connection is dead.
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    /// CLOSE has been handed to the transport, so the driver should end its write side.
    pub fn close_written(&self) -> bool {
        self.close_frame_taken
    }

    pub fn close_info(&self) -> Option<CloseInfo> {
        self.close_info.clone()
    }

    pub fn write_batch(&self) -> usize {
        self.opts.write_batch.max(1)
    }

    pub fn remote_limits(&self) -> Limits {
        self.remote
    }

    pub fn local_limits(&self) -> Limits {
        self.opts.limits
    }

    /// The largest payload a frame may have on `channel` from this side's point of view as receiver.
    pub fn frame_limit(&self, channel: u16) -> u32 {
        if channel == 0 {
            CONTROL_MAX
        } else {
            self.opts.limits.max_frame_payload
        }
    }

    // --- Output ---

    fn queue_ctrl(&mut self, ty: u8, body: &Value) {
        if self.close_queued {
            return;
        }
        let payload = Bytes::from(serde_json::to_vec(body).expect("JSON encodes"));
        self.queue_ctrl_frame(Frame::new(0, ty, 0, payload));
    }

    /// Replies pile up if the peer doesn't read them (core §4.2).
    fn queue_ctrl_frame(&mut self, f: Frame) {
        let size = f.encoded_len();
        if self.opts.max_control_queue > 0 && self.ctrl_bytes + size > self.opts.max_control_queue {
            self.fail(code::RATE_LIMITED, "too many unread control replies");
            return;
        }
        self.ctrl_bytes += size;
        self.ctrl_out.push_back(f);
    }

    /// Next frame to write. Control first, then probes, then channels: strict priority between
    /// levels, round robin within one (core §7).
    pub fn next_frame(&mut self, completed: &mut Vec<oneshot::Sender<Result<()>>>) -> Option<Frame> {
        if self.phase == Phase::Done || self.close_frame_taken {
            return None;
        }
        if !self.close_queued
            && let Some(f) = self.take_grants() {
                return Some(f);
            }
        if let Some(f) = self.ctrl_out.pop_front() {
            self.ctrl_bytes -= f.encoded_len();
            if f.channel == 0 && f.ty == ctl::CLOSE {
                self.close_frame_taken = true;
            }
            return Some(f);
        }
        if self.close_queued || self.phase == Phase::Handshake {
            return None;
        }
        if let Some(f) = self.probes_out.pop_front() {
            return Some(f);
        }
        self.next_data_frame(completed)
    }

    fn take_grants(&mut self) -> Option<Frame> {
        if self.grants.is_empty() {
            return None;
        }
        let mut payload = BytesMut::new();
        let ids: Vec<u16> = self.grants.keys().copied().take(WINDOW_ENTRIES_PER_FRAME).collect();
        for id in ids {
            let mut left = self.grants.remove(&id).unwrap_or(0);
            // An increment is at most 2^31-1, which may need more than one entry.
            while left > 0 {
                let inc = left.min(MAX_CREDIT);
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&(inc as u32).to_be_bytes());
                left -= inc;
            }
        }
        if payload.is_empty() {
            return None;
        }
        Some(Frame::new(0, ctl::WINDOW_UPDATE, 0, payload.freeze()))
    }

    fn next_data_frame(&mut self, completed: &mut Vec<oneshot::Sender<Result<()>>>) -> Option<Frame> {
        let levels: Vec<u8> = {
            let mut v: Vec<u8> = self.sendable.iter().map(|(p, _)| *p).collect();
            v.dedup();
            v
        };
        for prio in levels {
            let from = self.cursor.get(&prio).copied().unwrap_or(0);
            let after: Vec<u16> = self
                .sendable
                .range((prio, from.saturating_add(1))..=(prio, u16::MAX))
                .map(|(_, id)| *id)
                .chain(self.sendable.range((prio, 0)..=(prio, from)).map(|(_, id)| *id))
                .collect();
            for id in after {
                if let Some(f) = self.frame_from(id, completed) {
                    self.cursor.insert(prio, id);
                    return Some(f);
                }
            }
        }
        None
    }

    fn frame_from(&mut self, id: u16, completed: &mut Vec<oneshot::Sender<Result<()>>>) -> Option<Frame> {
        let frag = self.opts.fragment_size.max(1).min(self.remote.max_frame_payload) as usize;
        let ch = self.channels.get_mut(&id)?;
        if ch.state != ChanState::Open || ch.sent_close {
            return None;
        }
        let reliable = ch.props.reliable;
        let can_fragment = ch.props.reliable && ch.props.ordered;
        let credit = ch.send_credit;
        let m = ch.outq.front_mut()?;
        // A reliable channel may be out of credit, in which case it waits for WINDOW_UPDATE.
        if reliable && credit == 0 && !m.payload.is_empty() {
            return None;
        }
        let mut n = m.payload.len().min(frag);
        if reliable {
            n = n.min(credit as usize);
        }
        if !can_fragment {
            n = m.payload.len();
        }
        let chunk = m.payload.split_to(n);
        m.sent_any = true;
        let more = !m.payload.is_empty();
        let f = Frame::new(id, m.ty, if more { MORE } else { 0 }, chunk);
        if reliable {
            ch.send_credit -= n as u64;
        }
        if !more {
            if let Some(done) = ch.outq.pop_front().and_then(|m| m.done) {
                completed.push(done);
            }
            if ch.outq.is_empty() {
                let key = (ch.priority, id);
                self.sendable.remove(&key);
            }
        }
        Some(f)
    }

    // --- Handshake ---

    /// Client: queue HELLO, with channels to open during the handshake.
    pub(crate) fn start_client(&mut self, channels: &[ChannelSpec], now: Instant) -> Vec<(u16, Arc<Signals>)> {
        let mut out = Vec::new();
        let mut reqs = Vec::new();
        let mut id = 1u16;
        for spec in channels {
            let sig = self.insert_channel(id, ChanState::Opening, now);
            reqs.push(spec.to_json(id));
            out.push((id, sig));
            id += 2;
        }
        let l = self.opts.limits;
        let mut hello = json!({
            "version": PROTOCOL_VERSION,
            "maxFramePayload": l.max_frame_payload,
            "maxMessageSize": l.max_message_size,
            "initialWindow": l.initial_window,
            "pingInterval": self.opts.ping_interval,
            "pingTimeout": self.opts.ping_timeout,
            "channels": reqs,
        });
        if let Some(a) = &self.opts.application {
            hello["application"] = json!(a);
        }
        if let Some(a) = &self.opts.auth {
            hello["auth"] = a.clone();
        }
        if !self.opts.extensions.is_empty() {
            hello["extensions"] = json!(self.opts.extensions);
        }
        self.queue_ctrl(ctl::HELLO, &hello);
        out
    }

    fn version_ok(v: &[u64]) -> bool {
        // 0.x: major and minor must match. Patch differences are compatible (core §3.5).
        v.len() == 3 && v[0] == PROTOCOL_VERSION[0] && v[1] == PROTOCOL_VERSION[1]
    }

    fn parse_version(o: &Map<String, Value>) -> std::result::Result<Vec<u64>, Refusal> {
        let bad = || Refusal::new(code::INVALID_MESSAGE, "version must be [major, minor, patch]");
        let arr = o.get("version").and_then(Value::as_array).ok_or_else(bad)?;
        if arr.len() != 3 {
            return Err(bad());
        }
        arr.iter().map(|v| v.as_u64().ok_or_else(bad)).collect()
    }

    fn on_hello(&mut self, payload: &[u8], now: Instant) {
        match self.handle_hello(payload, now) {
            Ok(()) => {}
            Err(r) => self.fail(r.code, &r.reason),
        }
    }

    fn handle_hello(&mut self, payload: &[u8], now: Instant) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let version = Self::parse_version(&o)?;
        if !Self::version_ok(&version) {
            return Err(Refusal::new(code::VERSION_MISMATCH, "unsupported version"));
        }
        let remote = limits_from(&o)?;
        opt_str(&o, "application")?;
        opt_int(&o, "pingInterval")?;
        opt_int(&o, "pingTimeout")?;
        let extensions = match o.get("extensions") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| Refusal::new(code::INVALID_MESSAGE, "extensions must be strings")))
                .collect::<std::result::Result<Vec<_>, _>>()?,
            _ => return Err(Refusal::new(code::INVALID_MESSAGE, "extensions must be an array")),
        };
        match o.get("extensionParams") {
            None | Some(Value::Null) | Some(Value::Object(_)) => {}
            _ => return Err(Refusal::new(code::INVALID_MESSAGE, "extensionParams must be an object")),
        }
        let channels = match o.get("channels") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            _ => return Err(Refusal::new(code::INVALID_MESSAGE, "channels must be an array")),
        };
        // Parse everything first: a bad entry refuses the whole HELLO, with no channels half open.
        let mut specs = Vec::with_capacity(channels.len());
        let mut seen = BTreeSet::new();
        for c in &channels {
            let Value::Object(co) = c else {
                return Err(Refusal::new(code::INVALID_MESSAGE, "a channel request must be an object"));
            };
            let (id, spec) = parse_spec(co)?;
            if id == 0 || id > u64::from(RESERVED_CHANNEL) || id % 2 == 0 || id == u64::from(RESERVED_CHANNEL) || !seen.insert(id) {
                return Err(Refusal::new(code::PROTOCOL_ERROR, "bad channel ID in HELLO"));
            }
            specs.push((id as u16, spec));
        }
        if let Some(auth) = &self.authorize {
            auth(&o)?;
        }
        self.remote = remote;
        self.hello = Some(o);

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        let mut count = 0usize;
        for (id, spec) in specs {
            if count >= self.opts.max_channels {
                rejected.push(json!({ "id": id, "code": code::CHANNEL_LIMIT }));
                continue;
            }
            match self.decide(&spec) {
                Ok(()) => {
                    count += 1;
                    let sig = self.insert_channel(id, ChanState::Open, now);
                    let props = self.channels[&id].props;
                    accepted.push(json!({ "id": id, "reliable": props.reliable, "ordered": props.ordered }));
                    self.accepted.push_back(Accepted { id, spec, sig });
                }
                Err(r) => rejected.push(json!({ "id": id, "code": r.code, "reason": r.reason })),
            }
        }
        // No extensions are implemented yet, so WELCOME accepts none of the client's.
        let _ = extensions;
        let l = self.opts.limits;
        let welcome = json!({
            "version": PROTOCOL_VERSION,
            "extensions": [],
            "maxFramePayload": l.max_frame_payload,
            "maxMessageSize": l.max_message_size,
            "initialWindow": l.initial_window,
            "pingInterval": self.opts.ping_interval,
            "pingTimeout": self.opts.ping_timeout,
            "channels": accepted,
            "rejected": rejected,
        });
        self.queue_ctrl(ctl::WELCOME, &welcome);
        self.ping_interval = self.opts.ping_interval;
        self.ping_timeout = self.opts.ping_timeout;
        self.phase = Phase::Open;
        // Credit granted to the peer takes effect only now that its limits are known.
        let init = u64::from(self.remote.initial_window);
        for ch in self.channels.values_mut() {
            ch.send_credit = init;
        }
        self.handshake_done.notify_waiters();
        self.wake_accept.notify_waiters();
        Ok(())
    }

    fn on_welcome(&mut self, payload: &[u8]) {
        if let Err(r) = self.handle_welcome(payload) {
            self.fail(r.code, &r.reason);
        }
    }

    fn handle_welcome(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let version = Self::parse_version(&o)?;
        if !Self::version_ok(&version) {
            return Err(Refusal::new(code::VERSION_MISMATCH, "unsupported version"));
        }
        self.remote = limits_from(&o)?;
        if let Some(v) = opt_int(&o, "pingInterval")? {
            self.ping_interval = v;
        }
        if let Some(v) = opt_int(&o, "pingTimeout")? {
            self.ping_timeout = v;
        }
        let init = u64::from(self.remote.initial_window);
        let opening: BTreeSet<u16> = self.channels.keys().copied().collect();
        let mut answered = BTreeSet::new();
        if let Some(Value::Array(a)) = o.get("channels") {
            for c in a {
                let Value::Object(co) = c else {
                    return Err(Refusal::new(code::INVALID_MESSAGE, "bad WELCOME channel"));
                };
                let id = int_field(co, "id")?;
                let reliable = bool_field(co, "reliable")?;
                let ordered = bool_field(co, "ordered")?;
                let id16 = u16::try_from(id).ok().filter(|i| opening.contains(i));
                let Some(id16) = id16 else {
                    return Err(Refusal::new(code::PROTOCOL_ERROR, "WELCOME lists an ID that was not in HELLO"));
                };
                answered.insert(id16);
                let ch = self.channels.get_mut(&id16).expect("present");
                ch.props = Properties { reliable, ordered };
                ch.state = ChanState::Open;
                ch.send_credit = init;
                if let Some(w) = ch.open_waiter.take() {
                    let _ = w.send(Ok(ch.props));
                }
            }
        }
        if let Some(Value::Array(a)) = o.get("rejected") {
            for c in a {
                let Value::Object(co) = c else {
                    return Err(Refusal::new(code::INVALID_MESSAGE, "bad WELCOME refusal"));
                };
                let id = int_field(co, "id")?;
                let rcode = int_field(co, "code")?;
                let reason = opt_str(co, "reason")?.unwrap_or_default();
                let id16 = u16::try_from(id).ok().filter(|i| opening.contains(i) && !answered.contains(i));
                let Some(id16) = id16 else {
                    return Err(Refusal::new(code::PROTOCOL_ERROR, "WELCOME lists an ID that was not in HELLO"));
                };
                answered.insert(id16);
                self.rejected.push((id16, rcode as u16, reason.clone()));
                if let Some(mut ch) = self.channels.remove(&id16)
                    && let Some(w) = ch.open_waiter.take() {
                        let _ = w.send(Err(Error::Refused(CloseInfo { code: rcode as u16, reason })));
                    }
            }
        }
        if answered.len() != opening.len() {
            return Err(Refusal::new(code::PROTOCOL_ERROR, "WELCOME does not answer every HELLO channel"));
        }
        self.welcome = Some(o);
        self.phase = Phase::Open;
        self.handshake_done.notify_waiters();
        Ok(())
    }

    fn decide(&self, spec: &ChannelSpec) -> std::result::Result<(), Refusal> {
        match &self.policy {
            Some(p) => p(spec),
            None => Err(Refusal::new(code::UNSUPPORTED, "this side does not accept channels")),
        }
    }

    fn insert_channel(&mut self, id: u16, state: ChanState, now: Instant) -> Arc<Signals> {
        let sig = new_signals();
        let window = u64::from(self.opts.limits.initial_window);
        self.total_window += window;
        self.channels.insert(
            id,
            Chan {
                state,
                sent_close: false,
                recv_close: false,
                // Only a base path exists: every channel is effectively reliable and ordered.
                props: Properties { reliable: true, ordered: true },
                priority: 128,
                send_credit: if self.phase == Phase::Open { u64::from(self.remote.initial_window) } else { 0 },
                outq: VecDeque::new(),
                recv: VecDeque::new(),
                reasm: None,
                recv_credit: window,
                unreturned: 0,
                manual_credit: false,
                window,
                window_consumed: 0,
                window_started: now,
                probing_for_growth: false,
                close_info: None,
                stats: ProbeStats::default(),
                sig: sig.clone(),
                open_waiter: None,
                close_waiters: Vec::new(),
            },
        );
        sig
    }

    // --- Input ---

    /// One received frame, after framing has applied core §2.3 steps 1-2.
    pub fn on_frame(&mut self, f: Frame, now: Instant) {
        self.last_recv = now;
        self.keepalive_sent = None;
        if self.phase == Phase::Done {
            return;
        }
        // Step 3.
        if f.channel == RESERVED_CHANNEL || f.flags & !(MORE | PROBE) != 0 {
            self.fail(code::PROTOCOL_ERROR, "reserved channel or flag");
            return;
        }
        if f.channel == 0 && f.flags & MORE != 0 {
            self.fail(code::PROTOCOL_ERROR, "MORE on channel 0");
            return;
        }
        if f.flags & MORE != 0 && f.flags & PROBE != 0 {
            self.fail(code::PROTOCOL_ERROR, "MORE on a probe");
            return;
        }
        if self.phase == Phase::CloseSent {
            if f.channel == 0 && f.flags & PROBE == 0 && f.ty == ctl::CLOSE {
                self.on_close(&f.payload);
            }
            return;
        }
        if self.phase == Phase::Handshake {
            self.on_handshake_frame(f, now);
            return;
        }
        if f.flags & PROBE != 0 {
            self.on_probe(f, now);
        } else if f.channel == 0 {
            self.on_control(f, now);
        } else {
            self.on_data(f);
        }
    }

    fn on_handshake_frame(&mut self, f: Frame, now: Instant) {
        let control = f.channel == 0 && f.flags & PROBE == 0;
        match self.role {
            Role::Server => {
                if control && f.ty == ctl::HELLO {
                    self.on_hello(&f.payload, now);
                } else if control && f.ty == ctl::CLOSE {
                    self.on_close(&f.payload);
                } else {
                    self.fail(code::PROTOCOL_ERROR, "the first frame must be HELLO");
                }
            }
            Role::Client => {
                if control && f.ty == ctl::WELCOME {
                    self.on_welcome(&f.payload);
                } else if control && f.ty == ctl::CLOSE {
                    self.on_close(&f.payload);
                } else {
                    self.fail(code::PROTOCOL_ERROR, "expected WELCOME");
                }
            }
        }
    }

    fn on_probe(&mut self, f: Frame, now: Instant) {
        if f.payload.len() != 4 || (f.ty != PING && f.ty != PONG) {
            return;
        }
        if f.channel != 0 {
            match self.channels.get(&f.channel) {
                Some(ch) if ch.state == ChanState::Open && !ch.sent_close => {}
                _ => return,
            }
        }
        if f.ty == PING {
            self.probes_out.push_back(Frame::new(f.channel, PONG, PROBE, f.payload));
            return;
        }
        let token = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
        if let Some(mut p) = self.pings.remove(&token) {
            if p.channel != f.channel {
                self.pings.insert(token, p);
                return;
            }
            let rtt = now.saturating_duration_since(p.sent);
            if p.channel == 0 {
                self.stats.sample(rtt);
            } else if let Some(ch) = self.channels.get_mut(&p.channel) {
                ch.stats.sample(rtt);
                ch.probing_for_growth = false;
            }
            if let Some(w) = p.waiter.take() {
                let _ = w.send(Ok(rtt));
            }
            let _ = p.sig;
        }
    }

    fn on_control(&mut self, f: Frame, now: Instant) {
        let r = match f.ty {
            ctl::HELLO | ctl::WELCOME => Err(Refusal::new(code::PROTOCOL_ERROR, "a second HELLO or WELCOME")),
            ctl::OPEN_CHANNEL => self.on_open_channel(&f.payload, now),
            ctl::CHANNEL_ACK => self.on_channel_ack(&f.payload),
            ctl::CHANNEL_REJECT => self.on_channel_reject(&f.payload),
            ctl::CLOSE_CHANNEL => self.on_close_channel(&f.payload),
            ctl::WINDOW_UPDATE => self.on_window_update(&f.payload),
            ctl::CLOSE => {
                self.on_close(&f.payload);
                Ok(())
            }
            ctl::ERROR => self.on_error(&f.payload),
            other => {
                self.queue_ctrl(ctl::ERROR, &json!({ "code": code::UNSUPPORTED, "reason": format!("unknown control type {other:#04x}") }));
                Ok(())
            }
        };
        if let Err(r) = r {
            self.fail(r.code, &r.reason);
        }
    }

    fn on_error(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        int_field(&o, "code")?;
        opt_int(&o, "channel")?;
        opt_str(&o, "reason")?;
        Ok(())
    }

    fn peer_parity(&self) -> u64 {
        match self.role {
            Role::Server => 1,
            Role::Client => 0,
        }
    }

    fn on_open_channel(&mut self, payload: &[u8], now: Instant) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let (id, spec) = parse_spec(&o)?;
        if id == 0 || id >= u64::from(RESERVED_CHANNEL) || id % 2 != self.peer_parity() || self.channels.contains_key(&(id as u16)) {
            return Err(Refusal::new(code::PROTOCOL_ERROR, "bad channel ID in OPEN_CHANNEL"));
        }
        let id = id as u16;
        let peer_opened = self.channels.keys().filter(|i| u64::from(**i) % 2 == self.peer_parity()).count();
        if peer_opened >= self.opts.max_channels {
            self.queue_ctrl(ctl::CHANNEL_REJECT, &json!({ "id": id, "code": code::CHANNEL_LIMIT, "reason": "too many channels" }));
            return Ok(());
        }
        match self.decide(&spec) {
            Ok(()) => {
                let sig = self.insert_channel(id, ChanState::Open, now);
                let props = self.channels[&id].props;
                self.queue_ctrl(ctl::CHANNEL_ACK, &json!({ "id": id, "reliable": props.reliable, "ordered": props.ordered }));
                self.accepted.push_back(Accepted { id, spec, sig });
                self.wake_accept.notify_waiters();
            }
            Err(r) => {
                self.queue_ctrl(ctl::CHANNEL_REJECT, &json!({ "id": id, "code": r.code, "reason": r.reason }));
            }
        }
        Ok(())
    }

    fn opening_channel(&self, id: u64) -> std::result::Result<u16, Refusal> {
        let id16 = u16::try_from(id).ok().filter(|i| matches!(self.channels.get(i), Some(c) if c.state == ChanState::Opening));
        id16.ok_or_else(|| Refusal::new(code::PROTOCOL_ERROR, "answer for a channel that is not opening"))
    }

    fn on_channel_ack(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let id = self.opening_channel(int_field(&o, "id")?)?;
        let props = Properties { reliable: bool_field(&o, "reliable")?, ordered: bool_field(&o, "ordered")? };
        let init = u64::from(self.remote.initial_window);
        let ch = self.channels.get_mut(&id).expect("present");
        ch.props = props;
        ch.state = ChanState::Open;
        ch.send_credit = init;
        if let Some(w) = ch.open_waiter.take() {
            let _ = w.send(Ok(props));
        }
        Ok(())
    }

    fn on_channel_reject(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let id = self.opening_channel(int_field(&o, "id")?)?;
        let rcode = int_field(&o, "code")?;
        let reason = opt_str(&o, "reason")?.unwrap_or_default();
        let mut ch = self.channels.remove(&id).expect("present");
        self.total_window -= ch.window;
        if let Some(w) = ch.open_waiter.take() {
            let _ = w.send(Err(Error::Refused(CloseInfo { code: rcode as u16, reason })));
        }
        Ok(())
    }

    fn on_close_channel(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let id = int_field(&o, "id")?;
        let c = opt_int(&o, "code")?.unwrap_or(u64::from(code::NORMAL));
        let reason = opt_str(&o, "reason")?.unwrap_or_default();
        if id == 0 {
            self.queue_ctrl(ctl::ERROR, &json!({ "code": code::PROTOCOL_ERROR, "reason": "channel 0 closes only with the connection" }));
            return Ok(());
        }
        let Some(id) = u16::try_from(id).ok().filter(|i| self.channels.contains_key(i)) else {
            return Ok(());
        };
        let ch = self.channels.get_mut(&id).expect("present");
        if ch.state == ChanState::Opening {
            return Ok(());
        }
        ch.recv_close = true;
        ch.reasm = None;
        ch.state = ChanState::Closing;
        ch.close_info.get_or_insert(CloseInfo { code: c as u16, reason });
        self.abort_sends(id);
        let ch = self.channels.get_mut(&id).expect("present");
        ch.sig.recv.notify_waiters();
        ch.sig.credit.notify_waiters();
        if !ch.sent_close {
            self.send_close_channel(id, c as u16, None);
        }
        self.maybe_finish(id);
        Ok(())
    }

    fn on_window_update(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        if payload.is_empty() || !payload.len().is_multiple_of(6) {
            return Err(Refusal::new(code::INVALID_MESSAGE, "bad WINDOW_UPDATE length"));
        }
        for e in payload.as_chunks::<6>().0 {
            let id = u16::from_be_bytes([e[0], e[1]]);
            let inc = u64::from(u32::from_be_bytes([e[2], e[3], e[4], e[5]]));
            if inc == 0 || inc > MAX_CREDIT {
                return Err(Refusal::new(code::INVALID_MESSAGE, "bad WINDOW_UPDATE increment"));
            }
            if id == 0 {
                return Err(Refusal::new(code::PROTOCOL_ERROR, "WINDOW_UPDATE for channel 0"));
            }
            let Some(ch) = self.channels.get_mut(&id) else { continue };
            if ch.state != ChanState::Open || ch.sent_close {
                continue;
            }
            if !ch.props.reliable {
                return Err(Refusal::new(code::PROTOCOL_ERROR, "WINDOW_UPDATE for an unreliable channel"));
            }
            if ch.send_credit + inc > MAX_CREDIT {
                return Err(Refusal::new(code::FLOW_CONTROL_ERROR, "credit above 2^31-1"));
            }
            ch.send_credit += inc;
            ch.sig.credit.notify_waiters();
        }
        Ok(())
    }

    fn on_data(&mut self, f: Frame) {
        let max_message = self.opts.limits.max_message_size as usize;
        let Some(ch) = self.channels.get_mut(&f.channel) else {
            return; // Core §5.5: discard. ERROR 4003 is optional, and only adds traffic.
        };
        if ch.state != ChanState::Open || ch.sent_close {
            return;
        }
        let len = f.payload.len() as u64;
        if ch.props.reliable {
            if len > ch.recv_credit {
                self.fail(code::FLOW_CONTROL_ERROR, "peer exceeded its credit");
                return;
            }
            ch.recv_credit -= len;
        }
        let can_fragment = ch.props.reliable && ch.props.ordered;
        let more = f.flags & MORE != 0;
        let id = f.channel;
        if more && !can_fragment {
            self.close_channel_with(id, code::PROTOCOL_ERROR, "MORE on a channel that can't fragment");
            return;
        }
        if let Some((ty, _)) = ch.reasm.as_ref()
            && *ty != f.ty {
                self.close_channel_with(id, code::PROTOCOL_ERROR, "type changed within a message");
                return;
            }
        let so_far = ch.reasm.as_ref().map_or(0, |(_, b)| b.len());
        if so_far + f.payload.len() > max_message {
            self.close_channel_with(id, code::MESSAGE_TOO_LARGE, "message exceeds maxMessageSize");
            return;
        }
        if !more && ch.reasm.is_none() {
            ch.recv.push_back(Message { ty: f.ty, payload: f.payload });
            ch.sig.recv.notify_waiters();
            return;
        }
        let (ty, buf) = ch.reasm.get_or_insert_with(|| (f.ty, BytesMut::with_capacity(f.payload.len() * 2)));
        buf.extend_from_slice(&f.payload);
        if !more {
            let m = Message { ty: *ty, payload: std::mem::take(buf).freeze() };
            ch.reasm = None;
            ch.recv.push_back(m);
            ch.sig.recv.notify_waiters();
        }
    }

    fn on_close(&mut self, payload: &[u8]) {
        let (c, reason) = match parse_object(payload) {
            Ok(o) => (
                o.get("code").and_then(Value::as_u64).unwrap_or(u64::from(code::PROTOCOL_ERROR)) as u16,
                o.get("reason").and_then(Value::as_str).unwrap_or("").to_owned(),
            ),
            Err(_) => (code::INVALID_MESSAGE, "malformed CLOSE".to_owned()),
        };
        self.close_info.get_or_insert(CloseInfo { code: c, reason: reason.clone() });
        match self.phase {
            Phase::CloseSent => self.finish(),
            _ => {
                // Reply, then the driver writes it and ends the transport.
                self.phase = Phase::CloseSent;
                self.close_queued = false;
                self.ctrl_out.clear();
                self.ctrl_bytes = 0;
                self.grants.clear();
                self.queue_ctrl(ctl::CLOSE, &json!({ "code": c }));
                self.close_queued = true;
                self.peer_closed = true;
                self.end_channels();
            }
        }
    }

    // --- Closing ---

    /// A protocol failure, or the local application closing: send CLOSE.
    pub fn fail(&mut self, c: u16, reason: &str) {
        if self.close_queued || self.phase == Phase::Done {
            return;
        }
        self.close_info.get_or_insert(CloseInfo { code: c, reason: reason.to_owned() });
        self.ctrl_out.clear();
        self.ctrl_bytes = 0;
        self.grants.clear();
        self.probes_out.clear();
        let body = if reason.is_empty() { json!({ "code": c }) } else { json!({ "code": c, "reason": reason }) };
        self.queue_ctrl(ctl::CLOSE, &body);
        self.close_queued = true;
        self.phase = Phase::CloseSent;
        self.end_channels();
    }

    pub fn close(&mut self, c: u16, reason: &str, now: Instant) {
        self.close_sent_at.get_or_insert(now);
        self.fail(c, reason);
    }

    /// Record when CLOSE went out, which starts the wait for the peer's.
    pub fn close_write_done(&mut self, now: Instant) {
        self.close_sent_at.get_or_insert(now);
        if self.peer_closed {
            self.finish();
        }
    }

    /// The transport ended.
    pub fn transport_closed(&mut self) {
        self.close_info.get_or_insert(CloseInfo { code: code::GOING_AWAY, reason: "transport closed".into() });
        self.finish();
    }

    fn end_channels(&mut self) {
        let info = self.close_info.clone().unwrap_or(CloseInfo { code: code::GOING_AWAY, reason: String::new() });
        let ids: Vec<u16> = self.channels.keys().copied().collect();
        for id in ids {
            self.abort_sends_with(id, Error::Closed(info.clone()));
            let mut ch = self.channels.remove(&id).expect("present");
            if let Some(w) = ch.open_waiter.take() {
                let _ = w.send(Err(Error::Closed(info.clone())));
            }
            *ch.sig.finished.lock().unwrap() = Some(Finished {
                recv: std::mem::take(&mut ch.recv),
                info: info.clone(),
                stats: ch.stats,
            });
            ch.sig.recv.notify_waiters();
            ch.sig.credit.notify_waiters();
            ch.sig.closed.notify_waiters();
            for w in ch.close_waiters.drain(..) {
                let _ = w.send(());
            }
        }
        self.sendable.clear();
        for (_, mut p) in self.pings.drain() {
            if let Some(w) = p.waiter.take() {
                let _ = w.send(Err(Error::Closed(info.clone())));
            }
        }
        self.handshake_done.notify_waiters();
        self.wake_accept.notify_waiters();
    }

    fn finish(&mut self) {
        if self.phase == Phase::Done {
            return;
        }
        self.end_channels();
        self.phase = Phase::Done;
        self.session_closed.notify_waiters();
    }

    fn abort_sends(&mut self, id: u16) {
        let info = self.channels[&id].close_info.clone().unwrap_or(CloseInfo { code: code::NORMAL, reason: String::new() });
        self.abort_sends_with(id, Error::ChannelClosed(info));
    }

    fn abort_sends_with(&mut self, id: u16, e: Error) {
        let Some(ch) = self.channels.get_mut(&id) else { return };
        let prio = ch.priority;
        for mut m in ch.outq.drain(..) {
            if let Some(d) = m.done.take() {
                let _ = d.send(Err(e.clone()));
            }
        }
        self.sendable.remove(&(prio, id));
    }

    fn send_close_channel(&mut self, id: u16, c: u16, reason: Option<&str>) {
        self.grants.remove(&id);
        let mut body = json!({ "id": id, "code": c });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        self.queue_ctrl(ctl::CLOSE_CHANNEL, &body);
        if let Some(ch) = self.channels.get_mut(&id) {
            ch.sent_close = true;
        }
    }

    /// A channel-level error: core §7.
    fn close_channel_with(&mut self, id: u16, c: u16, reason: &str) {
        let Some(ch) = self.channels.get_mut(&id) else { return };
        ch.state = ChanState::Closing;
        ch.reasm = None;
        ch.close_info.get_or_insert(CloseInfo { code: c, reason: reason.to_owned() });
        ch.sig.recv.notify_waiters();
        ch.sig.credit.notify_waiters();
        self.abort_sends(id);
        self.send_close_channel(id, c, Some(reason));
    }

    fn maybe_finish(&mut self, id: u16) {
        let done = matches!(self.channels.get(&id), Some(c) if c.sent_close && c.recv_close);
        if !done {
            return;
        }
        let mut ch = self.channels.remove(&id).expect("present");
        self.total_window -= ch.window;
        let info = ch.close_info.clone().unwrap_or(CloseInfo { code: code::NORMAL, reason: String::new() });
        *ch.sig.finished.lock().unwrap() = Some(Finished { recv: std::mem::take(&mut ch.recv), info, stats: ch.stats });
        ch.sig.recv.notify_waiters();
        ch.sig.closed.notify_waiters();
        ch.sig.credit.notify_waiters();
        for w in ch.close_waiters.drain(..) {
            let _ = w.send(());
        }
    }

    // --- Timers ---

    /// Keepalive (core §8.2) and the wait for the peer's CLOSE (core §9.1). Returns when to call again.
    pub fn tick(&mut self, now: Instant) -> Duration {
        match self.phase {
            Phase::Done => return Duration::from_secs(3600),
            Phase::Handshake => {
                if now.saturating_duration_since(self.started) >= self.opts.handshake_timeout {
                    match self.role {
                        Role::Server => self.fail(code::HELLO_TIMEOUT, "no HELLO within the timeout"),
                        Role::Client => self.fail(code::GOING_AWAY, "no WELCOME within the timeout"),
                    }
                }
                return Duration::from_millis(100).min(self.opts.handshake_timeout);
            }
            Phase::CloseSent => {
                if let Some(t) = self.close_sent_at
                    && now.saturating_duration_since(t) >= self.opts.close_timeout {
                        self.finish();
                    }
                return Duration::from_millis(50);
            }
            Phase::Open => {}
        }
        if self.ping_interval == 0 {
            return Duration::from_secs(3600);
        }
        let idle = Duration::from_secs(self.ping_interval);
        let timeout = Duration::from_secs(self.ping_timeout);
        if let Some(sent) = self.keepalive_sent {
            if now.saturating_duration_since(sent) >= timeout {
                self.close_info.get_or_insert(CloseInfo { code: code::KEEPALIVE_TIMEOUT, reason: "peer stopped responding".into() });
                self.fail(code::KEEPALIVE_TIMEOUT, "peer stopped responding");
                return Duration::from_millis(50);
            }
            return timeout - now.saturating_duration_since(sent);
        }
        let quiet = now.saturating_duration_since(self.last_recv);
        if quiet >= idle {
            self.keepalive_sent = Some(now);
            let token = self.new_token(now);
            self.probes_out.push_back(Frame::new(0, PING, PROBE, Bytes::copy_from_slice(&token.to_be_bytes())));
            self.stats.probes_sent += 1;
            return timeout;
        }
        idle - quiet
    }

    fn new_token(&self, now: Instant) -> u32 {
        let mut t = now.saturating_duration_since(self.epoch).as_micros() as u32;
        while self.pings.contains_key(&t) {
            t = t.wrapping_add(1);
        }
        t
    }

    // --- Application operations, used by the driver's handles ---

    fn closed_error(&self) -> Error {
        Error::Closed(self.close_info.clone().unwrap_or(CloseInfo { code: code::GOING_AWAY, reason: String::new() }))
    }

    pub(crate) fn open_channel(&mut self, spec: ChannelSpec, now: Instant) -> Result<(u16, Arc<Signals>, oneshot::Receiver<Result<Properties>>)> {
        if self.phase != Phase::Open {
            return Err(self.closed_error());
        }
        let start: u32 = if self.role == Role::Client { 1 } else { 2 };
        let id = (start..u32::from(RESERVED_CHANNEL))
            .step_by(2)
            .map(|i| i as u16)
            .find(|i| !self.channels.contains_key(i))
            .ok_or(Error::Invalid("no free channel IDs"))?;
        let body = spec.to_json(id);
        let _ = spec;
        let sig = self.insert_channel(id, ChanState::Opening, now);
        let (tx, rx) = oneshot::channel();
        self.channels.get_mut(&id).expect("present").open_waiter = Some(tx);
        self.queue_ctrl(ctl::OPEN_CHANNEL, &body);
        Ok((id, sig, rx))
    }

    pub(crate) fn hello_channel_waiter(&mut self, id: u16) -> Option<oneshot::Receiver<Result<Properties>>> {
        let ch = self.channels.get_mut(&id)?;
        let (tx, rx) = oneshot::channel();
        ch.open_waiter = Some(tx);
        Some(rx)
    }

    fn live<'a>(&'a mut self, id: u16, sig: &Arc<Signals>) -> Option<&'a mut Chan> {
        self.channels.get_mut(&id).filter(|c| Arc::ptr_eq(&c.sig, sig))
    }

    fn channel_error(&mut self, id: u16, sig: &Arc<Signals>) -> Error {
        if let Some(f) = sig.finished.lock().unwrap().as_ref() {
            return if self.close_info.is_some() && self.phase != Phase::Open {
                Error::Closed(f.info.clone())
            } else {
                Error::ChannelClosed(f.info.clone())
            };
        }
        let info = self.live(id, sig).and_then(|c| c.close_info.clone());
        Error::ChannelClosed(info.unwrap_or(CloseInfo { code: code::NORMAL, reason: String::new() }))
    }

    pub(crate) fn send(&mut self, id: u16, sig: &Arc<Signals>, ty: u8, payload: Bytes) -> Result<oneshot::Receiver<Result<()>>> {
        let limit = self.remote.max_message_size as usize;
        let frame_limit = self.remote.max_frame_payload as usize;
        if payload.len() > limit {
            return Err(Error::TooLarge { size: payload.len(), limit });
        }
        let err = self.channel_error_if_closed(id, sig);
        if let Some(e) = err {
            return Err(e);
        }
        let ch = self.channels.get_mut(&id).expect("checked");
        if !(ch.props.reliable && ch.props.ordered) && payload.len() > frame_limit {
            return Err(Error::TooLarge { size: payload.len(), limit: frame_limit });
        }
        let (tx, rx) = oneshot::channel();
        let key = (ch.priority, id);
        ch.outq.push_back(OutMsg { ty, payload, sent_any: false, done: Some(tx) });
        self.sendable.insert(key);
        Ok(rx)
    }

    fn channel_error_if_closed(&mut self, id: u16, sig: &Arc<Signals>) -> Option<Error> {
        match self.live(id, sig) {
            Some(c) if c.state == ChanState::Open && !c.sent_close => None,
            _ => Some(self.channel_error(id, sig)),
        }
    }

    /// Bytes that can be sent on this channel without waiting.
    pub(crate) fn send_credit(&mut self, id: u16, sig: &Arc<Signals>) -> Result<u64> {
        if let Some(e) = self.channel_error_if_closed(id, sig) {
            return Err(e);
        }
        let queued: u64 = self.channels[&id].outq.iter().map(|m| m.payload.len() as u64).sum();
        Ok(self.channels[&id].send_credit.saturating_sub(queued))
    }

    /// The largest message that goes out as a single frame.
    pub(crate) fn max_unfragmented(&self) -> u32 {
        self.opts.fragment_size.max(1).min(self.remote.max_frame_payload)
    }

    pub(crate) fn queued_messages(&mut self, id: u16, sig: &Arc<Signals>) -> usize {
        self.live(id, sig).map_or(0, |c| c.outq.len())
    }

    pub(crate) fn set_priority(&mut self, id: u16, sig: &Arc<Signals>, priority: u8) {
        let Some(ch) = self.live(id, sig) else { return };
        let old = (ch.priority, id);
        ch.priority = priority;
        let has_out = !ch.outq.is_empty();
        self.sendable.remove(&old);
        if has_out {
            self.sendable.insert((priority, id));
        }
    }

    pub(crate) fn set_manual_credit(&mut self, id: u16, sig: &Arc<Signals>, on: bool) {
        if let Some(ch) = self.live(id, sig) {
            ch.manual_credit = on;
        }
    }

    pub(crate) fn receive(&mut self, id: u16, sig: &Arc<Signals>, now: Instant) -> Option<Result<Option<Message>>> {
        if let Some(f) = sig.finished.lock().unwrap().as_mut() {
            return Some(match f.recv.pop_front() {
                Some(m) => Ok(Some(m)),
                None if f.info.code == code::NORMAL => Ok(None),
                None if self.phase != Phase::Open => {
                    if f.info.code == code::NORMAL || f.info.code == code::GOING_AWAY { Ok(None) } else { Err(Error::Closed(f.info.clone())) }
                }
                None => Err(Error::ChannelClosed(f.info.clone())),
            });
        }
        let ch = self.live(id, sig)?;
        if let Some(m) = ch.recv.pop_front() {
            let n = m.payload.len() as u64;
            if !ch.manual_credit {
                self.consumed(id, n, now);
            }
            return Some(Ok(Some(m)));
        }
        if ch.state == ChanState::Closing {
            let info = ch.close_info.clone();
            if ch.recv_close {
                return Some(match info {
                    Some(i) if i.code != code::NORMAL => Err(Error::ChannelClosed(i)),
                    _ => Ok(None),
                });
            }
            return Some(Err(Error::ChannelClosed(info.unwrap_or(CloseInfo { code: code::NORMAL, reason: String::new() }))));
        }
        None
    }

    pub(crate) fn return_credit(&mut self, id: u16, sig: &Arc<Signals>, n: u64, now: Instant) {
        if self.live(id, sig).is_some() {
            self.consumed(id, n, now);
        }
    }

    fn consumed(&mut self, id: u16, n: u64, now: Instant) {
        let total_allowed = self.opts.connection_window;
        let max_window = self.opts.max_channel_window;
        let total = self.total_window;
        let Some(ch) = self.channels.get_mut(&id) else { return };
        if ch.sent_close {
            return;
        }
        ch.unreturned += n;
        ch.window_consumed += n;

        // Window growth (core §6): a whole window consumed within two round trips means the sender
        // is window-limited.
        let mut grew = 0;
        let mut want_probe = false;
        if ch.window_consumed >= ch.window {
            let elapsed = now.saturating_duration_since(ch.window_started);
            match ch.stats.srtt {
                Some(srtt) => {
                    let measure = srtt.max(ch.stats.rtt.unwrap_or(srtt));
                    let grow = (ch.window * 2).min(max_window);
                    if elapsed < measure * 2 && grow > ch.window && total + (grow - ch.window) <= total_allowed {
                        grew = grow - ch.window;
                    }
                }
                None => want_probe = !ch.probing_for_growth,
            }
            ch.window_consumed = 0;
            ch.window_started = now;
        }
        ch.window += grew;

        let flush = ch.unreturned + grew >= ch.window / 2 || ch.recv.is_empty();
        if flush && ch.unreturned + grew > 0 {
            let inc = ch.unreturned + grew;
            ch.unreturned = 0;
            ch.recv_credit += inc;
            *self.grants.entry(id).or_insert(0) += inc;
        }
        self.total_window += grew;
        if want_probe {
            let ch = self.channels.get_mut(&id).expect("present");
            ch.probing_for_growth = true;
            ch.stats.probes_sent += 1;
            let token = self.new_token(now);
            self.pings.insert(token, PendingPing { channel: id, sig: None, sent: now, waiter: None });
            self.probes_out.push_back(Frame::new(id, PING, PROBE, Bytes::copy_from_slice(&token.to_be_bytes())));
        }
    }

    pub(crate) fn ping(&mut self, channel: Option<(u16, &Arc<Signals>)>, now: Instant) -> Result<oneshot::Receiver<Result<Duration>>> {
        if self.phase != Phase::Open {
            return Err(self.closed_error());
        }
        let ch_id = match channel {
            None => {
                self.stats.probes_sent += 1;
                0
            }
            Some((id, sig)) => {
                if let Some(e) = self.channel_error_if_closed(id, sig) {
                    return Err(e);
                }
                self.channels.get_mut(&id).expect("checked").stats.probes_sent += 1;
                id
            }
        };
        let token = self.new_token(now);
        let (tx, rx) = oneshot::channel();
        self.pings.insert(token, PendingPing { channel: ch_id, sig: None, sent: now, waiter: Some(tx) });
        self.probes_out.push_back(Frame::new(ch_id, PING, PROBE, Bytes::copy_from_slice(&token.to_be_bytes())));
        Ok(rx)
    }

    pub(crate) fn channel_stats(&mut self, id: u16, sig: &Arc<Signals>) -> ProbeStats {
        if let Some(f) = sig.finished.lock().unwrap().as_ref() {
            return f.stats;
        }
        self.live(id, sig).map_or(ProbeStats::default(), |c| c.stats)
    }

    pub(crate) fn channel_props(&mut self, id: u16, sig: &Arc<Signals>) -> Option<Properties> {
        self.live(id, sig).map(|c| c.props)
    }

    pub(crate) fn receive_window(&mut self, id: u16, sig: &Arc<Signals>) -> Option<u64> {
        self.live(id, sig).map(|c| c.window)
    }

    /// Start closing. The receiver resolves when the channel is fully closed.
    pub(crate) fn close_channel(&mut self, id: u16, sig: &Arc<Signals>, c: u16, reason: Option<&str>) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        if sig.finished.lock().unwrap().is_some() {
            let _ = tx.send(());
            return rx;
        }
        let Some(ch) = self.live(id, sig) else {
            let _ = tx.send(());
            return rx;
        };
        ch.close_waiters.push(tx);
        if ch.sent_close || ch.state == ChanState::Opening {
            return rx;
        }
        ch.state = ChanState::Closing;
        ch.close_info.get_or_insert(CloseInfo { code: c, reason: reason.unwrap_or("").to_owned() });
        ch.recv.clear();
        ch.reasm = None;
        ch.sig.recv.notify_waiters();
        self.abort_sends(id);
        self.send_close_channel(id, c, reason);
        self.maybe_finish(id);
        rx
    }

    pub(crate) fn take_accepted(&mut self) -> Option<Accepted> {
        self.accepted.pop_front()
    }

    pub(crate) fn is_ended(&self) -> bool {
        self.phase != Phase::Open && self.phase != Phase::Handshake
    }
}
