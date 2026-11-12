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
pub const QUIC_MULTISTREAM: &str = "quic-multistream/1";
const DATAGRAM_QUARANTINE: Duration = Duration::from_secs(2);
/// The shortest wait before a probe counts as lost: RFC 6298's minimum RTO.
const MIN_PROBE_WAIT: Duration = Duration::from_secs(1);
/// pingInterval and pingTimeout have no upper bound in the spec, so larger values are clamped to a
/// year, which is as good as never, rather than refused. That keeps every deadline built from them
/// far inside what `Instant` can represent.
const MAX_PING_SECS: u64 = 365 * 24 * 3600;

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
    /// Values above 2^31-1, the most credit a peer may hold (core §6), are clamped to it.
    pub max_channel_window: u64,
    /// No window grows past the point where all of them together would exceed this. It is a total,
    /// not one peer's credit, so the 2^31-1 bound doesn't apply.
    pub connection_window: u64,
    pub max_control_queue: usize,
    /// Most bytes handed to the transport at once. Smaller lets a high-priority channel overtake
    /// sooner; larger costs fewer system calls.
    pub write_batch: usize,
    /// Largest datagram the binding can send, where it has them. Set by the binding.
    pub max_datagram: Option<usize>,
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
            max_datagram: None,
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
    /// The path asked for under quic-multistream/1: `stream` or `datagram`.
    pub quic: Option<String>,
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
            quic: None,
        }
    }

    /// Latest value wins: unreliable and unordered, on QUIC datagrams where available. Elsewhere the
    /// channel still opens, on the base path: check [`crate::Channel::properties`].
    pub fn datagram(name: impl Into<String>) -> Self {
        ChannelSpec { reliable: false, ordered: false, max_retransmits: Some(0), quic: Some("datagram".into()), ..Self::reliable(name) }
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
        if let Some(q) = &self.quic {
            o["quic"] = json!(q);
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
    /// On QUIC datagrams, not the base path.
    datagram: bool,
    /// We opened it asking for QUIC datagrams: the one case where the answer may make it unreliable.
    asked_datagram: bool,
    /// What overtook the answer to our OPEN_CHANNEL (core §5.2).
    held: Vec<Frame>,
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
    sent: Instant,
    /// After this the probe counts as lost. None if the deadline can't be represented as an
    /// `Instant`: such a probe is then never expired, only answered or dropped with its channel.
    deadline: Option<Instant>,
    /// None for the probes this side sends itself: keepalive and window growth.
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
    /// Bytes in probes_out, which share the control budget with ctrl_out.
    probe_bytes: usize,
    grants: BTreeMap<u16, u64>,
    /// Channels with something to send, by priority then ID.
    sendable: BTreeSet<(u8, u16)>,
    /// Where each priority's round robin last stopped.
    cursor: HashMap<u8, u16>,
    pings: HashMap<u32, PendingPing>,
    /// A growth probe was sent outside `tick`, so the driver should call `tick` again for its deadline.
    timer_kick: bool,
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
    multistream: bool,
    dgram_out: VecDeque<Frame>,
    dgram_bytes: usize,
    /// IDs of closed datagram channels, and when they may be used again.
    quarantine: HashMap<u16, Instant>,
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

/// Close codes are 16-bit. A wider one is out of range (core §4.1), and casting it down could turn
/// it into another code, even 1000.
fn close_code(v: u64) -> std::result::Result<u16, Refusal> {
    u16::try_from(v).map_err(|_| Refusal::new(code::INVALID_MESSAGE, "code is out of range"))
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
        quic: opt_str(o, "quic")?,
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
    pub fn new(role: Role, mut opts: Options, policy: Option<Policy>, authorize: Option<Authorize>, now: Instant) -> Result<Core> {
        if !opts.limits.valid() {
            return Err(Error::Invalid("declared limits are out of bounds"));
        }
        // A larger window would let growth grant the peer more than the 2^31-1 credit it may hold
        // (core §6), which the peer must close with 4009.
        opts.max_channel_window = opts.max_channel_window.min(MAX_CREDIT);
        Ok(Core {
            role,
            phase: Phase::Handshake,
            ping_interval: opts.ping_interval.min(MAX_PING_SECS),
            ping_timeout: opts.ping_timeout.min(MAX_PING_SECS),
            opts,
            remote: Limits::default(),
            policy,
            authorize,
            channels: BTreeMap::new(),
            ctrl_out: VecDeque::new(),
            ctrl_bytes: 0,
            probes_out: VecDeque::new(),
            probe_bytes: 0,
            grants: BTreeMap::new(),
            sendable: BTreeSet::new(),
            cursor: HashMap::new(),
            pings: HashMap::new(),
            timer_kick: false,
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
            multistream: false,
            dgram_out: VecDeque::new(),
            dgram_bytes: 0,
            quarantine: HashMap::new(),
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

    /// How long to wait for the peer's CLOSE (core §9.1), and so for the transport to end after it.
    pub fn close_timeout(&self) -> Duration {
        self.opts.close_timeout
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

    fn queue_ctrl(&mut self, ty: u8, body: &Value, now: Instant) {
        if self.close_queued {
            return;
        }
        let payload = Bytes::from(serde_json::to_vec(body).expect("JSON encodes"));
        self.queue_ctrl_frame(Frame::new(0, ty, 0, payload), now);
    }

    /// Replies pile up if the peer doesn't read them (core §4.2).
    fn queue_ctrl_frame(&mut self, f: Frame, now: Instant) {
        let size = f.encoded_len();
        if self.over_control_budget(size) {
            self.fail(code::RATE_LIMITED, "too many unread control replies", now);
            return;
        }
        self.ctrl_bytes += size;
        self.ctrl_out.push_back(f);
    }

    fn over_control_budget(&self, size: usize) -> bool {
        self.opts.max_control_queue > 0 && self.ctrl_bytes + self.probe_bytes + size > self.opts.max_control_queue
    }

    /// A PONG is a reply too, so a peer that sends PINGs and never reads is closed, not queued for.
    fn queue_probe(&mut self, f: Frame, now: Instant) {
        let size = f.encoded_len();
        if self.over_control_budget(size) {
            self.fail(code::RATE_LIMITED, "too many unread probe replies", now);
            return;
        }
        self.probe_bytes += size;
        self.probes_out.push_back(f);
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
            self.probe_bytes -= f.encoded_len();
            return Some(f);
        }
        self.next_data_frame(completed)
    }

    fn take_grants(&mut self) -> Option<Frame> {
        if self.grants.is_empty() {
            return None;
        }
        let mut payload = BytesMut::new();
        let mut entries = 0;
        while entries < WINDOW_ENTRIES_PER_FRAME {
            let Some(mut e) = self.grants.first_entry() else { break };
            // An increment is at most 2^31-1, so one grant may need several entries. A frame holds at
            // most CONTROL_MAX/6 of them; what doesn't fit stays for the next frame.
            let id = *e.key();
            let left = e.get_mut();
            while *left > 0 && entries < WINDOW_ENTRIES_PER_FRAME {
                let inc = (*left).min(MAX_CREDIT);
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&(inc as u32).to_be_bytes());
                *left -= inc;
                entries += 1;
            }
            if *left == 0 {
                e.remove();
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
        // A reliable channel may be out of credit, in which case it waits for WINDOW_UPDATE. One that
        // can't fragment waits until the whole message fits (core §7); send() made sure it can.
        if reliable && !m.payload.is_empty() && (credit == 0 || (!can_fragment && credit < m.payload.len() as u64)) {
            return None;
        }
        let n = if can_fragment { m.payload.len().min(frag).min(usize::try_from(credit).unwrap_or(usize::MAX)) } else { m.payload.len() };
        let chunk = m.payload.split_to(n);
        m.sent_any = true;
        let more = !m.payload.is_empty();
        let f = Frame::new(id, m.ty, if more { MORE } else { 0 }, chunk);
        if reliable {
            // n <= credit by the checks above; saturate rather than wrap if that ever stops being true.
            debug_assert!(n as u64 <= ch.send_credit);
            ch.send_credit = ch.send_credit.saturating_sub(n as u64);
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
    pub(crate) fn start_client(&mut self, channels: &[ChannelSpec], now: Instant) -> Result<Vec<(u16, Arc<Signals>)>> {
        // Odd IDs below the reserved 0xFFFF: 1, 3, ..., 65533.
        if channels.len() > usize::from(RESERVED_CHANNEL / 2) {
            return Err(Error::Invalid("too many channels for HELLO"));
        }
        let ids = (1..RESERVED_CHANNEL).step_by(2);
        let reqs: Vec<Value> = channels.iter().zip(ids.clone()).map(|(spec, id)| spec.to_json(id)).collect();
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
        // core §3.1: HELLO MUST NOT exceed the 65536-byte channel-0 limit. Checked before any
        // channel exists, so a refusal leaves nothing half open.
        let payload = serde_json::to_vec(&hello).expect("JSON encodes");
        if payload.len() > CONTROL_MAX as usize {
            return Err(Error::Invalid("HELLO is larger than a control payload may be"));
        }
        let mut out = Vec::with_capacity(channels.len());
        for (spec, id) in channels.iter().zip(ids) {
            let sig = self.insert_channel(id, ChanState::Opening, now);
            self.channels.get_mut(&id).expect("present").asked_datagram = spec.quic.as_deref() == Some("datagram");
            out.push((id, sig));
        }
        self.queue_ctrl_frame(Frame::new(0, ctl::HELLO, 0, Bytes::from(payload)), now);
        Ok(out)
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
            Err(r) => self.fail(r.code, &r.reason, now),
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
        let accepted_ext: Vec<String> = extensions.into_iter().filter(|e| self.opts.extensions.contains(e)).collect();
        self.multistream = accepted_ext.iter().any(|e| e == QUIC_MULTISTREAM) && self.opts.max_datagram.is_some();

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
                    accepted.push(self.accept_path(id, &spec));
                    self.accepted.push_back(Accepted { id, spec, sig });
                }
                Err(r) => rejected.push(json!({ "id": id, "code": r.code, "reason": r.reason })),
            }
        }
        let l = self.opts.limits;
        let welcome = json!({
            "version": PROTOCOL_VERSION,
            "extensions": accepted_ext.iter().filter(|e| *e != QUIC_MULTISTREAM || self.multistream).collect::<Vec<_>>(),
            "maxFramePayload": l.max_frame_payload,
            "maxMessageSize": l.max_message_size,
            "initialWindow": l.initial_window,
            "pingInterval": self.opts.ping_interval,
            "pingTimeout": self.opts.ping_timeout,
            "channels": accepted,
            "rejected": rejected,
        });
        let welcome = self.fit_welcome(welcome);
        self.queue_ctrl(ctl::WELCOME, &welcome, now);
        self.ping_interval = self.opts.ping_interval.min(MAX_PING_SECS);
        self.ping_timeout = self.opts.ping_timeout.min(MAX_PING_SECS);
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

    /// WELCOME, like any channel-0 payload, MUST NOT exceed 65536 bytes (core §3.1), but an answer
    /// can be longer than the request it answers: a refusal with a reason, or a datagram placement.
    /// Following core §5.2, refusals lose their reasons first. If that is not enough, accepted
    /// channels are refused with 4002 and no reason, from the last, as if past the channel limit.
    fn fit_welcome(&mut self, mut welcome: Value) -> Value {
        let size = |v: &Value| serde_json::to_vec(v).expect("JSON encodes").len();
        let max = CONTROL_MAX as usize;
        let mut len = size(&welcome);
        if len <= max {
            return welcome;
        }
        for r in welcome["rejected"].as_array_mut().expect("built by handle_hello") {
            r.as_object_mut().expect("built by handle_hello").remove("reason");
        }
        len = size(&welcome);
        let mut refused = BTreeSet::new();
        while len > max {
            let Some(a) = welcome["channels"].as_array_mut().expect("built by handle_hello").pop() else { break };
            let id = a["id"].as_u64().and_then(|i| u16::try_from(i).ok()).expect("built by handle_hello");
            let r = json!({ "id": id, "code": code::CHANNEL_LIMIT });
            let rejected = welcome["rejected"].as_array_mut().expect("built by handle_hello");
            // A comma separates each entry from the one before it.
            len += size(&r) + usize::from(!rejected.is_empty());
            rejected.push(r);
            len -= size(&a) + usize::from(!welcome["channels"].as_array().expect("built by handle_hello").is_empty());
            refused.insert(id);
            if let Some(ch) = self.channels.remove(&id) {
                self.total_window -= ch.window;
            }
        }
        debug_assert_eq!(len, size(&welcome));
        self.accepted.retain(|a| !refused.contains(&a.id));
        welcome
    }

    fn on_welcome(&mut self, payload: &[u8], now: Instant) {
        if let Err(r) = self.handle_welcome(payload) {
            self.fail(r.code, &r.reason, now);
        }
    }

    fn handle_welcome(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let version = Self::parse_version(&o)?;
        if !Self::version_ok(&version) {
            return Err(Refusal::new(code::VERSION_MISMATCH, "unsupported version"));
        }
        self.remote = limits_from(&o)?;
        let extensions = match o.get("extensions") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a.iter().map(|v| v.as_str().ok_or_else(|| Refusal::new(code::INVALID_MESSAGE, "extensions must be strings"))).collect::<std::result::Result<Vec<_>, _>>()?,
            _ => return Err(Refusal::new(code::INVALID_MESSAGE, "extensions must be an array")),
        };
        // core §3.3: accepted extensions "MUST be a subset of the client's list". No action is
        // given, so the §4.1 catch-all applies: 1002.
        if extensions.iter().any(|e| !self.opts.extensions.iter().any(|ours| ours == e)) {
            return Err(Refusal::new(code::PROTOCOL_ERROR, "WELCOME accepts an extension that HELLO did not offer"));
        }
        self.multistream = extensions.contains(&QUIC_MULTISTREAM);
        if let Some(v) = opt_int(&o, "pingInterval")? {
            self.ping_interval = v.min(MAX_PING_SECS);
        }
        if let Some(v) = opt_int(&o, "pingTimeout")? {
            self.ping_timeout = v.min(MAX_PING_SECS);
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
                let props = Properties { reliable, ordered };
                let datagram = self.check_granted(id16, props, opt_str(co, "quic")?.as_deref())?;
                let ch = self.channels.get_mut(&id16).expect("present");
                ch.props = props;
                ch.datagram = datagram;
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
                let rcode = close_code(int_field(co, "code")?)?;
                let reason = opt_str(co, "reason")?.unwrap_or_default();
                let id16 = u16::try_from(id).ok().filter(|i| opening.contains(i) && !answered.contains(i));
                let Some(id16) = id16 else {
                    return Err(Refusal::new(code::PROTOCOL_ERROR, "WELCOME lists an ID that was not in HELLO"));
                };
                answered.insert(id16);
                self.rejected.push((id16, rcode, reason.clone()));
                if let Some(mut ch) = self.channels.remove(&id16) {
                    self.total_window -= ch.window;
                    if let Some(w) = ch.open_waiter.take() {
                        let _ = w.send(Err(Error::Refused(CloseInfo { code: rcode, reason })));
                    }
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

    /// Chooses a new channel's path, and returns the body of its CHANNEL_ACK or WELCOME entry.
    /// Dedicated streams aren't implemented: the draft lets a responder place those on the session
    /// stream instead, and say so.
    fn accept_path(&mut self, id: u16, spec: &ChannelSpec) -> Value {
        let multistream = self.multistream;
        let ch = self.channels.get_mut(&id).expect("just inserted");
        let datagram = multistream && spec.quic.as_deref() == Some("datagram") && !spec.reliable;
        if datagram {
            ch.datagram = true;
            ch.props = Properties { reliable: false, ordered: false };
            return json!({ "id": id, "reliable": false, "ordered": false, "maxRetransmits": 0, "quic": "datagram" });
        }
        let props = ch.props;
        let mut body = json!({ "id": id, "reliable": props.reliable, "ordered": props.ordered });
        if multistream && spec.quic.is_some() {
            body["quic"] = json!("session");
        }
        body
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
                datagram: false,
                asked_datagram: false,
                held: Vec::new(),
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
        self.on_frame_via(f, now, false);
    }

    /// One frame from a datagram. A datagram for channel 0, or before the handshake, is discarded.
    pub fn on_datagram(&mut self, f: Frame, now: Instant) {
        if f.channel == 0 {
            return;
        }
        if self.phase != Phase::Open {
            self.last_recv = now;
            return;
        }
        self.on_frame_via(f, now, true);
    }

    fn on_frame_via(&mut self, f: Frame, now: Instant, via_datagram: bool) {
        self.last_recv = now;
        self.keepalive_sent = None;
        if self.phase == Phase::Done {
            return;
        }
        // Step 3.
        if f.channel == RESERVED_CHANNEL || f.flags & !(MORE | PROBE) != 0 {
            self.fail(code::PROTOCOL_ERROR, "reserved channel or flag", now);
            return;
        }
        if f.channel == 0 && f.flags & MORE != 0 {
            self.fail(code::PROTOCOL_ERROR, "MORE on channel 0", now);
            return;
        }
        if f.flags & MORE != 0 && f.flags & PROBE != 0 {
            self.fail(code::PROTOCOL_ERROR, "MORE on a probe", now);
            return;
        }
        if self.phase == Phase::CloseSent {
            if f.channel == 0 && f.flags & PROBE == 0 && f.ty == ctl::CLOSE {
                self.on_close(&f.payload, now);
            }
            return;
        }
        if self.phase == Phase::Handshake {
            self.on_handshake_frame(f, now);
            return;
        }
        // A channel uses exactly one path (core §1.2).
        if let Some(ch) = self.channels.get_mut(&f.channel) {
            if via_datagram && ch.state == ChanState::Opening {
                if ch.held.len() < 64 {
                    ch.held.push(f);
                }
                return;
            }
            if ch.datagram != via_datagram {
                return;
            }
        } else if via_datagram {
            return;
        }
        if f.flags & PROBE != 0 {
            self.on_probe(f, now);
        } else if f.channel == 0 {
            self.on_control(f, now);
        } else {
            self.on_data(f, now);
        }
    }

    fn on_handshake_frame(&mut self, f: Frame, now: Instant) {
        let control = f.channel == 0 && f.flags & PROBE == 0;
        match self.role {
            Role::Server => {
                if control && f.ty == ctl::HELLO {
                    self.on_hello(&f.payload, now);
                } else if control && f.ty == ctl::CLOSE {
                    self.on_close(&f.payload, now);
                } else {
                    self.fail(code::PROTOCOL_ERROR, "the first frame must be HELLO", now);
                }
            }
            Role::Client => {
                if control && f.ty == ctl::WELCOME {
                    self.on_welcome(&f.payload, now);
                } else if control && f.ty == ctl::CLOSE {
                    self.on_close(&f.payload, now);
                } else {
                    self.fail(code::PROTOCOL_ERROR, "expected WELCOME", now);
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
            self.push_probe(Frame::new(f.channel, PONG, PROBE, f.payload), now);
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
        }
    }

    /// A probe travels on its channel's path.
    fn push_probe(&mut self, f: Frame, now: Instant) {
        if self.channels.get(&f.channel).is_some_and(|c| c.datagram) {
            self.push_datagram(f);
        } else {
            self.queue_probe(f, now);
        }
    }

    /// Unreliable data isn't flow-controlled, so its queue is bounded by dropping the oldest (core §4.2).
    fn push_datagram(&mut self, f: Frame) {
        self.dgram_bytes += f.encoded_len();
        self.dgram_out.push_back(f);
        while self.dgram_bytes > self.opts.max_control_queue {
            let Some(old) = self.dgram_out.pop_front() else { break };
            self.dgram_bytes -= old.encoded_len();
        }
    }

    /// The next frame to send as a datagram.
    pub fn next_datagram(&mut self) -> Option<Frame> {
        if self.phase != Phase::Open {
            return None;
        }
        let f = self.dgram_out.pop_front()?;
        self.dgram_bytes -= f.encoded_len();
        Some(f)
    }

    /// The path's limit can change as the network does.
    pub fn set_max_datagram(&mut self, max: Option<usize>) {
        self.opts.max_datagram = max;
    }

    fn on_control(&mut self, f: Frame, now: Instant) {
        let r = match f.ty {
            ctl::HELLO | ctl::WELCOME => Err(Refusal::new(code::PROTOCOL_ERROR, "a second HELLO or WELCOME")),
            ctl::OPEN_CHANNEL => self.on_open_channel(&f.payload, now),
            ctl::CHANNEL_ACK => self.on_channel_ack(&f.payload, now),
            ctl::CHANNEL_REJECT => self.on_channel_reject(&f.payload),
            ctl::CLOSE_CHANNEL => self.on_close_channel(&f.payload, now),
            ctl::WINDOW_UPDATE => self.on_window_update(&f.payload),
            ctl::CLOSE => {
                self.on_close(&f.payload, now);
                Ok(())
            }
            ctl::ERROR => self.on_error(&f.payload),
            other => {
                self.queue_ctrl(ctl::ERROR, &json!({ "code": code::UNSUPPORTED, "reason": format!("unknown control type {other:#04x}") }), now);
                Ok(())
            }
        };
        if let Err(r) = r {
            self.fail(r.code, &r.reason, now);
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
            self.queue_ctrl(ctl::CHANNEL_REJECT, &json!({ "id": id, "code": code::CHANNEL_LIMIT, "reason": "too many channels" }), now);
            return Ok(());
        }
        match self.decide(&spec) {
            Ok(()) => {
                let sig = self.insert_channel(id, ChanState::Open, now);
                let ack = self.accept_path(id, &spec);
                self.queue_ctrl(ctl::CHANNEL_ACK, &ack, now);
                self.accepted.push_back(Accepted { id, spec, sig });
                self.wake_accept.notify_waiters();
            }
            Err(r) => {
                self.queue_ctrl(ctl::CHANNEL_REJECT, &json!({ "id": id, "code": r.code, "reason": r.reason }), now);
            }
        }
        Ok(())
    }

    fn opening_channel(&self, id: u64) -> std::result::Result<u16, Refusal> {
        let id16 = u16::try_from(id).ok().filter(|i| matches!(self.channels.get(i), Some(c) if c.state == ChanState::Opening));
        id16.ok_or_else(|| Refusal::new(code::PROTOCOL_ERROR, "answer for a channel that is not opening"))
    }

    fn on_channel_ack(&mut self, payload: &[u8], now: Instant) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let id = self.opening_channel(int_field(&o, "id")?)?;
        let props = Properties { reliable: bool_field(&o, "reliable")?, ordered: bool_field(&o, "ordered")? };
        let init = u64::from(self.remote.initial_window);
        let datagram = self.check_granted(id, props, opt_str(&o, "quic")?.as_deref())?;
        let ch = self.channels.get_mut(&id).expect("present");
        ch.props = props;
        ch.datagram = datagram;
        ch.state = ChanState::Open;
        ch.send_credit = init;
        if let Some(w) = ch.open_waiter.take() {
            let _ = w.send(Ok(props));
        }
        // Frames that overtook this answer can be processed now. Only datagrams are ever held, so they
        // replay as datagrams: if the answer put the channel on a stream, they are discarded (core §1.2).
        for f in std::mem::take(&mut ch.held) {
            self.on_frame_via(f, now, true);
        }
        Ok(())
    }

    /// Checks the effective properties in a CHANNEL_ACK or WELCOME entry for a channel we opened, and
    /// returns whether it is on QUIC datagrams. They must be those of the path the answer names (core
    /// §5.3). Every path here other than datagrams is a reliable, ordered stream (core §1.2, quic
    /// binding §3, quic-multistream §2 table), so any other answer would switch off flow control or
    /// fragmentation rules without a path to justify it. The responder may move a channel to the
    /// session stream (quic-multistream §2), which makes an unreliable request reliable, but may place
    /// one on datagrams only if that was requested and the extension is in use.
    fn check_granted(&self, id: u16, props: Properties, quic: Option<&str>) -> std::result::Result<bool, Refusal> {
        let datagram = quic == Some("datagram");
        let expect = if datagram {
            if !self.multistream || !self.channels.get(&id).is_some_and(|c| c.asked_datagram) {
                return Err(Refusal::new(code::PROTOCOL_ERROR, "channel placed on datagrams without being asked"));
            }
            Properties { reliable: false, ordered: false }
        } else {
            Properties { reliable: true, ordered: true }
        };
        if props != expect {
            return Err(Refusal::new(code::PROTOCOL_ERROR, "effective properties do not match the channel's path"));
        }
        Ok(datagram)
    }

    fn on_channel_reject(&mut self, payload: &[u8]) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let id = self.opening_channel(int_field(&o, "id")?)?;
        let rcode = close_code(int_field(&o, "code")?)?;
        let reason = opt_str(&o, "reason")?.unwrap_or_default();
        let mut ch = self.channels.remove(&id).expect("present");
        self.total_window -= ch.window;
        if let Some(w) = ch.open_waiter.take() {
            let _ = w.send(Err(Error::Refused(CloseInfo { code: rcode, reason })));
        }
        Ok(())
    }

    fn on_close_channel(&mut self, payload: &[u8], now: Instant) -> std::result::Result<(), Refusal> {
        let o = parse_object(payload)?;
        let id = int_field(&o, "id")?;
        let c = close_code(opt_int(&o, "code")?.unwrap_or(u64::from(code::NORMAL)))?;
        let reason = opt_str(&o, "reason")?.unwrap_or_default();
        if id == 0 {
            self.queue_ctrl(ctl::ERROR, &json!({ "code": code::PROTOCOL_ERROR, "reason": "channel 0 closes only with the connection" }), now);
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
        ch.close_info.get_or_insert(CloseInfo { code: c, reason });
        self.abort_sends(id);
        let ch = self.channels.get_mut(&id).expect("present");
        ch.sig.recv.notify_waiters();
        ch.sig.credit.notify_waiters();
        if !ch.sent_close {
            self.send_close_channel(id, c, None, now);
        }
        self.maybe_finish(id, now);
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

    fn on_data(&mut self, f: Frame, now: Instant) {
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
                self.fail(code::FLOW_CONTROL_ERROR, "peer exceeded its credit", now);
                return;
            }
            ch.recv_credit -= len;
        }
        let can_fragment = ch.props.reliable && ch.props.ordered;
        let more = f.flags & MORE != 0;
        let id = f.channel;
        if more && !can_fragment {
            self.close_channel_with(id, code::PROTOCOL_ERROR, "MORE on a channel that can't fragment", now);
            return;
        }
        if let Some((ty, _)) = ch.reasm.as_ref()
            && *ty != f.ty {
                self.close_channel_with(id, code::PROTOCOL_ERROR, "type changed within a message", now);
                return;
            }
        let so_far = ch.reasm.as_ref().map_or(0, |(_, b)| b.len());
        if so_far + f.payload.len() > max_message {
            self.close_channel_with(id, code::MESSAGE_TOO_LARGE, "message exceeds maxMessageSize", now);
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

    fn on_close(&mut self, payload: &[u8], now: Instant) {
        // CLOSE is `{code, reason?}` (core §9.1). A missing or mistyped field is 4001 (core §4.1),
        // as is a code out of range; either way the connection still ends.
        let parsed = parse_object(payload).and_then(|o| Ok((close_code(int_field(&o, "code")?)?, opt_str(&o, "reason")?.unwrap_or_default())));
        let (c, reason) = match parsed {
            Ok(v) => v,
            Err(r) => (r.code, format!("malformed CLOSE: {}", r.reason)),
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
                // Never written after CLOSE, and they would count against the budget the reply needs.
                self.probes_out.clear();
                self.probe_bytes = 0;
                self.queue_ctrl(ctl::CLOSE, &json!({ "code": c }), now);
                self.close_queued = true;
                self.peer_closed = true;
                // As in fail: a peer that sent CLOSE and stopped reading can't hold the connection open.
                self.close_sent_at.get_or_insert(now);
                self.end_channels();
            }
        }
    }

    // --- Closing ---

    /// A protocol failure, or the local application closing: send CLOSE.
    pub fn fail(&mut self, c: u16, reason: &str, now: Instant) {
        if self.close_queued || self.phase == Phase::Done {
            return;
        }
        self.close_info.get_or_insert(CloseInfo { code: c, reason: reason.to_owned() });
        self.ctrl_out.clear();
        self.ctrl_bytes = 0;
        self.grants.clear();
        self.probes_out.clear();
        self.probe_bytes = 0;
        let body = if reason.is_empty() { json!({ "code": c }) } else { json!({ "code": c, "reason": reason }) };
        self.queue_ctrl(ctl::CLOSE, &body, now);
        self.close_queued = true;
        self.phase = Phase::CloseSent;
        // The wait for the peer's CLOSE starts now, not once ours is written: if the peer has
        // stopped reading, the write never finishes, and only this timeout ends the connection.
        self.close_sent_at.get_or_insert(now);
        self.end_channels();
    }

    pub fn close(&mut self, c: u16, reason: &str, now: Instant) {
        self.fail(c, reason, now);
    }

    /// CLOSE went out. If it was the reply to the peer's, the exchange is over.
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

    fn send_close_channel(&mut self, id: u16, c: u16, reason: Option<&str>, now: Instant) {
        self.grants.remove(&id);
        let mut body = json!({ "id": id, "code": c });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        self.queue_ctrl(ctl::CLOSE_CHANNEL, &body, now);
        if let Some(ch) = self.channels.get_mut(&id) {
            ch.sent_close = true;
            // A closing channel discards received probes (core §8.1), so no PONG can answer its
            // pings now: end them rather than leave them to time out.
            let info = ch.close_info.clone().unwrap_or(CloseInfo { code: c, reason: reason.unwrap_or("").to_owned() });
            self.end_pings(id, &info);
        }
    }

    /// Ends a channel's pending pings, failing their waiters with `ChannelClosed`.
    fn end_pings(&mut self, id: u16, info: &CloseInfo) {
        self.pings.retain(|_, p| {
            if p.channel != id {
                return true;
            }
            if let Some(w) = p.waiter.take() {
                let _ = w.send(Err(Error::ChannelClosed(info.clone())));
            }
            false
        });
    }

    /// A channel-level error: core §7.
    fn close_channel_with(&mut self, id: u16, c: u16, reason: &str, now: Instant) {
        let Some(ch) = self.channels.get_mut(&id) else { return };
        ch.state = ChanState::Closing;
        ch.reasm = None;
        ch.close_info.get_or_insert(CloseInfo { code: c, reason: reason.to_owned() });
        ch.sig.recv.notify_waiters();
        ch.sig.credit.notify_waiters();
        self.abort_sends(id);
        self.send_close_channel(id, c, Some(reason), now);
    }

    fn maybe_finish(&mut self, id: u16, now: Instant) {
        let done = matches!(self.channels.get(&id), Some(c) if c.sent_close && c.recv_close);
        if !done {
            return;
        }
        let mut ch = self.channels.remove(&id).expect("present");
        self.total_window -= ch.window;
        if ch.datagram {
            // A delayed datagram carries nothing but the ID, so it could reach a later channel.
            self.quarantine.insert(id, now + DATAGRAM_QUARANTINE);
        }
        let info = ch.close_info.clone().unwrap_or(CloseInfo { code: code::NORMAL, reason: String::new() });
        // Its PONGs can no longer arrive, and the ID may be reused.
        self.end_pings(id, &info);
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
                        Role::Server => self.fail(code::HELLO_TIMEOUT, "no HELLO within the timeout", now),
                        Role::Client => self.fail(code::GOING_AWAY, "no WELCOME within the timeout", now),
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
        let next_ping = self.expire_pings(now);
        let wait = self.keepalive(now);
        match next_ping {
            Some(d) if self.phase == Phase::Open => wait.min(d.saturating_duration_since(now)),
            _ => wait,
        }
    }

    fn keepalive(&mut self, now: Instant) -> Duration {
        if self.ping_interval == 0 {
            return Duration::from_secs(3600);
        }
        let idle = Duration::from_secs(self.ping_interval);
        let timeout = Duration::from_secs(self.ping_timeout);
        if let Some(sent) = self.keepalive_sent {
            if now.saturating_duration_since(sent) >= timeout {
                self.close_info.get_or_insert(CloseInfo { code: code::KEEPALIVE_TIMEOUT, reason: "peer stopped responding".into() });
                self.fail(code::KEEPALIVE_TIMEOUT, "peer stopped responding", now);
                return Duration::from_millis(50);
            }
            return timeout - now.saturating_duration_since(sent);
        }
        let quiet = now.saturating_duration_since(self.last_recv);
        if quiet >= idle {
            self.keepalive_sent = Some(now);
            // Registered like any ping, so its PONG is an RTT sample.
            self.send_ping(0, now, None);
            self.stats.probes_sent += 1;
            return timeout;
        }
        idle - quiet
    }

    /// How long to wait for a PONG: at least `pingTimeout`, which bounds a keepalive PONG and so any
    /// PONG on a live connection, but no less than an RFC 6298 retransmission timeout (srtt + 4 *
    /// rttvar) for the probe's path, so a path slower than the timeout isn't counted as losing every
    /// probe. Never under a second, so `pingTimeout: 0` doesn't expire probes at once.
    fn ping_wait(&self, channel: u16) -> Duration {
        let stats = self.channels.get(&channel).map(|c| c.stats).filter(|s| s.srtt.is_some()).unwrap_or(self.stats);
        let rto = match (stats.srtt, stats.rttvar) {
            (Some(s), Some(v)) => s.saturating_add(v.saturating_mul(4)),
            _ => Duration::ZERO,
        };
        Duration::from_secs(self.ping_timeout).max(rto).max(MIN_PROBE_WAIT)
    }

    /// Queues a PING on its channel's path and records it. A PING that would overrun the control
    /// budget closes the connection instead (core §4.2), and then nothing is left pending for it.
    fn send_ping(&mut self, channel: u16, now: Instant, waiter: Option<oneshot::Sender<Result<Duration>>>) {
        let token = self.new_token(now);
        let deadline = now.checked_add(self.ping_wait(channel));
        self.push_probe(Frame::new(channel, PING, PROBE, Bytes::copy_from_slice(&token.to_be_bytes())), now);
        if self.close_queued || self.phase != Phase::Open {
            if let Some(w) = waiter {
                let _ = w.send(Err(self.closed_error()));
            }
            return;
        }
        self.pings.insert(token, PendingPing { channel, sent: now, deadline, waiter });
    }

    /// Ends pings past their deadline, as lost. Returns the next deadline.
    fn expire_pings(&mut self, now: Instant) -> Option<Instant> {
        let expired: Vec<u32> = self.pings.iter().filter(|(_, p)| p.deadline.is_some_and(|d| d <= now)).map(|(t, _)| *t).collect();
        for t in expired {
            let mut p = self.pings.remove(&t).expect("present");
            if p.channel == 0 {
                self.stats.probes_lost += 1;
            } else if let Some(ch) = self.channels.get_mut(&p.channel) {
                ch.stats.probes_lost += 1;
                if p.waiter.is_none() {
                    // A lost growth probe: let the next full window probe again.
                    ch.probing_for_growth = false;
                }
            }
            if let Some(w) = p.waiter.take() {
                let _ = w.send(Err(Error::Timeout));
            }
        }
        self.pings.values().filter_map(|p| p.deadline).min()
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
        self.quarantine.retain(|_, until| *until > now);
        let id = (start..u32::from(RESERVED_CHANNEL))
            .step_by(2)
            .map(|i| i as u16)
            .find(|i| !self.channels.contains_key(i) && !self.quarantine.contains_key(i))
            .ok_or(Error::Invalid("no free channel IDs"))?;
        let body = spec.to_json(id);
        let sig = self.insert_channel(id, ChanState::Opening, now);
        let (tx, rx) = oneshot::channel();
        let ch = self.channels.get_mut(&id).expect("present");
        ch.open_waiter = Some(tx);
        ch.asked_datagram = spec.quic.as_deref() == Some("datagram");
        self.queue_ctrl(ctl::OPEN_CHANNEL, &body, now);
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
        let max_datagram = self.opts.max_datagram;
        let ch = self.channels.get_mut(&id).expect("checked");
        if !(ch.props.reliable && ch.props.ordered) && payload.len() > frame_limit {
            return Err(Error::TooLarge { size: payload.len(), limit: frame_limit });
        }
        // A reliable message that can't fragment needs that much credit at once, and a channel never
        // has more than the peer's initial window outstanding. Limits::valid() implies this, but
        // frame_from would wait forever if it didn't hold.
        let window = self.remote.initial_window as usize;
        if ch.props.reliable && !ch.props.ordered && payload.len() > window {
            return Err(Error::TooLarge { size: payload.len(), limit: window });
        }
        let (tx, rx) = oneshot::channel();
        if ch.datagram {
            let limit = max_datagram.unwrap_or(0).saturating_sub(crate::frame::HEADER_LEN).min(frame_limit);
            if payload.len() > limit {
                return Err(Error::TooLarge { size: payload.len(), limit });
            }
            self.push_datagram(Frame::new(id, ty, 0, payload));
            let _ = tx.send(Ok(()));
            return Ok(rx);
        }
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
        let ch = &self.channels[&id];
        if !ch.props.reliable {
            return Ok(u64::MAX); // Not flow-controlled.
        }
        let queued: u64 = ch.outq.iter().map(|m| m.payload.len() as u64).sum();
        Ok(ch.send_credit.saturating_sub(queued))
    }

    /// The largest message that goes out as a single frame.
    pub(crate) fn max_unfragmented(&self) -> u32 {
        self.opts.fragment_size.max(1).min(self.remote.max_frame_payload)
    }

    /// The largest payload this channel can send at all, in one frame, on a datagram path.
    pub(crate) fn max_datagram_payload(&mut self, id: u16, sig: &Arc<Signals>) -> Option<usize> {
        let limit = self.remote.max_frame_payload as usize;
        let max = self.opts.max_datagram;
        let ch = self.live(id, sig)?;
        if !ch.datagram {
            return None;
        }
        Some(max.unwrap_or(0).saturating_sub(crate::frame::HEADER_LEN).min(limit))
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
        if ch.sent_close || !ch.props.reliable {
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
                    if elapsed < measure.saturating_mul(2) && grow > ch.window && total + (grow - ch.window) <= total_allowed {
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
            self.send_ping(id, now, None);
            self.timer_kick = true;
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
        let (tx, rx) = oneshot::channel();
        self.send_ping(ch_id, now, Some(tx));
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
    pub(crate) fn close_channel(&mut self, id: u16, sig: &Arc<Signals>, c: u16, reason: Option<&str>, now: Instant) -> oneshot::Receiver<()> {
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
        self.send_close_channel(id, c, reason, now);
        self.maybe_finish(id, now);
        rx
    }

    /// Whether a deadline was set since the last call, so the timer must run `tick` again.
    pub(crate) fn take_timer_kick(&mut self) -> bool {
        std::mem::take(&mut self.timer_kick)
    }

    pub(crate) fn take_accepted(&mut self) -> Option<Accepted> {
        self.accepted.pop_front()
    }

    pub(crate) fn is_ended(&self) -> bool {
        self.phase != Phase::Open && self.phase != Phase::Handshake
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    fn server(datagrams: bool) -> Core {
        let policy: Policy = Arc::new(|_| Ok(()));
        let opts = Options { extensions: vec![QUIC_MULTISTREAM.into()], max_datagram: datagrams.then_some(1200), ..Options::default() };
        Core::new(Role::Server, opts, Some(policy), None, Instant::now()).unwrap()
    }

    fn drain(c: &mut Core) -> Vec<Frame> {
        let (mut out, mut done) = (Vec::new(), Vec::new());
        while let Some(f) = c.next_frame(&mut done) {
            out.push(f);
        }
        out
    }

    fn hello(c: &mut Core, ext: &str) -> Value {
        let body = json!({ "version": PROTOCOL_VERSION, "extensions": [ext] });
        c.on_frame(Frame::new(0, ctl::HELLO, 0, serde_json::to_vec(&body).unwrap()), Instant::now());
        serde_json::from_slice(&drain(c)[0].payload).unwrap()
    }

    fn open(c: &mut Core, id: u16, quic: &str) -> Value {
        let body = json!({ "id": id, "name": "x", "reliable": false, "ordered": false, "quic": quic });
        c.on_frame(Frame::new(0, ctl::OPEN_CHANNEL, 0, serde_json::to_vec(&body).unwrap()), Instant::now());
        serde_json::from_slice(&drain(c)[0].payload).unwrap()
    }

    fn close_code(frames: &[Frame]) -> Option<u64> {
        frames.iter().find(|f| f.channel == 0 && f.ty == ctl::CLOSE).map(|f| serde_json::from_slice::<Value>(&f.payload).unwrap()["code"].as_u64().unwrap())
    }

    #[test]
    fn the_extension_needs_datagrams_and_both_sides() {
        let mut c = server(true);
        assert_eq!(hello(&mut c, QUIC_MULTISTREAM)["extensions"], json!([QUIC_MULTISTREAM]));
        let mut c = server(false);
        assert_eq!(hello(&mut c, QUIC_MULTISTREAM)["extensions"], json!([]));
        let mut c = server(true);
        assert_eq!(hello(&mut c, "something/1")["extensions"], json!([]));
    }

    #[test]
    fn without_the_extension_a_datagram_request_stays_reliable_on_the_base_path() {
        let mut c = server(true);
        hello(&mut c, "something/1");
        let ack = open(&mut c, 1, "datagram");
        assert_eq!((&ack["reliable"], &ack["ordered"]), (&json!(true), &json!(true)));
        assert!(ack.get("quic").is_none());
    }

    #[test]
    fn a_frame_on_the_wrong_path_is_discarded() {
        let mut c = server(true);
        hello(&mut c, QUIC_MULTISTREAM);
        assert_eq!(open(&mut c, 1, "datagram")["quic"], "datagram");
        let body = json!({ "id": 3, "name": "y", "reliable": true, "ordered": true });
        c.on_frame(Frame::new(0, ctl::OPEN_CHANNEL, 0, serde_json::to_vec(&body).unwrap()), Instant::now());
        drain(&mut c);

        c.on_frame(Frame::new(1, 7, 0, b"wrong path".to_vec()), Instant::now()); // Datagram channel, on the stream.
        c.on_datagram(Frame::new(3, 7, 0, b"wrong path".to_vec()), Instant::now()); // Stream channel, by datagram.
        c.on_datagram(Frame::new(0, ctl::CLOSE, 0, br#"{"code":1000}"#.to_vec()), Instant::now()); // Channel 0, by datagram.
        assert!(c.is_open());
        assert!(c.channels[&1].recv.is_empty());
        assert!(c.channels[&3].recv.is_empty());

        c.on_datagram(Frame::new(1, 7, 0, b"right".to_vec()), Instant::now());
        assert_eq!(c.channels[&1].recv.len(), 1);
    }

    #[test]
    fn a_window_update_for_a_datagram_channel_closes_with_1002() {
        let mut c = server(true);
        hello(&mut c, QUIC_MULTISTREAM);
        open(&mut c, 1, "datagram");
        c.on_frame(Frame::new(0, ctl::WINDOW_UPDATE, 0, vec![0, 1, 0, 0, 16, 0]), Instant::now());
        assert_eq!(close_code(&drain(&mut c)), Some(1002));
    }

    #[test]
    fn taking_a_datagram_message_returns_no_credit() {
        let mut c = server(true);
        hello(&mut c, QUIC_MULTISTREAM);
        open(&mut c, 1, "datagram");
        c.on_datagram(Frame::new(1, 7, 0, vec![0u8; 500]), Instant::now());
        let sig = c.channels[&1].sig.clone();
        assert!(matches!(c.receive(1, &sig, Instant::now()), Some(Ok(Some(_)))));
        assert!(c.grants.is_empty());
        assert!(drain(&mut c).is_empty());
    }

    #[test]
    fn a_datagram_that_overtakes_the_ack_is_held_then_delivered() {
        let policy: Policy = Arc::new(|_| Ok(()));
        let opts = Options { max_datagram: Some(1200), extensions: vec![QUIC_MULTISTREAM.into()], ..Options::default() };
        let now = Instant::now();
        let mut c = Core::new(Role::Client, opts, Some(policy), None, now).unwrap();
        c.start_client(&[], now).unwrap();
        drain(&mut c);
        let welcome = json!({ "version": PROTOCOL_VERSION, "extensions": [QUIC_MULTISTREAM] });
        c.on_frame(Frame::new(0, ctl::WELCOME, 0, serde_json::to_vec(&welcome).unwrap()), now);
        let (id, _sig, _rx) = c.open_channel(ChannelSpec::datagram("v"), now).unwrap();
        drain(&mut c);

        c.on_datagram(Frame::new(id, 7, 0, b"early".to_vec()), now);
        assert!(c.channels[&id].recv.is_empty(), "held until the answer");

        let ack = json!({ "id": id, "reliable": false, "ordered": false, "quic": "datagram" });
        c.on_frame(Frame::new(0, ctl::CHANNEL_ACK, 0, serde_json::to_vec(&ack).unwrap()), now);
        assert_eq!(c.channels[&id].recv.len(), 1);
    }

    #[test]
    fn unsent_datagrams_drop_the_oldest_rather_than_grow() {
        let mut c = server(true);
        hello(&mut c, QUIC_MULTISTREAM);
        open(&mut c, 1, "datagram");
        let sig = c.channels[&1].sig.clone();
        for i in 0..3000u32 {
            c.send(1, &sig, 1, Bytes::from(vec![(i % 251) as u8; 1000])).unwrap();
        }
        assert!(c.dgram_bytes <= c.opts.max_control_queue);
        assert_eq!(c.next_datagram().unwrap().payload[0], (((3000 - c.dgram_out.len() - 1) as u32) % 251) as u8, "the oldest kept");
    }
}

#[cfg(test)]
mod flow_tests {
    use super::*;

    fn drain(c: &mut Core) -> Vec<Frame> {
        let (mut out, mut done) = (Vec::new(), Vec::new());
        while let Some(f) = c.next_frame(&mut done) {
            out.push(f);
        }
        out
    }

    fn ctl_frame(ty: u8, v: Value) -> Frame {
        Frame::new(0, ty, 0, serde_json::to_vec(&v).unwrap())
    }

    fn close_code(frames: &[Frame]) -> Option<u64> {
        frames.iter().find(|f| f.channel == 0 && f.ty == ctl::CLOSE).map(|f| serde_json::from_slice::<Value>(&f.payload).unwrap()["code"].as_u64().unwrap())
    }

    fn client(opts: Options, specs: &[ChannelSpec]) -> Core {
        let now = Instant::now();
        let mut c = Core::new(Role::Client, opts, None, None, now).unwrap();
        c.start_client(specs, now).unwrap();
        drain(&mut c);
        c
    }

    fn welcomed(opts: Options, ext: &[&str]) -> Core {
        let mut c = client(opts, &[]);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "extensions": ext })), Instant::now());
        assert!(c.is_open());
        c
    }

    fn multistream() -> Options {
        Options { max_datagram: Some(1200), extensions: vec![QUIC_MULTISTREAM.into()], ..Options::default() }
    }

    /// Opens a channel and answers it with `ack` (the id is filled in). Returns what the core wrote.
    fn open_and_ack(c: &mut Core, spec: ChannelSpec, mut ack: Value) -> (u16, Arc<Signals>, Vec<Frame>) {
        let (id, sig, _rx) = c.open_channel(spec, Instant::now()).unwrap();
        drain(c);
        ack["id"] = json!(id);
        c.on_frame(ctl_frame(ctl::CHANNEL_ACK, ack), Instant::now());
        (id, sig, drain(c))
    }

    fn reliable_unordered(c: &mut Core) -> (u16, Arc<Signals>) {
        let (id, sig, _) = open_and_ack(c, ChannelSpec::reliable("x"), json!({ "reliable": true, "ordered": true }));
        // No path implemented here is reliable but unordered (see check_granted), so set it directly.
        c.channels.get_mut(&id).unwrap().props = Properties { reliable: true, ordered: false };
        (id, sig)
    }

    // C2: a reliable channel that can't fragment waits for credit for the whole message.
    #[test]
    fn a_reliable_unfragmentable_message_waits_for_enough_credit() {
        let mut c = welcomed(Options::default(), &[]);
        let (id, sig) = reliable_unordered(&mut c);
        let mut left = c.channels[&id].send_credit;
        while left > 1000 + 65536 {
            c.send(id, &sig, 1, Bytes::from(vec![0u8; 65536])).unwrap();
            left -= 65536;
        }
        c.send(id, &sig, 1, Bytes::from(vec![0u8; (left - 1000) as usize])).unwrap();
        drain(&mut c);
        assert_eq!(c.channels[&id].send_credit, 1000);

        c.send(id, &sig, 1, Bytes::from(vec![0u8; 4000])).unwrap();
        assert!(drain(&mut c).is_empty(), "1000 bytes of credit is not enough for 4000");
        assert_eq!(c.channels[&id].send_credit, 1000);

        let mut wu = id.to_be_bytes().to_vec();
        wu.extend_from_slice(&2999u32.to_be_bytes());
        c.on_frame(Frame::new(0, ctl::WINDOW_UPDATE, 0, wu.clone()), Instant::now());
        assert!(drain(&mut c).is_empty(), "3999 is still not enough");
        wu[2..].copy_from_slice(&1u32.to_be_bytes());
        c.on_frame(Frame::new(0, ctl::WINDOW_UPDATE, 0, wu), Instant::now());
        let out = drain(&mut c);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].payload.len(), out[0].flags), (4000, 0));
        assert_eq!(c.channels[&id].send_credit, 0);
    }

    #[test]
    fn an_unfragmentable_message_larger_than_the_initial_window_is_refused() {
        let mut c = welcomed(Options::default(), &[]);
        let (id, sig) = reliable_unordered(&mut c);
        // Limits::valid() rules this out for a real peer; set it directly to check the guard.
        c.remote.initial_window = 4096;
        assert!(matches!(c.send(id, &sig, 1, Bytes::from(vec![0u8; 5000])), Err(Error::TooLarge { limit: 4096, .. })));
    }

    // H4: the answer may not report properties the channel's path doesn't have.
    #[test]
    fn an_ack_that_drops_ordering_closes_with_1002() {
        let mut c = welcomed(Options::default(), &[]);
        let (_, _, out) = open_and_ack(&mut c, ChannelSpec::reliable("x"), json!({ "reliable": true, "ordered": false }));
        assert_eq!(close_code(&out), Some(1002));
    }

    #[test]
    fn an_ack_that_drops_reliability_closes_with_1002() {
        let mut c = welcomed(Options::default(), &[]);
        let (_, _, out) = open_and_ack(&mut c, ChannelSpec::reliable("x"), json!({ "reliable": false, "ordered": false }));
        assert_eq!(close_code(&out), Some(1002));
    }

    #[test]
    fn an_unreliable_answer_on_the_base_path_closes_with_1002_even_if_requested() {
        let mut c = welcomed(Options::default(), &[]);
        let spec = ChannelSpec { reliable: false, ordered: false, ..ChannelSpec::reliable("x") };
        let (_, _, out) = open_and_ack(&mut c, spec, json!({ "reliable": false, "ordered": false }));
        assert_eq!(close_code(&out), Some(1002));
    }

    #[test]
    fn an_unreliable_request_may_be_answered_reliable_on_the_base_path() {
        let mut c = welcomed(Options::default(), &[]);
        let (id, sig, out) = open_and_ack(&mut c, ChannelSpec::datagram("x"), json!({ "reliable": true, "ordered": true }));
        assert!(out.is_empty());
        assert_eq!(c.channel_props(id, &sig), Some(Properties { reliable: true, ordered: true }));
    }

    #[test]
    fn a_datagram_placement_that_was_not_requested_closes_with_1002() {
        let mut c = welcomed(multistream(), &[QUIC_MULTISTREAM]);
        let (_, _, out) = open_and_ack(&mut c, ChannelSpec::reliable("x"), json!({ "reliable": false, "ordered": false, "quic": "datagram" }));
        assert_eq!(close_code(&out), Some(1002));
    }

    #[test]
    fn a_datagram_placement_without_the_extension_closes_with_1002() {
        let mut c = welcomed(multistream(), &[]);
        let (_, _, out) = open_and_ack(&mut c, ChannelSpec::datagram("x"), json!({ "reliable": false, "ordered": false, "quic": "datagram" }));
        assert_eq!(close_code(&out), Some(1002));
    }

    #[test]
    fn a_datagram_placement_must_report_the_datagram_properties() {
        let mut c = welcomed(multistream(), &[QUIC_MULTISTREAM]);
        let (_, _, out) = open_and_ack(&mut c, ChannelSpec::datagram("x"), json!({ "reliable": true, "ordered": false, "quic": "datagram" }));
        assert_eq!(close_code(&out), Some(1002));
    }

    #[test]
    fn a_requested_datagram_placement_is_accepted() {
        let mut c = welcomed(multistream(), &[QUIC_MULTISTREAM]);
        let (id, sig, out) = open_and_ack(&mut c, ChannelSpec::datagram("x"), json!({ "reliable": false, "ordered": false, "quic": "datagram" }));
        assert!(out.is_empty());
        assert_eq!(c.channel_props(id, &sig), Some(Properties { reliable: false, ordered: false }));
        assert!(c.channels[&id].datagram);
    }

    #[test]
    fn a_welcome_entry_that_drops_reliability_closes_with_1002() {
        let mut c = client(Options::default(), &[ChannelSpec::reliable("a")]);
        let welcome = json!({ "version": PROTOCOL_VERSION, "channels": [{ "id": 1, "reliable": false, "ordered": true }] });
        c.on_frame(ctl_frame(ctl::WELCOME, welcome), Instant::now());
        assert_eq!(close_code(&drain(&mut c)), Some(1002));
    }

    #[test]
    fn a_welcome_entry_on_the_base_path_is_accepted() {
        let mut c = client(Options::default(), &[ChannelSpec::reliable("a")]);
        let welcome = json!({ "version": PROTOCOL_VERSION, "channels": [{ "id": 1, "reliable": true, "ordered": true }] });
        c.on_frame(ctl_frame(ctl::WELCOME, welcome), Instant::now());
        assert!(c.is_open());
        assert!(drain(&mut c).is_empty());
    }

    // H1: PONGs count against the control budget.
    fn server(max_control_queue: usize) -> Core {
        let opts = Options { max_control_queue, ..Options::default() };
        let mut c = Core::new(Role::Server, opts, None, None, Instant::now()).unwrap();
        c.on_frame(ctl_frame(ctl::HELLO, json!({ "version": PROTOCOL_VERSION })), Instant::now());
        drain(&mut c); // WELCOME
        c
    }

    #[test]
    fn pongs_nobody_reads_close_with_4004() {
        let mut c = server(4096);
        for i in 0..10_000u32 {
            c.on_frame(Frame::new(0, PING, PROBE, i.to_be_bytes().to_vec()), Instant::now());
        }
        assert!(c.probes_out.len() * 12 <= 4096, "{} PONGs queued", c.probes_out.len());
        assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::RATE_LIMITED)));
    }

    #[test]
    fn pongs_that_are_written_free_their_budget() {
        let mut c = server(4096);
        for i in 0..10_000u32 {
            c.on_frame(Frame::new(0, PING, PROBE, i.to_be_bytes().to_vec()), Instant::now());
            if i % 100 == 99 {
                assert_eq!(drain(&mut c).len(), 100);
            }
        }
        assert!(c.is_open());
        assert!(c.probes_out.is_empty());
    }

    // take_grants: one ID can need several entries, and the frame must still fit channel 0.
    #[test]
    fn window_updates_never_exceed_the_control_limit() {
        let mut c = welcomed(Options::default(), &[]);
        let per_id = 3 * MAX_CREDIT;
        let ids: Vec<u16> = (1..=WINDOW_ENTRIES_PER_FRAME as u16).map(|i| i * 2 + 1).collect();
        for id in &ids {
            c.grants.insert(*id, per_id);
        }
        let mut total: HashMap<u16, u64> = HashMap::new();
        let mut frames = 0;
        for f in drain(&mut c) {
            assert_eq!(f.ty, ctl::WINDOW_UPDATE);
            assert!(f.payload.len() <= CONTROL_MAX as usize, "{} bytes", f.payload.len());
            for e in f.payload.as_chunks::<6>().0 {
                let inc = u64::from(u32::from_be_bytes([e[2], e[3], e[4], e[5]]));
                assert!((1..=MAX_CREDIT).contains(&inc));
                *total.entry(u16::from_be_bytes([e[0], e[1]])).or_insert(0) += inc;
            }
            frames += 1;
        }
        assert_eq!(frames, 3);
        assert_eq!(total.len(), ids.len());
        assert!(total.values().all(|v| *v == per_id));
    }

    // M1: datagrams held before the answer are replayed as datagrams.
    #[test]
    fn a_held_datagram_is_dropped_if_the_channel_lands_on_the_session_stream() {
        let mut c = welcomed(multistream(), &[QUIC_MULTISTREAM]);
        let (id, _sig, _rx) = c.open_channel(ChannelSpec::datagram("v"), Instant::now()).unwrap();
        drain(&mut c);
        c.on_datagram(Frame::new(id, 7, 0, b"stray".to_vec()), Instant::now());
        c.on_frame(ctl_frame(ctl::CHANNEL_ACK, json!({ "id": id, "reliable": true, "ordered": true, "quic": "session" })), Instant::now());
        assert!(c.is_open());
        assert!(c.channels[&id].recv.is_empty(), "a datagram must not be delivered on a stream channel");
    }
}

#[cfg(test)]
mod correctness_tests {
    use super::*;

    fn drain(c: &mut Core) -> Vec<Frame> {
        let (mut out, mut done) = (Vec::new(), Vec::new());
        while let Some(f) = c.next_frame(&mut done) {
            out.push(f);
        }
        out
    }

    fn ctl_frame(ty: u8, v: Value) -> Frame {
        Frame::new(0, ty, 0, serde_json::to_vec(&v).unwrap())
    }

    fn client_at(opts: Options, now: Instant) -> Core {
        let mut c = Core::new(Role::Client, opts, None, None, now).unwrap();
        c.start_client(&[], now).unwrap();
        drain(&mut c);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION })), now);
        c
    }

    /// An open, reliable channel with no RTT sample yet.
    fn open_channel(c: &mut Core, now: Instant) -> (u16, Arc<Signals>) {
        let (id, sig, _rx) = c.open_channel(ChannelSpec::reliable("x"), now).unwrap();
        c.on_frame(ctl_frame(ctl::CHANNEL_ACK, json!({ "id": id, "reliable": true, "ordered": true })), now);
        drain(c);
        (id, sig)
    }

    fn close_code(frames: &[Frame]) -> Option<u64> {
        frames.iter().find(|f| f.channel == 0 && f.ty == ctl::CLOSE).map(|f| serde_json::from_slice::<Value>(&f.payload).unwrap()["code"].as_u64().unwrap())
    }

    #[test]
    fn a_channel_refused_in_welcome_gives_back_its_window() {
        let now = Instant::now();
        let mut c = Core::new(Role::Client, Options::default(), None, None, now).unwrap();
        c.start_client(&[ChannelSpec::reliable("a")], now).unwrap();
        drain(&mut c);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "rejected": [{ "id": 1, "code": 4010 }] })), now);
        assert!(c.is_open());
        assert_eq!(c.total_window, 0);
    }

    #[test]
    fn an_unanswered_ping_times_out_and_counts_as_lost() {
        let now = Instant::now();
        let mut c = client_at(Options::default(), now);
        let (id, sig) = open_channel(&mut c, now);
        let mut rx = c.ping(Some((id, &sig)), now).unwrap();
        drain(&mut c);
        c.tick(now + Duration::from_secs(1));
        assert!(rx.try_recv().is_err(), "still waiting before the deadline");
        c.tick(now + Duration::from_secs(3600));
        assert_eq!(rx.try_recv().unwrap(), Err(Error::Timeout));
        assert!(!c.pings.values().any(|p| p.channel == id), "the channel's ping is gone (a keepalive may be pending)");
        assert_eq!(c.channel_stats(id, &sig).probes_lost, 1);
    }

    #[test]
    fn a_lost_connection_ping_counts_on_the_connection() {
        let now = Instant::now();
        let mut c = client_at(Options { ping_interval: 0, ..Options::default() }, now);
        let mut rx = c.ping(None, now).unwrap();
        drain(&mut c);
        // Keepalive is off, so only the ping's deadline bounds the wait.
        assert!(c.tick(now) <= Duration::from_secs(c.ping_timeout), "tick waits for the ping deadline");
        c.tick(now + Duration::from_secs(3600));
        assert_eq!(rx.try_recv().unwrap(), Err(Error::Timeout));
        assert_eq!(c.stats.probes_lost, 1);
    }

    #[test]
    fn a_lost_growth_probe_does_not_stop_growth_for_good() {
        let now = Instant::now();
        let mut c = client_at(Options::default(), now);
        let (id, sig) = open_channel(&mut c, now);
        let consume_window = |c: &mut Core, at: Instant| {
            let mut left = c.channels[&id].window;
            while left > 0 {
                let n = left.min(65536);
                c.on_frame(Frame::new(id, 1, 0, vec![0u8; n as usize]), at);
                assert!(matches!(c.receive(id, &sig, at), Some(Ok(Some(_)))));
                left -= n;
            }
            drain(c)
        };
        let probes = |frames: &[Frame]| frames.iter().filter(|f| f.channel == id && f.ty == PING && f.flags & PROBE != 0).count();
        assert_eq!(probes(&consume_window(&mut c, now)), 1);
        assert!(c.channels[&id].probing_for_growth);
        let later = now + Duration::from_secs(3600);
        c.tick(later);
        assert!(!c.channels[&id].probing_for_growth);
        assert_eq!(c.channels[&id].stats.probes_lost, 1);
        assert_eq!(probes(&consume_window(&mut c, later)), 1, "probes again");
    }

    #[test]
    fn a_channels_pings_end_with_it() {
        let now = Instant::now();
        let mut c = client_at(Options::default(), now);
        let (id, sig) = open_channel(&mut c, now);
        let mut rx = c.ping(Some((id, &sig)), now).unwrap();
        drain(&mut c);
        drop(c.close_channel(id, &sig, 1000, None, now));
        c.on_frame(ctl_frame(ctl::CLOSE_CHANNEL, json!({ "id": id, "code": 1000 })), now);
        assert!(!c.channels.contains_key(&id));
        assert!(c.pings.is_empty());
        assert!(matches!(rx.try_recv(), Ok(Err(Error::ChannelClosed(_)))));
    }

    #[test]
    fn the_keepalive_pong_is_an_rtt_sample() {
        let now = Instant::now();
        let mut c = client_at(Options { ping_interval: 1, ..Options::default() }, now);
        drain(&mut c);
        c.tick(now + Duration::from_secs(1));
        let frames = drain(&mut c);
        let ping = frames.iter().find(|f| f.channel == 0 && f.ty == PING).expect("keepalive PING");
        c.on_frame(Frame::new(0, PONG, PROBE, ping.payload.clone()), now + Duration::from_millis(1500));
        assert_eq!(c.stats.rtt, Some(Duration::from_millis(500)));
    }

    #[test]
    fn a_close_code_above_16_bits_is_invalid() {
        let now = Instant::now();
        let mut c = client_at(Options::default(), now);
        c.on_frame(ctl_frame(ctl::CLOSE, json!({ "code": 66536 })), now);
        assert_eq!(c.close_info().unwrap().code, code::INVALID_MESSAGE);
        assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::INVALID_MESSAGE)));
    }

    #[test]
    fn a_close_channel_code_above_16_bits_is_invalid() {
        let now = Instant::now();
        let mut c = client_at(Options::default(), now);
        let (id, _sig) = open_channel(&mut c, now);
        c.on_frame(ctl_frame(ctl::CLOSE_CHANNEL, json!({ "id": id, "code": 66536 })), now);
        assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::INVALID_MESSAGE)));
    }

    #[test]
    fn a_channel_reject_code_above_16_bits_is_invalid() {
        let now = Instant::now();
        let mut c = client_at(Options::default(), now);
        let (id, _sig, _rx) = c.open_channel(ChannelSpec::reliable("x"), now).unwrap();
        drain(&mut c);
        c.on_frame(ctl_frame(ctl::CHANNEL_REJECT, json!({ "id": id, "code": 66536 })), now);
        assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::INVALID_MESSAGE)));
    }

    #[test]
    fn a_welcome_refusal_code_above_16_bits_is_invalid() {
        let now = Instant::now();
        let mut c = Core::new(Role::Client, Options::default(), None, None, now).unwrap();
        c.start_client(&[ChannelSpec::reliable("a")], now).unwrap();
        drain(&mut c);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "rejected": [{ "id": 1, "code": 66536 }] })), now);
        assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::INVALID_MESSAGE)));
    }

    #[test]
    fn datagram_quarantine_runs_on_the_callers_clock() {
        let now = Instant::now();
        let policy: Policy = Arc::new(|_| Ok(()));
        let opts = Options { max_datagram: Some(1200), extensions: vec![QUIC_MULTISTREAM.into()], ..Options::default() };
        let mut c = Core::new(Role::Client, opts, Some(policy), None, now).unwrap();
        c.start_client(&[], now).unwrap();
        drain(&mut c);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "extensions": [QUIC_MULTISTREAM] })), now);
        let (id, _sig, _rx) = c.open_channel(ChannelSpec::datagram("v"), now).unwrap();
        c.on_frame(ctl_frame(ctl::CHANNEL_ACK, json!({ "id": id, "reliable": false, "ordered": false, "quic": "datagram" })), now);
        drain(&mut c);
        // The peer closes it an hour on, by the driver's clock.
        let t = now + Duration::from_secs(3600);
        c.on_frame(ctl_frame(ctl::CLOSE_CHANNEL, json!({ "id": id, "code": 1000 })), t);
        assert!(!c.channels.contains_key(&id));
        let (next, _, _) = c.open_channel(ChannelSpec::datagram("w"), t + Duration::from_secs(1)).unwrap();
        assert_ne!(next, id, "still quarantined");
        drain(&mut c);
        let (later, _, _) = c.open_channel(ChannelSpec::datagram("u"), t + DATAGRAM_QUARANTINE + Duration::from_secs(1)).unwrap();
        assert_eq!(later, id, "free again after the quarantine");
    }

    #[test]
    fn huge_peer_ping_settings_do_not_overflow_the_clock() {
        let now = Instant::now();
        let mut c = Core::new(Role::Client, Options::default(), None, None, now).unwrap();
        c.start_client(&[], now).unwrap();
        drain(&mut c);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "pingInterval": u64::MAX, "pingTimeout": u64::MAX })), now);
        assert!(c.is_open());
        let (id, sig) = open_channel(&mut c, now);
        let mut rx = c.ping(Some((id, &sig)), now).unwrap();
        // A full window with no RTT sample sends a growth probe.
        let mut left = c.channels[&id].window;
        while left > 0 {
            let n = left.min(65536);
            c.on_frame(Frame::new(id, 1, 0, vec![0u8; n as usize]), now);
            assert!(matches!(c.receive(id, &sig, now), Some(Ok(Some(_)))));
            left -= n;
        }
        assert!(c.channels[&id].probing_for_growth);
        drain(&mut c);
        assert!(c.tick(now) > Duration::ZERO);
        // Past every clamped bound: the probes expire and keepalive sends its PING.
        let far = now + Duration::from_secs(2 * 365 * 24 * 3600);
        c.tick(far);
        assert_eq!(rx.try_recv().unwrap(), Err(Error::Timeout));
        assert!(!c.channels[&id].probing_for_growth);
        assert!(c.is_open());
        assert!(drain(&mut c).iter().any(|f| f.channel == 0 && f.ty == PING), "keepalive PING");
        c.tick(far + Duration::from_secs(1));
        assert!(c.is_open());
    }

    /// A client whose unread PONGs leave no room in the control budget for another probe.
    fn client_with_full_probe_queue(ping_interval: u64, now: Instant) -> Core {
        let mut c = client_at(Options { ping_interval, ..Options::default() }, now);
        c.opts.max_control_queue = 64; // After HELLO, which alone is larger.
        for i in 0..5u32 {
            c.on_frame(Frame::new(0, PING, PROBE, i.to_be_bytes().to_vec()), now);
        }
        assert!(c.is_open());
        c
    }

    #[test]
    fn a_ping_over_the_control_budget_leaves_nothing_pending() {
        let now = Instant::now();
        let mut c = client_with_full_probe_queue(0, now);
        let mut rx = c.ping(None, now).unwrap();
        assert!(!c.is_open(), "closed with RATE_LIMITED");
        assert!(c.pings.is_empty());
        assert!(matches!(rx.try_recv(), Ok(Err(Error::Closed(_)))));

        let mut c = client_with_full_probe_queue(1, now);
        c.tick(now + Duration::from_secs(1));
        assert!(!c.is_open(), "the keepalive PING closed it with RATE_LIMITED");
        assert!(c.pings.is_empty());
    }

    #[test]
    fn too_many_hello_channels_are_refused_not_overflowed() {
        let now = Instant::now();
        let mut c = Core::new(Role::Client, Options::default(), None, None, now).unwrap();
        let specs = vec![ChannelSpec::reliable("a"); 32768];
        assert!(matches!(c.start_client(&specs, now), Err(Error::Invalid(_))));
        assert!(c.channels.is_empty());
        // As many as there are odd IDs for can't fit in a HELLO either, and are refused for that.
        let mut c = Core::new(Role::Client, Options::default(), None, None, now).unwrap();
        assert!(matches!(c.start_client(&specs[..32767], now), Err(Error::Invalid(_))));
        assert!(c.channels.is_empty());
    }
}

#[cfg(test)]
mod hygiene_tests {
    use super::*;

    fn drain(c: &mut Core) -> Vec<Frame> {
        let (mut out, mut done) = (Vec::new(), Vec::new());
        while let Some(f) = c.next_frame(&mut done) {
            out.push(f);
        }
        out
    }

    fn ctl_frame(ty: u8, v: Value) -> Frame {
        Frame::new(0, ty, 0, serde_json::to_vec(&v).unwrap())
    }

    fn close_code(frames: &[Frame]) -> Option<u64> {
        frames.iter().find(|f| f.channel == 0 && f.ty == ctl::CLOSE).map(|f| serde_json::from_slice::<Value>(&f.payload).unwrap()["code"].as_u64().unwrap())
    }

    fn client(opts: Options) -> Core {
        let now = Instant::now();
        let mut c = Core::new(Role::Client, opts, None, None, now).unwrap();
        c.start_client(&[], now).unwrap();
        drain(&mut c);
        c
    }

    fn welcomed(opts: Options) -> Core {
        let mut c = client(opts);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION })), Instant::now());
        assert!(c.is_open());
        c
    }

    fn open_channel(c: &mut Core, now: Instant) -> (u16, Arc<Signals>) {
        let (id, sig, _rx) = c.open_channel(ChannelSpec::reliable("x"), now).unwrap();
        c.on_frame(ctl_frame(ctl::CHANNEL_ACK, json!({ "id": id, "reliable": true, "ordered": true })), now);
        drain(c);
        (id, sig)
    }

    /// A server that has answered `hello`, and the WELCOME it wrote.
    fn welcome_for(opts: Options, policy: Option<Policy>, hello: &Value) -> (Core, Frame) {
        let now = Instant::now();
        let mut c = Core::new(Role::Server, opts, policy, None, now).unwrap();
        let hello = ctl_frame(ctl::HELLO, hello.clone());
        assert!(hello.payload.len() <= CONTROL_MAX as usize, "the HELLO itself must fit");
        c.on_frame(hello, now);
        let welcome = drain(&mut c).into_iter().find(|f| f.ty == ctl::WELCOME).expect("WELCOME");
        (c, welcome)
    }

    // 1: WELCOME may only accept what HELLO offered (core §3.3).
    #[test]
    fn a_welcome_extension_we_did_not_offer_closes_with_1002() {
        let mut c = client(Options { max_datagram: Some(1200), ..Options::default() });
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "extensions": [QUIC_MULTISTREAM] })), Instant::now());
        assert!(!c.multistream);
        assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::PROTOCOL_ERROR)));
    }

    #[test]
    fn welcome_extensions_that_are_not_strings_close_with_4001() {
        for bad in [json!("quic-multistream/1"), json!([1])] {
            let mut c = client(Options::default());
            c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "extensions": bad })), Instant::now());
            assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::INVALID_MESSAGE)), "{bad}");
        }
    }

    #[test]
    fn an_offered_extension_is_accepted() {
        let opts = Options { max_datagram: Some(1200), extensions: vec![QUIC_MULTISTREAM.into()], ..Options::default() };
        let mut c = client(opts);
        c.on_frame(ctl_frame(ctl::WELCOME, json!({ "version": PROTOCOL_VERSION, "extensions": [QUIC_MULTISTREAM] })), Instant::now());
        assert!(c.is_open() && c.multistream);
    }

    // 2: no grant may raise the peer's credit above 2^31-1 (core §6).
    #[test]
    fn window_growth_stops_at_the_credit_maximum() {
        let now = Instant::now();
        let mut c = welcomed(Options { max_channel_window: u64::MAX, connection_window: u64::MAX, ..Options::default() });
        let (id, _sig) = open_channel(&mut c, now);
        c.channels.get_mut(&id).unwrap().stats.srtt = Some(Duration::from_secs(1));
        for _ in 0..20 {
            // The peer sends all its credit at once, and the application takes it at once.
            let ch = c.channels.get_mut(&id).unwrap();
            let n = std::mem::take(&mut ch.recv_credit);
            c.consumed(id, n, now);
            let ch = &c.channels[&id];
            assert!(ch.recv_credit <= MAX_CREDIT, "the peer holds {} credit", ch.recv_credit);
        }
        assert_eq!(c.channels[&id].window, MAX_CREDIT);
    }

    // 3: HELLO and WELCOME fit in a channel-0 payload (core §3.1, §4).
    #[test]
    fn a_hello_over_the_control_limit_is_refused() {
        let now = Instant::now();
        let mut c = Core::new(Role::Client, Options::default(), None, None, now).unwrap();
        let specs = vec![ChannelSpec::reliable("a"); 2000];
        assert!(matches!(c.start_client(&specs, now), Err(Error::Invalid(_))));
        assert!(c.channels.is_empty());
        assert_eq!(c.total_window, 0);
        assert!(drain(&mut c).is_empty());
        // Large credentials count too.
        let opts = Options { auth: Some(json!({ "token": "x".repeat(70_000) })), ..Options::default() };
        let mut c = Core::new(Role::Client, opts, None, None, now).unwrap();
        assert!(matches!(c.start_client(&[], now), Err(Error::Invalid(_))));
        // One that fits goes out.
        let mut c = Core::new(Role::Client, Options::default(), None, None, now).unwrap();
        c.start_client(&specs[..1000], now).unwrap();
        let hello = drain(&mut c);
        assert_eq!(hello.len(), 1);
        assert!(hello[0].payload.len() <= CONTROL_MAX as usize);
    }

    fn hello_with(n: u16, spec: impl Fn(u16) -> Value) -> Value {
        json!({ "version": PROTOCOL_VERSION, "extensions": [QUIC_MULTISTREAM], "channels": (0..n).map(|i| spec(2 * i + 1)).collect::<Vec<_>>() })
    }

    #[test]
    fn long_refusals_lose_their_reasons_to_fit_welcome() {
        // Each refusal, with the default reason, is longer than the request it answers.
        let hello = hello_with(1200, |id| json!({ "id": id, "name": "", "reliable": true, "ordered": true }));
        let (c, welcome) = welcome_for(Options::default(), None, &hello);
        assert!(welcome.payload.len() <= CONTROL_MAX as usize, "WELCOME is {} bytes", welcome.payload.len());
        let w: Value = serde_json::from_slice(&welcome.payload).unwrap();
        let rejected = w["rejected"].as_array().unwrap();
        assert_eq!(rejected.len(), 1200);
        assert!(rejected.iter().all(|r| r["code"] == code::UNSUPPORTED));
        assert!(c.is_open());
    }

    #[test]
    fn channels_that_do_not_fit_welcome_are_refused_with_4002() {
        // A datagram placement's answer is longer than its request.
        let opts = Options { max_datagram: Some(1200), extensions: vec![QUIC_MULTISTREAM.into()], max_channels: 2000, ..Options::default() };
        let hello = hello_with(900, |id| json!({ "id": id, "name": "", "reliable": false, "ordered": false, "quic": "datagram" }));
        let policy: Policy = Arc::new(|_| Ok(()));
        let (mut c, welcome) = welcome_for(opts, Some(policy), &hello);
        assert!(welcome.payload.len() <= CONTROL_MAX as usize, "WELCOME is {} bytes", welcome.payload.len());
        let w: Value = serde_json::from_slice(&welcome.payload).unwrap();
        let accepted = w["channels"].as_array().unwrap();
        let rejected = w["rejected"].as_array().unwrap();
        assert!(!rejected.is_empty());
        assert_eq!(accepted.len() + rejected.len(), 900);
        assert!(rejected.iter().all(|r| r["code"] == code::CHANNEL_LIMIT && r.get("reason").is_none()));
        // Refused channels are not open, and their windows are given back.
        assert_eq!(c.channels.len(), accepted.len());
        assert_eq!(c.total_window, accepted.len() as u64 * u64::from(Limits::default().initial_window));
        let mut handed = 0;
        while let Some(a) = c.take_accepted() {
            assert!(c.channels.contains_key(&a.id));
            handed += 1;
        }
        assert_eq!(handed, accepted.len());
    }

    // 4: a CLOSE body is checked like any control payload (core §4.1, §9.1).
    #[test]
    fn a_close_without_a_usable_code_is_invalid() {
        for body in [json!({}), json!({ "code": "1000" }), json!({ "code": 1000.5 }), json!({ "code": -1 }), json!({ "code": 1000, "reason": 7 })] {
            let mut c = welcomed(Options::default());
            c.on_frame(ctl_frame(ctl::CLOSE, body.clone()), Instant::now());
            assert_eq!(c.close_info().unwrap().code, code::INVALID_MESSAGE, "{body}");
            assert_eq!(close_code(&drain(&mut c)), Some(u64::from(code::INVALID_MESSAGE)), "{body}");
        }
    }

    // 5: a closing channel discards its probes (core §8.1), so its pings end at once.
    #[test]
    fn closing_a_channel_ends_its_pings_at_once() {
        let now = Instant::now();
        let mut c = welcomed(Options::default());
        let (id, sig) = open_channel(&mut c, now);
        let mut rx = c.ping(Some((id, &sig)), now).unwrap();
        drain(&mut c);
        let _closed = c.close_channel(id, &sig, code::NORMAL, None, now);
        assert!(matches!(rx.try_recv(), Ok(Err(Error::ChannelClosed(_)))));
        assert!(c.pings.is_empty());
    }

    #[test]
    fn a_channel_error_ends_its_pings_at_once() {
        let now = Instant::now();
        let mut c = welcomed(Options::default());
        let (id, sig) = open_channel(&mut c, now);
        let mut rx = c.ping(Some((id, &sig)), now).unwrap();
        drain(&mut c);
        // Fragments with different types: CLOSE_CHANNEL 1002 (core §7).
        c.on_frame(Frame::new(id, 1, MORE, b"a".to_vec()), now);
        c.on_frame(Frame::new(id, 2, 0, b"b".to_vec()), now);
        assert!(c.channels[&id].sent_close);
        assert!(matches!(rx.try_recv(), Ok(Err(Error::ChannelClosed(i))) if i.code == code::PROTOCOL_ERROR));
        assert!(c.pings.is_empty());
    }
}
