//! The tokio driver: runs a [`Core`] over a byte stream, and the handles applications use.
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;

use crate::core::{Authorize, ChannelSpec, Core, Limits, Message, Options, Policy, ProbeStats, Properties, Refusal, Role, Signals};
use crate::error::{CloseInfo, Error, Result};
use crate::frame::{code, parse_header, Frame, Header, HEADER_LEN, MAGIC};

struct Shared {
    core: Mutex<Core>,
    wake_writer: Notify,
    wake_datagrams: Notify,
    wake_timer: Notify,
    closed: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Core> {
        self.core.lock().expect("core lock")
    }
}

/// One xumux connection.
#[derive(Clone)]
pub struct Session {
    shared: Arc<Shared>,
}

/// Server configuration.
#[derive(Clone, Default)]
pub struct Acceptor {
    pub policy: Option<Policy>,
    pub authorize: Option<Authorize>,
}

impl Acceptor {
    pub fn policy(mut self, f: impl Fn(&ChannelSpec) -> std::result::Result<(), Refusal> + Send + Sync + 'static) -> Self {
        self.policy = Some(Arc::new(f));
        self
    }

    pub fn authorize(
        mut self,
        f: impl Fn(&serde_json::Map<String, serde_json::Value>) -> std::result::Result<(), Refusal> + Send + Sync + 'static,
    ) -> Self {
        self.authorize = Some(Arc::new(f));
        self
    }
}

impl Session {
    /// Runs the server side on a byte stream, with magic bytes (TCP, Unix sockets, stdio).
    pub async fn accept<R, W>(reader: R, writer: W, opts: Options, acceptor: Acceptor) -> Result<Session>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let core = Core::new(Role::Server, opts, acceptor.policy, acceptor.authorize, Instant::now())?;
        let s = Session::spawn(core, reader, writer);
        s.finish_handshake().await?;
        Ok(s)
    }

    /// Runs the client side on a byte stream. Returns the session and the channels opened in HELLO,
    /// or their refusals, in order.
    pub async fn connect<R, W>(
        reader: R,
        writer: W,
        opts: Options,
        acceptor: Acceptor,
        channels: Vec<ChannelSpec>,
    ) -> Result<(Session, Vec<Result<Channel>>)>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let now = Instant::now();
        let mut core = Core::new(Role::Client, opts, acceptor.policy, acceptor.authorize, now)?;
        let opened = core.start_client(&channels, now);
        let waits: Vec<_> = opened
            .iter()
            .map(|(id, sig)| (*id, sig.clone(), core.hello_channel_waiter(*id).expect("just inserted")))
            .collect();
        let s = Session::spawn(core, reader, writer);
        s.finish_handshake().await?;
        let mut out = Vec::with_capacity(waits.len());
        for ((id, sig, rx), spec) in waits.into_iter().zip(channels) {
            out.push(match rx.await {
                Ok(Ok(_)) => Ok(Channel { session: s.clone(), id, sig, spec }),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(s.closed_error()),
            });
        }
        Ok((s, out))
    }

    /// Runs on a QUIC session stream, with datagrams. Used by [`crate::quic`].
    #[cfg(feature = "quic")]
    pub(crate) fn spawn_quic<R, W, D>(core: Core, reader: R, writer: W, datagrams: D) -> Session
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        D: DatagramPath,
    {
        let shared = Arc::new(Shared { core: Mutex::new(core), wake_writer: Notify::new(), wake_datagrams: Notify::new(), wake_timer: Notify::new(), closed: Notify::new() });
        tokio::spawn(read_loop(shared.clone(), reader, false));
        tokio::spawn(write_loop(shared.clone(), writer, false));
        tokio::spawn(timer_loop(shared.clone()));
        tokio::spawn(read_datagrams(shared.clone(), datagrams.clone()));
        tokio::spawn(write_datagrams(shared.clone(), datagrams));
        Session { shared }
    }

    #[cfg(feature = "quic")]
    pub(crate) async fn finish_handshake_pub(&self) -> Result<()> {
        self.finish_handshake().await
    }

    #[cfg(feature = "quic")]
    pub(crate) async fn channels_from_hello(
        &self,
        waits: Vec<(u16, Arc<Signals>, tokio::sync::oneshot::Receiver<Result<Properties>>)>,
        channels: Vec<ChannelSpec>,
    ) -> Vec<Result<Channel>> {
        let mut out = Vec::with_capacity(waits.len());
        for ((id, sig, rx), spec) in waits.into_iter().zip(channels) {
            out.push(match rx.await {
                Ok(Ok(_)) => Ok(Channel { session: self.clone(), id, sig, spec }),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(self.closed_error()),
            });
        }
        out
    }

    /// Runs the server side on a message pipe: one frame per message, no magic (WebSocket, WebRTC).
    pub async fn accept_messages<R: MessageReader, W: MessageWriter>(reader: R, writer: W, opts: Options, acceptor: Acceptor) -> Result<Session> {
        let core = Core::new(Role::Server, opts, acceptor.policy, acceptor.authorize, Instant::now())?;
        let s = Session::spawn_messages(core, reader, writer);
        s.finish_handshake().await?;
        Ok(s)
    }

    /// Runs the client side on a message pipe.
    pub async fn connect_messages<R: MessageReader, W: MessageWriter>(
        reader: R,
        writer: W,
        opts: Options,
        acceptor: Acceptor,
        channels: Vec<ChannelSpec>,
    ) -> Result<(Session, Vec<Result<Channel>>)> {
        let now = Instant::now();
        let mut core = Core::new(Role::Client, opts, acceptor.policy, acceptor.authorize, now)?;
        let opened = core.start_client(&channels, now);
        let waits: Vec<_> = opened
            .iter()
            .map(|(id, sig)| (*id, sig.clone(), core.hello_channel_waiter(*id).expect("just inserted")))
            .collect();
        let s = Session::spawn_messages(core, reader, writer);
        s.finish_handshake().await?;
        let mut out = Vec::with_capacity(waits.len());
        for ((id, sig, rx), spec) in waits.into_iter().zip(channels) {
            out.push(match rx.await {
                Ok(Ok(_)) => Ok(Channel { session: s.clone(), id, sig, spec }),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(s.closed_error()),
            });
        }
        Ok((s, out))
    }

    fn spawn_messages<R: MessageReader, W: MessageWriter>(core: Core, reader: R, writer: W) -> Session {
        let shared = Arc::new(Shared { core: Mutex::new(core), wake_writer: Notify::new(), wake_datagrams: Notify::new(), wake_timer: Notify::new(), closed: Notify::new() });
        tokio::spawn(read_messages(shared.clone(), reader));
        tokio::spawn(write_messages(shared.clone(), writer));
        tokio::spawn(timer_loop(shared.clone()));
        Session { shared }
    }

    fn spawn<R, W>(core: Core, reader: R, writer: W) -> Session
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let shared = Arc::new(Shared { core: Mutex::new(core), wake_writer: Notify::new(), wake_datagrams: Notify::new(), wake_timer: Notify::new(), closed: Notify::new() });
        tokio::spawn(read_loop(shared.clone(), reader, true));
        tokio::spawn(write_loop(shared.clone(), writer, true));
        tokio::spawn(timer_loop(shared.clone()));
        Session { shared }
    }

    /// A refusal returns only after the close exchange, so a caller that exits at once can't lose
    /// the CLOSE that tells the peer why.
    async fn finish_handshake(&self) -> Result<()> {
        let r = self.wait_handshake().await;
        if r.is_err() {
            self.closed().await;
        }
        r
    }

    async fn wait_handshake(&self) -> Result<()> {
        loop {
            let notify = self.shared.lock().handshake_done.clone();
            let waiting = notify.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            {
                let core = self.shared.lock();
                if core.is_open() {
                    return Ok(());
                }
                if !core.is_handshaking() {
                    return Err(Error::Closed(core.close_info().unwrap_or(CloseInfo { code: code::GOING_AWAY, reason: String::new() })));
                }
            }
            waiting.await;
        }
    }

    fn closed_error(&self) -> Error {
        Error::Closed(self.shared.lock().close_info().unwrap_or(CloseInfo { code: code::GOING_AWAY, reason: String::new() }))
    }

    /// The next channel the peer opened, or `None` once the connection has ended.
    pub async fn accept_channel(&self) -> Option<Channel> {
        loop {
            let notify = self.shared.lock().wake_accept.clone();
            let waiting = notify.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            {
                let mut core = self.shared.lock();
                if let Some(a) = core.take_accepted() {
                    return Some(Channel { session: self.clone(), id: a.id, sig: a.sig, spec: a.spec });
                }
                if core.is_ended() {
                    return None;
                }
            }
            waiting.await;
        }
    }

    pub async fn open_channel(&self, spec: ChannelSpec) -> Result<Channel> {
        let (id, sig, rx) = {
            let mut core = self.shared.lock();
            core.open_channel(spec.clone(), Instant::now())?
        };
        self.shared.wake_writer.notify_one();
        match rx.await {
            Ok(Ok(_)) => Ok(Channel { session: self.clone(), id, sig, spec }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(self.closed_error()),
        }
    }

    /// Round-trip time on channel 0.
    pub async fn ping(&self) -> Result<Duration> {
        let rx = self.shared.lock().ping(None, Instant::now())?;
        self.shared.wake_writer.notify_one();
        rx.await.unwrap_or_else(|_| Err(self.closed_error()))
    }

    pub fn stats(&self) -> ProbeStats {
        self.shared.lock().stats
    }

    pub fn remote_limits(&self) -> Limits {
        self.shared.lock().remote_limits()
    }

    pub fn close_info(&self) -> Option<CloseInfo> {
        self.shared.lock().close_info()
    }

    /// Sends CLOSE, and waits for the exchange to finish.
    pub async fn close(&self, c: u16, reason: &str) {
        self.shared.lock().close(c, reason, Instant::now());
        self.shared.wake_writer.notify_one();
        self.shared.wake_timer.notify_one();
        self.closed().await;
    }

    /// Waits for the connection to end.
    pub async fn closed(&self) -> CloseInfo {
        loop {
            let waiting = self.shared.closed.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            {
                let core = self.shared.lock();
                if core.is_done() {
                    return core.close_info().unwrap_or(CloseInfo { code: code::GOING_AWAY, reason: String::new() });
                }
            }
            waiting.await;
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(shared: Arc<Shared>, mut r: R, use_magic: bool) {
    let mut magic = [0u8; 4];
    let ok = !use_magic || (r.read_exact(&mut magic).await.is_ok() && magic == MAGIC);
    if !ok {
        // Core: on a mismatch, close the transport without sending anything.
        shared.lock().transport_closed();
        shared.closed.notify_waiters();
        shared.wake_writer.notify_one();
        return;
    }
    let mut header = [0u8; HEADER_LEN];
    loop {
        if r.read_exact(&mut header).await.is_err() {
            break;
        }
        let Header { channel, ty, flags, len } = parse_header(&header);
        let limit = shared.lock().frame_limit(channel);
        if len > limit {
            // Core §2.3 step 1: refuse without reading or buffering the payload.
            shared.lock().fail(code::MESSAGE_TOO_LARGE, "frame exceeds the receiver's limit");
            shared.wake_writer.notify_one();
            shared.wake_timer.notify_one();
            break;
        }
        let mut payload = BytesMut::with_capacity(len as usize);
        if len > 0 {
            payload.resize(len as usize, 0);
            if r.read_exact(&mut payload).await.is_err() {
                break;
            }
        }
        let frame = Frame { channel, ty, flags, payload: payload.freeze() };
        let done = {
            let mut core = shared.lock();
            core.on_frame(frame, Instant::now());
            core.is_done()
        };
        shared.wake_writer.notify_one();
        shared.wake_timer.notify_one();
        if done {
            shared.closed.notify_waiters();
            break;
        }
    }
    let mut core = shared.lock();
    // Bytes after a failure are not read. The writer still sends CLOSE, then the transport ends.
    if !core.close_written() && !core.is_done() && core.is_ended() {
        drop(core);
        // Wait for the writer: it finishes the connection after writing CLOSE.
        return;
    }
    core.transport_closed();
    drop(core);
    shared.closed.notify_waiters();
    shared.wake_writer.notify_one();
}

async fn write_loop<W: AsyncWrite + Unpin>(shared: Arc<Shared>, mut w: W, use_magic: bool) {
    if use_magic && (w.write_all(&MAGIC).await.is_err() || w.flush().await.is_err()) {
        shared.lock().transport_closed();
        shared.closed.notify_waiters();
        return;
    }
    let write_batch = shared.lock().write_batch();
    let mut buf = BytesMut::with_capacity(write_batch);
    let mut completed = Vec::new();
    loop {
        let waiting = shared.wake_writer.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let (close_now, done) = {
            let mut core = shared.lock();
            while buf.len() < write_batch {
                let Some(f) = core.next_frame(&mut completed) else { break };
                buf.reserve(f.encoded_len());
                f.encode_into(&mut buf);
            }
            (core.close_written(), core.is_done())
        };
        if !buf.is_empty() {
            let failed = w.write_all(&buf).await.is_err() || w.flush().await.is_err();
            buf.clear();
            for c in completed.drain(..) {
                let _ = c.send(Ok(()));
            }
            if failed {
                shared.lock().transport_closed();
                shared.closed.notify_waiters();
                return;
            }
            if !close_now && !done {
                continue;
            }
        }
        if close_now || done {
            let _ = w.shutdown().await;
            let mut core = shared.lock();
            core.close_write_done(Instant::now());
            let finished = core.is_done();
            drop(core);
            shared.wake_timer.notify_one();
            if finished {
                shared.closed.notify_waiters();
            }
            return;
        }
        waiting.await;
    }
}

/// One message from a message pipe.
pub enum Incoming {
    Binary(Bytes),
    /// Bindings carry frames in binary messages, so a text message is a protocol error.
    Text,
}

/// The receive side of a message-oriented transport. `None` means it ended.
pub trait MessageReader: Send + 'static {
    fn read(&mut self) -> impl Future<Output = Option<Incoming>> + Send;
}

/// The send side of a message-oriented transport.
pub trait MessageWriter: Send + 'static {
    fn write(&mut self, message: Bytes) -> impl Future<Output = std::io::Result<()>> + Send;
    /// Ends the transport, after the xumux CLOSE exchange.
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

async fn read_messages<R: MessageReader>(shared: Arc<Shared>, mut r: R) {
    while let Some(msg) = r.read().await {
        let failure = match msg {
            Incoming::Text => Some((code::PROTOCOL_ERROR, "text message on a binary binding")),
            Incoming::Binary(mut b) if b.len() >= HEADER_LEN => {
                let head: [u8; HEADER_LEN] = b[..HEADER_LEN].try_into().expect("length checked");
                let Header { channel, ty, flags, len } = parse_header(&head);
                if len > shared.lock().frame_limit(channel) {
                    Some((code::MESSAGE_TOO_LARGE, "frame exceeds the receiver's limit"))
                } else if b.len() != HEADER_LEN + len as usize {
                    // Core §2.3 step 2.
                    Some((code::INVALID_MESSAGE, "message length differs from the frame's"))
                } else {
                    let payload = b.split_off(HEADER_LEN);
                    let done = {
                        let mut core = shared.lock();
                        core.on_frame(Frame { channel, ty, flags, payload }, Instant::now());
                        core.is_done()
                    };
                    shared.wake_writer.notify_one();
                    shared.wake_timer.notify_one();
                    if done {
                        shared.closed.notify_waiters();
                        return;
                    }
                    None
                }
            }
            Incoming::Binary(_) => Some((code::INVALID_MESSAGE, "message shorter than a frame header")),
        };
        if let Some((c, reason)) = failure {
            shared.lock().fail(c, reason);
            shared.wake_writer.notify_one();
            shared.wake_timer.notify_one();
        }
    }
    let mut core = shared.lock();
    core.transport_closed();
    drop(core);
    shared.closed.notify_waiters();
    shared.wake_writer.notify_one();
}

async fn write_messages<W: MessageWriter>(shared: Arc<Shared>, mut w: W) {
    let mut completed = Vec::new();
    loop {
        let waiting = shared.wake_writer.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let (frame, close_now, done) = {
            let mut core = shared.lock();
            let f = core.next_frame(&mut completed);
            (f, core.close_written(), core.is_done())
        };
        let had_frame = frame.is_some();
        if let Some(f) = frame {
            let mut buf = BytesMut::with_capacity(f.encoded_len());
            f.encode_into(&mut buf);
            let failed = w.write(buf.freeze()).await.is_err();
            for c in completed.drain(..) {
                let _ = c.send(Ok(()));
            }
            if failed {
                shared.lock().transport_closed();
                shared.closed.notify_waiters();
                return;
            }
        }
        if close_now || done {
            {
                let mut core = shared.lock();
                core.close_write_done(Instant::now());
            }
            shared.wake_timer.notify_one();
            // The peer's CLOSE may still be on its way, so the transport stays up until it arrives
            // or the wait for it runs out.
            let waiting = shared.closed.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            if !shared.lock().is_done() {
                waiting.await;
            }
            w.close().await;
            return;
        }
        if !had_frame {
            waiting.await;
        }
    }
}

/// A transport's unreliable datagrams.
#[cfg(feature = "quic")]
pub trait DatagramPath: Clone + Send + Sync + 'static {
    fn read(&self) -> impl Future<Output = Option<Bytes>> + Send;
    /// Sends one datagram. Failing to is the same as loss.
    fn write(&self, b: Bytes);
    fn max_size(&self) -> Option<usize>;
}

#[cfg(feature = "quic")]
async fn read_datagrams<D: DatagramPath>(shared: Arc<Shared>, d: D) {
    while let Some(mut b) = d.read().await {
        if b.len() < HEADER_LEN {
            continue;
        }
        let head: [u8; HEADER_LEN] = b[..HEADER_LEN].try_into().expect("length checked");
        let Header { channel, ty, flags, len } = parse_header(&head);
        // A bad datagram is discarded, as a lost one would be.
        if b.len() != HEADER_LEN + len as usize || len > shared.lock().frame_limit(channel) {
            continue;
        }
        let payload = b.split_off(HEADER_LEN);
        shared.lock().on_datagram(Frame { channel, ty, flags, payload }, Instant::now());
        shared.wake_writer.notify_one();
        shared.wake_datagrams.notify_one();
    }
}

#[cfg(feature = "quic")]
async fn write_datagrams<D: DatagramPath>(shared: Arc<Shared>, d: D) {
    loop {
        let waiting = shared.wake_datagrams.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let frames: Vec<Frame> = {
            let mut core = shared.lock();
            core.set_max_datagram(d.max_size());
            let mut v = Vec::new();
            while let Some(f) = core.next_datagram() {
                v.push(f);
            }
            if core.is_done() {
                return;
            }
            v
        };
        for f in &frames {
            let mut buf = BytesMut::with_capacity(f.encoded_len());
            f.encode_into(&mut buf);
            d.write(buf.freeze());
        }
        if frames.is_empty() {
            let closed = shared.closed.notified();
            tokio::select! {
                _ = waiting => {}
                _ = closed => {}
            }
        }
    }
}

async fn timer_loop(shared: Arc<Shared>) {
    loop {
        let wait = {
            let mut core = shared.lock();
            let d = core.tick(Instant::now());
            if core.is_done() {
                drop(core);
                shared.closed.notify_waiters();
                shared.wake_writer.notify_one();
                return;
            }
            d
        };
        shared.wake_writer.notify_one();
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shared.wake_timer.notified() => {}
        }
    }
}

/// One channel. Cloning shares it.
#[derive(Clone)]
pub struct Channel {
    session: Session,
    id: u16,
    sig: Arc<Signals>,
    spec: ChannelSpec,
}

impl Channel {
    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.spec.name
    }

    pub fn spec(&self) -> &ChannelSpec {
        &self.spec
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn profile(&self) -> Option<&str> {
        self.spec.metadata.as_ref()?.get("profile")?.as_str()
    }

    fn core(&self) -> MutexGuard<'_, Core> {
        self.session.shared.lock()
    }

    fn wake(&self) {
        self.session.shared.wake_writer.notify_one();
        self.session.shared.wake_datagrams.notify_one();
    }

    /// Sends one message, fragmenting as needed. Resolves once it is handed to the transport. Waits
    /// while the peer's flow-control window is used up.
    pub async fn send(&self, ty: u8, payload: impl Into<Bytes>) -> Result<()> {
        let rx = self.core().send(self.id, &self.sig, ty, payload.into())?;
        self.wake();
        rx.await.unwrap_or_else(|_| Err(self.session.closed_error()))
    }

    /// Queues a message without waiting for it to be sent. For senders with their own pacing, such
    /// as video, which checks [`Channel::send_credit`] and [`Channel::queued`] first.
    pub fn queue(&self, ty: u8, payload: impl Into<Bytes>) -> Result<()> {
        // The completion receiver isn't needed: a queued message reports nothing back.
        drop(self.core().send(self.id, &self.sig, ty, payload.into())?);
        self.wake();
        Ok(())
    }

    /// Bytes that can go out now, not counting what is already queued.
    pub fn send_credit(&self) -> Result<u64> {
        self.core().send_credit(self.id, &self.sig)
    }

    /// On a datagram channel, the largest message that can be sent. It can change as the path does.
    pub fn max_datagram_payload(&self) -> Option<usize> {
        self.core().max_datagram_payload(self.id, &self.sig)
    }

    /// The largest message that goes out as a single frame, for protocols that forbid fragments.
    pub fn max_unfragmented(&self) -> usize {
        self.core().max_unfragmented() as usize
    }

    pub fn queued(&self) -> usize {
        self.core().queued_messages(self.id, &self.sig)
    }

    /// Waits until there is credit to send. For senders of unfragmented data, such as pipe/1.
    pub async fn wait_credit(&self) -> Result<u64> {
        loop {
            let waiting = self.sig.credit.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            let c = self.core().send_credit(self.id, &self.sig)?;
            if c > 0 {
                return Ok(c);
            }
            waiting.await;
        }
    }

    /// Receives one whole message. `None` means the channel closed normally.
    pub async fn receive(&self) -> Result<Option<Message>> {
        loop {
            let waiting = self.sig.recv.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            let r = {
                let mut core = self.core();
                let r = core.receive(self.id, &self.sig, Instant::now());
                if r.is_none() && core.is_ended() {
                    Some(Ok(None))
                } else {
                    r
                }
            };
            if let Some(r) = r {
                // Taking a message may have freed credit.
                self.wake();
                return r;
            }
            waiting.await;
        }
    }

    /// Scheduling on a shared path. Lower runs first, strictly: a channel at a lower number always
    /// goes ahead of one at a higher number. The default is 128. This is local and changes nothing on
    /// the wire.
    pub fn set_priority(&self, priority: u8) {
        self.core().set_priority(self.id, &self.sig, priority);
    }

    /// With manual credit, bytes count as consumed only through [`Channel::return_credit`] (core §6).
    pub fn set_manual_credit(&self, on: bool) {
        self.core().set_manual_credit(self.id, &self.sig, on);
    }

    pub fn return_credit(&self, n: usize) {
        self.core().return_credit(self.id, &self.sig, n as u64, Instant::now());
        self.wake();
    }

    pub async fn ping(&self) -> Result<Duration> {
        let rx = self.core().ping(Some((self.id, &self.sig)), Instant::now())?;
        self.wake();
        rx.await.unwrap_or_else(|_| Err(self.session.closed_error()))
    }

    pub fn stats(&self) -> ProbeStats {
        self.core().channel_stats(self.id, &self.sig)
    }

    pub fn properties(&self) -> Option<Properties> {
        self.core().channel_props(self.id, &self.sig)
    }

    pub fn receive_window(&self) -> Option<u64> {
        self.core().receive_window(self.id, &self.sig)
    }

    /// Closes, and waits until the peer has answered.
    pub async fn close(&self, c: u16, reason: Option<&str>) {
        let rx = self.core().close_channel(self.id, &self.sig, c, reason);
        self.wake();
        let _ = rx.await;
    }

    /// Waits for the channel to end.
    pub async fn closed(&self) {
        loop {
            let waiting = self.sig.closed.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            if self.sig.finished.lock().unwrap().is_some() {
                return;
            }
            waiting.await;
        }
    }
}

