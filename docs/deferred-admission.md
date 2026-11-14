# Deferred channel admission

Use deferred admission when a profile requires its local endpoint to be ready before CHANNEL_ACK. A slow endpoint connection belongs in application async code, rather than a synchronous channel policy callback.

```rust,no_run
use xumux::{Acceptor, Session};

let acceptor = Acceptor::default()
    .policy(|_request| Ok(())) // Apply the deployment's authorization and metadata policy here.
    .defer_profile("pipe/1");
// Pass acceptor to Session::accept or the corresponding transport binding.
# async fn serve(session: Session) {
while let Some(pending) = session.accept_pending_channel().await {
    // Inspect pending.spec(), reserve endpoint capacity, and perform bounded async setup.
    // Select pending.closed() alongside setup to cancel it when the session ends.
    // Only call accept after setup succeeds; on failure, reject with a profile-appropriate code.
    let channel = match pending.accept() {
        Ok(channel) => channel,
        Err(_) => continue, // Close any endpoint prepared for an admission that ended meanwhile.
    };
    // Run the profile's bounded I/O adapter on channel and the prepared endpoint.
    drop(channel);
}
# }
```

The synchronous policy still runs first, outside the core lock. Keep it quick: it decides authorization and validates metadata; deferred admission is the separate stage that may await endpoint setup. A policy refusal never becomes a pending request. Profiles are selected by their exact `metadata.profile` string; call `defer_profile` repeatedly to select more than one.

Selected profiles are refused with `1003` if requested in HELLO. Open them after WELCOME instead. Other HELLO channels and profiles keep their existing synchronous behavior. This opt-in applies to byte streams, WebSocket, QUIC and WebTransport through the same core.

`PendingChannel::accept` queues ACK and returns the admitted channel. It does not also enqueue that channel on `Session::accept_channel`. `reject` supplies a refusal, and dropping an unsettled handle rejects with `4010`. Both queued requests and handed-out handles count against `Options::max_channels`; capacity remains reserved until the request is settled or the session ends. Apply a finite setup deadline and bound concurrent endpoint tasks in the application.

A pending handle does not keep its session alive. Session shutdown retires every pending request and wakes `closed`; a late `accept` fails. The application must close provisional sockets/processes when setup or admission is cancelled. The session stores no application handles or endpoint objects, so dropping queued requests during teardown cannot call application code under its lock.

The core reserves each pending channel ID as soon as its OPEN is accepted for admission. Reusing that ID while pending remains a protocol error, and a stale completion cannot settle a later request that reuses a rejected ID. Unrelated channel data, probes and control messages continue while admission waits. The existing core treatment of illegal opener traffic before ACK is unchanged: premature data/probes/close do not become application data or cancel admission. An opener that cancels its own open waits for the answer and closes an accepted channel, as core §5.2 requires.
