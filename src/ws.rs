//! The WebSocket binding: subprotocol `xumux`, one frame per binary message, no magic.
use std::io;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::core::{ChannelSpec, Options};
use crate::error::{Error, Result};
use crate::session::{Acceptor, Channel, Incoming, MessageReader, MessageWriter, Session};

pub const SUBPROTOCOL: &str = "xumux";

pub struct WsReader<S>(SplitStream<WebSocketStream<S>>);
pub struct WsWriter<S>(SplitSink<WebSocketStream<S>, Message>);

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> MessageReader for WsReader<S> {
    async fn read(&mut self) -> Option<Incoming> {
        loop {
            match self.0.next().await? {
                Ok(Message::Binary(b)) => return Some(Incoming::Binary(b)),
                Ok(Message::Text(_)) => return Some(Incoming::Text),
                Ok(Message::Close(_)) | Err(_) => return None,
                Ok(_) => {} // Pings and pongs are invisible to xumux.
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> MessageWriter for WsWriter<S> {
    async fn write(&mut self, message: Bytes) -> io::Result<()> {
        self.0.send(Message::Binary(message)).await.map_err(io::Error::other)
    }

    async fn close(&mut self) {
        let frame = CloseFrame { code: CloseCode::Normal, reason: "".into() };
        let _ = self.0.send(Message::Close(Some(frame))).await;
        let _ = self.0.close().await;
    }
}

/// A WebSocket message holds one frame, so the transport's limit follows the frame limit.
fn config(opts: &Options) -> WebSocketConfig {
    let max = opts.limits.max_frame_payload.max(crate::frame::CONTROL_MAX) as usize + crate::frame::HEADER_LEN;
    WebSocketConfig::default().max_message_size(Some(max)).max_frame_size(Some(max))
}

/// Answers the upgrade on an accepted connection, requiring the `xumux` subprotocol and passing the
/// `Origin` header to `allow_origin`, then runs the server side.
pub async fn accept<S>(stream: S, opts: Options, acceptor: Acceptor, allow_origin: impl Fn(Option<&str>) -> bool) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The error type is fixed by tungstenite's callback signature.
    #[allow(clippy::result_large_err)]
    let callback = |req: &Request, mut res: Response| -> std::result::Result<Response, ErrorResponse> {
        let refuse = |status: StatusCode, why: &str| {
            let mut r = ErrorResponse::new(Some(why.to_owned()));
            *r.status_mut() = status;
            r
        };
        let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
        if !allow_origin(origin) {
            return Err(refuse(StatusCode::FORBIDDEN, "origin not allowed"));
        }
        let offered = req.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !offered.split(',').any(|p| p.trim() == SUBPROTOCOL) {
            return Err(refuse(StatusCode::BAD_REQUEST, "the xumux subprotocol is required"));
        }
        res.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
        Ok(res)
    };
    let ws = tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(config(&opts)))
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    let (w, r) = ws.split();
    Session::accept_messages(WsReader(r), WsWriter(w), opts, acceptor).await
}

/// Runs the client side on an established WebSocket.
pub async fn connect<S>(ws: WebSocketStream<S>, opts: Options, acceptor: Acceptor, channels: Vec<ChannelSpec>) -> Result<(Session, Vec<Result<Channel>>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (w, r) = ws.split();
    Session::connect_messages(WsReader(r), WsWriter(w), opts, acceptor, channels).await
}

/// The `ws://` handshake for a client on an already connected stream.
pub async fn client_handshake<S>(stream: S, url: &str, opts: &Options) -> Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = url.into_client_request().map_err(|e| Error::Io(e.to_string()))?;
    req.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
    let (ws, _) = tokio_tungstenite::client_async_with_config(req, stream, Some(config(opts)))
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(ws)
}
