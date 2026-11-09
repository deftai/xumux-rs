//! xumux: channels for remote apps, over any transport.
//!
//! [`core`] is the protocol as a state machine with no I/O. [`Session`] runs it on tokio, over any
//! byte stream, and [`pipe`] implements the pipe/1 profile.
pub mod core;
mod error;
pub mod frame;
pub mod pipe;
mod session;
pub mod transport;

pub use crate::core::{ChannelSpec, Limits, Message, Options, ProbeStats, Properties, Refusal};
pub use crate::error::{CloseInfo, Error, Result};
pub use crate::session::{Acceptor, Channel, Session};
