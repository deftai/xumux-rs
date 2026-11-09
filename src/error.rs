use std::fmt;

/// A close code and reason, as carried by CLOSE and CLOSE_CHANNEL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseInfo {
    pub code: u16,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The connection has ended.
    Closed(CloseInfo),
    /// This channel has ended.
    ChannelClosed(CloseInfo),
    /// The peer refused to open the channel.
    Refused(CloseInfo),
    /// The message is larger than the peer accepts.
    TooLarge { size: usize, limit: usize },
    /// The operation doesn't fit the channel's state or properties.
    Invalid(&'static str),
    /// A transport failure.
    Io(String),
    /// A timeout expired.
    Timeout,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Closed(c) => write!(f, "connection closed [{}] {}", c.code, c.reason),
            Error::ChannelClosed(c) => write!(f, "channel closed [{}] {}", c.code, c.reason),
            Error::Refused(c) => write!(f, "channel refused [{}] {}", c.code, c.reason),
            Error::TooLarge { size, limit } => write!(f, "message of {size} bytes exceeds the limit of {limit}"),
            Error::Invalid(m) => write!(f, "invalid operation: {m}"),
            Error::Io(m) => write!(f, "transport error: {m}"),
            Error::Timeout => write!(f, "timed out"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
