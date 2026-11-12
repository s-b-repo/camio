//! The typed error for the AI assistant (plan §11).
//!
//! Mirrors the project convention (e.g. `camio_request::RequestError`): a small
//! enum that `impl`s [`Display`](std::fmt::Display) and
//! [`std::error::Error`]. No variant ever carries the API key — the only body we
//! retain is the *server's* response text in [`AiError::Api`], which is the
//! endpoint's reply, not our `Authorization` header.

use std::fmt;

/// Something went wrong configuring or calling the AI endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiError {
    /// The assistant is off / not ready: no API key for a provider that needs
    /// one, so no call was attempted (plan §11: off by default).
    NotConfigured(String),
    /// A transport/IO/TLS error while building the client or sending the request
    /// (connection refused, timeout, DNS, …).
    Transport(String),
    /// The endpoint answered with a non-2xx status. `body` is the server's
    /// response, truncated so the error stays bounded.
    Api { status: u16, body: String },
    /// A 2xx response whose JSON could not be parsed into a chat completion.
    Decode(String),
}

impl fmt::Display for AiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiError::NotConfigured(s) => write!(f, "AI assistant not configured: {s}"),
            AiError::Transport(s) => write!(f, "AI transport error: {s}"),
            AiError::Api { status, body } => {
                write!(f, "AI endpoint returned HTTP {status}: {body}")
            }
            AiError::Decode(s) => write!(f, "AI response decode error: {s}"),
        }
    }
}

impl std::error::Error for AiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_prefixed_per_variant() {
        assert_eq!(
            AiError::NotConfigured("no key".into()).to_string(),
            "AI assistant not configured: no key"
        );
        assert_eq!(
            AiError::Transport("connection refused".into()).to_string(),
            "AI transport error: connection refused"
        );
        assert_eq!(
            AiError::Api {
                status: 401,
                body: "unauthorized".into(),
            }
            .to_string(),
            "AI endpoint returned HTTP 401: unauthorized"
        );
        assert_eq!(
            AiError::Decode("no choices".into()).to_string(),
            "AI response decode error: no choices"
        );
    }

    #[test]
    fn is_std_error() {
        // Confirms the trait object builds (the enum is a real `Error`).
        let e: Box<dyn std::error::Error> = Box::new(AiError::Decode("x".into()));
        assert_eq!(e.to_string(), "AI response decode error: x");
    }
}
