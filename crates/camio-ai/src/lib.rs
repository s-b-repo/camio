//! `camio-ai` — the optional, bring-your-own-key AI assistant (plan §11,
//! "Automation & AI": "Optional local or BYO-key assistant … gated by the same
//! policy engine. No external model/telemetry by default").
//!
//! Camio never contacts a model on its own. This crate is an
//! OpenAI-*chat-completions*-compatible client so a user who opts in can point
//! Camio at NVIDIA NIM, OpenAI, a local Ollama, or any compatible endpoint to
//! summarize project data and propose next tests. It is **off by default**, and
//! a live call needs an explicit API key (except Ollama, which needs none):
//! [`AiConfig::is_ready`] is the gate and [`AiClient::new`] refuses a config
//! that is not ready, so nothing leaves the machine until the user supplies a
//! key and asks for it.
//!
//! ## Secrets (plan §11: "No external model/telemetry by default")
//!
//! The API key is read from a provider-specific environment variable
//! ([`AiConfig::nvidia_nim`] reads `NVIDIA_API_KEY`, [`AiConfig::openai`] reads
//! `OPENAI_API_KEY`) and is **never logged or printed**:
//!
//! * [`AiConfig`]'s `Debug` implementation redacts the key.
//! * [`AiConfig`] is deliberately **not** `Serialize`/`Deserialize`, so the key
//!   cannot be written to a project file, log, or wire dump by accident.
//! * The `Authorization: Bearer …` header is built only at send time and is
//!   dropped immediately after.
//! * No [`AiError`] variant ever carries the key (the error body we keep is the
//!   *server's* response, not our request).
//!
//! ## Layout
//!
//! * [`config`] — [`Provider`] and [`AiConfig`] (presets + environment
//!   discovery).
//! * [`error`] — the typed [`AiError`] (`impl Display + std::error::Error`).
//! * [`message`] — the chat [`Message`] and its role helpers.
//! * [`client`] — [`AiClient`] plus the pure, network-free [`build_chat_body`]
//!   and [`parse_chat_response`] helpers it (and its tests) use.
//! * [`prompt`] — pure workbench prompt builders ([`explain_exchange`],
//!   [`suggest_tests`], [`nl_to_camioql`]).

pub mod client;
pub mod config;
pub mod error;
pub mod message;
pub mod prompt;

pub use client::{build_chat_body, parse_chat_response, AiClient};
pub use config::{AiConfig, Provider};
pub use error::AiError;
pub use message::Message;
pub use prompt::{explain_exchange, nl_to_camioql, suggest_tests};

/// Truncate `s` to at most `max` characters (UTF-8 safe), appending a short
/// marker when any content was dropped.
///
/// Used to bound both the raw request/response dumps that go into a prompt and
/// the server error body we keep in [`AiError::Api`], so neither the model
/// context nor an error value can grow without limit. Truncation is on a
/// character boundary so the result is always valid UTF-8.
pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    for (count, (idx, _)) in s.char_indices().enumerate() {
        if count == max {
            let mut out = String::with_capacity(idx + 12);
            out.push_str(&s[..idx]);
            out.push_str("…[truncated]");
            return out;
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::truncate_chars;

    #[test]
    fn truncate_keeps_short_strings_verbatim() {
        assert_eq!(truncate_chars("hello", 10), "hello");
        // Exactly `max` characters is not truncated.
        assert_eq!(truncate_chars("hello", 5), "hello");
    }

    #[test]
    fn truncate_bounds_long_strings() {
        let out = truncate_chars("abcdef", 3);
        assert!(out.starts_with("abc"));
        assert!(out.contains("[truncated]"));
        // The dropped tail is gone (checked as a substring — the "[truncated]"
        // marker itself contains the letters d/e, so a single-char check lies).
        assert!(!out.contains("def"));
    }

    #[test]
    fn truncate_is_utf8_safe_on_multibyte_input() {
        // Each `é` is two bytes; truncating at 2 chars must land on a boundary.
        let out = truncate_chars("éééé", 2);
        assert!(out.starts_with("éé"));
        assert!(out.contains("[truncated]"));
        // Result must still be valid UTF-8 (String guarantees it; this asserts
        // we did not slice mid-codepoint, which would have panicked above).
        assert!(out.is_char_boundary(out.len()));
    }
}
