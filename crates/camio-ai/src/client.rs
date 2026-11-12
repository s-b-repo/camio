//! The chat client and the pure request/response helpers (plan §11).
//!
//! [`AiClient`] owns the [`AiConfig`], a [`wreq::Client`], and a current-thread
//! tokio runtime, bridging the async client into Camio's synchronous call sites
//! exactly as `camio_request::impersonate::ImpersonatingEngine` does. The
//! request body is built with [`build_chat_body`] and the reply parsed with
//! [`parse_chat_response`]; both are pure and need no network, so the wire
//! format is unit-tested without ever making a call.
//!
//! The API key (when present) is attached as `Authorization: Bearer …` at send
//! time only and is never logged.

use std::time::Duration;

use serde_json::Value;
use wreq::Client;

use crate::config::AiConfig;
use crate::error::AiError;
use crate::message::Message;
use crate::truncate_chars;

/// Request timeout, mirroring the 90s used by the impersonating engine's client.
const REQUEST_TIMEOUT_SECS: u64 = 90;
/// Chat sampling temperature — low, because the workbench wants deterministic,
/// analytical answers rather than creative ones.
const DEFAULT_TEMPERATURE: f32 = 0.2;
/// Upper bound (characters) on the server error body kept in [`AiError::Api`].
const API_ERROR_BODY_MAX: usize = 2000;

/// Build the OpenAI chat-completions request body.
///
/// Pure and network-free: `{"model":…, "messages":[{role,content}…],
/// "temperature":…, "stream":false}`. Separated out so the exact wire shape can
/// be asserted in tests.
pub fn build_chat_body(model: &str, messages: &[Message], temperature: f32) -> Value {
    serde_json::json!({
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": false,
    })
}

/// Extract `choices[0].message.content` from a chat-completions JSON response.
///
/// Uses [`serde_json::Value`] so unrelated/extra fields are tolerated. Returns
/// [`AiError::Decode`] when the body is not JSON or has no assistant content; if
/// the body is an OpenAI-style `{"error":{"message":…}}`, that message is
/// surfaced for a clearer diagnostic.
pub fn parse_chat_response(json: &str) -> Result<String, AiError> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| AiError::Decode(format!("invalid JSON: {e}")))?;

    let content = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c0| c0.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str);

    match content {
        Some(s) => Ok(s.to_string()),
        None => {
            if let Some(err) = v.get("error") {
                let msg = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified error");
                return Err(AiError::Decode(format!(
                    "endpoint returned an error object: {msg}"
                )));
            }
            Err(AiError::Decode(
                "response had no choices[0].message.content".to_string(),
            ))
        }
    }
}

/// A ready-to-use chat client for one [`AiConfig`].
pub struct AiClient {
    config: AiConfig,
    client: Client,
    rt: tokio::runtime::Runtime,
}

impl AiClient {
    /// Build a client for `cfg`.
    ///
    /// Returns [`AiError::NotConfigured`] when the config is not ready
    /// ([`AiConfig::is_ready`] is `false`) — the assistant is off by default and
    /// will not send anything without a key (plan §11). No network call is made
    /// here; only the runtime and HTTP client are created.
    pub fn new(cfg: AiConfig) -> Result<Self, AiError> {
        if !cfg.is_ready() {
            return Err(AiError::NotConfigured(format!(
                "provider '{}' needs an API key; set its key environment variable and retry",
                cfg.provider
            )));
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| AiError::Transport(format!("tokio runtime: {e}")))?;

        let client = rt
            .block_on(async {
                Client::builder()
                    .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                    .build()
            })
            .map_err(|e| AiError::Transport(format!("building AI client: {e}")))?;

        Ok(AiClient {
            config: cfg,
            client,
            rt,
        })
    }

    /// The configuration this client was built with.
    pub fn config(&self) -> &AiConfig {
        &self.config
    }

    /// Send a chat completion and return the assistant's text.
    ///
    /// POSTs `{base_url}/chat/completions` with `Content-Type: application/json`
    /// and, when a key is present, `Authorization: Bearer {key}` (omitted for
    /// keyless endpoints such as Ollama). A non-2xx status becomes
    /// [`AiError::Api`] with the (truncated) server body.
    pub fn chat(&self, messages: &[Message]) -> Result<String, AiError> {
        self.rt.block_on(self.chat_async(messages))
    }

    async fn chat_async(&self, messages: &[Message]) -> Result<String, AiError> {
        let body = build_chat_body(&self.config.model, messages, DEFAULT_TEMPERATURE);
        let payload = serde_json::to_vec(&body)
            .map_err(|e| AiError::Transport(format!("encoding request body: {e}")))?;

        let url = format!(
            "{}/chat/completions",
            self.config.base_url.trim_end_matches('/')
        );

        let mut rb = self
            .client
            .post(url.as_str())
            .header("Content-Type", "application/json");
        // Attach the bearer token only when we have one; keyless endpoints (e.g.
        // Ollama) get no `Authorization` header. The key is used here and never
        // stored or logged.
        if let Some(key) = &self.config.api_key {
            rb = rb.header("Authorization", format!("Bearer {key}"));
        }
        rb = rb.body(payload);

        let resp = rb
            .send()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| AiError::Transport(format!("reading response: {e}")))?;

        if !(200..300).contains(&status) {
            return Err(AiError::Api {
                status,
                body: truncate_chars(&text, API_ERROR_BODY_MAX),
            });
        }

        parse_chat_response(&text)
    }

    /// Convenience wrapper: a single `system` + `user` exchange.
    pub fn complete(&self, system: &str, user: &str) -> Result<String, AiError> {
        self.chat(&[Message::system(system), Message::user(user)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_chat_body_has_expected_shape() {
        let msgs = [Message::system("sys"), Message::user("hi")];
        let body = build_chat_body("gpt-4o-mini", &msgs, 0.2);
        assert_eq!(body["model"], "gpt-4o-mini");
        assert_eq!(body["stream"], false);
        // temperature is a JSON number ~= 0.2
        assert!((body["temperature"].as_f64().expect("num") - 0.2).abs() < 1e-6);
        let arr = body["messages"].as_array().expect("messages array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["role"], "system");
        assert_eq!(arr[0]["content"], "sys");
        assert_eq!(arr[1]["role"], "user");
        assert_eq!(arr[1]["content"], "hi");
    }

    #[test]
    fn parse_chat_response_extracts_content() {
        let json = r#"{"choices":[{"message":{"role":"assistant","content":"hi"}}]}"#;
        assert_eq!(parse_chat_response(json).expect("ok"), "hi");
    }

    #[test]
    fn parse_chat_response_tolerates_extra_fields() {
        let json = r#"{
            "id":"cmpl-1","object":"chat.completion","created":123,
            "model":"gpt-4o-mini","usage":{"total_tokens":5},
            "choices":[{"index":0,"finish_reason":"stop",
                "message":{"role":"assistant","content":"answer here"}}]
        }"#;
        assert_eq!(parse_chat_response(json).expect("ok"), "answer here");
    }

    #[test]
    fn parse_chat_response_surfaces_error_object() {
        let json = r#"{"error":{"message":"invalid api key","type":"auth_error"}}"#;
        match parse_chat_response(json) {
            Err(AiError::Decode(m)) => assert!(m.contains("invalid api key"), "got: {m}"),
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn parse_chat_response_rejects_missing_content() {
        let json = r#"{"choices":[]}"#;
        assert!(matches!(parse_chat_response(json), Err(AiError::Decode(_))));
    }

    #[test]
    fn parse_chat_response_rejects_non_json() {
        assert!(matches!(
            parse_chat_response("not json at all"),
            Err(AiError::Decode(_))
        ));
    }

    #[test]
    fn new_refuses_unconfigured_provider() {
        // Custom with no key is not ready -> NotConfigured, no network touched.
        let err = AiClient::new(AiConfig::custom("http://localhost:9/v1", "m", None))
            .err()
            .expect("should be NotConfigured");
        assert!(matches!(err, AiError::NotConfigured(_)));
    }

    #[test]
    fn new_builds_for_keyless_ollama() {
        // Ollama is ready without a key; building the runtime/client makes no
        // network call, so this succeeds offline.
        let client = AiClient::new(AiConfig::ollama("llama3.1")).expect("builds");
        assert_eq!(client.config().provider, crate::Provider::Ollama);
        assert_eq!(client.config().model, "llama3.1");
    }
}
