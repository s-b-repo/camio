//! A single chat message in the OpenAI chat-completions shape (plan §11).
//!
//! Serializes to `{"role": "...", "content": "..."}`, the element shape every
//! OpenAI-compatible `messages` array uses (NVIDIA NIM, OpenAI, Ollama, …).

use serde::{Deserialize, Serialize};

/// One turn of a chat conversation. `role` is conventionally `"system"`,
/// `"user"`, or `"assistant"`; it is a plain `String` (not an enum) so an
/// uncommon role an endpoint supports still round-trips exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    /// A `system` message — instructions/persona for the model.
    pub fn system(content: impl Into<String>) -> Self {
        Message {
            role: "system".to_string(),
            content: content.into(),
        }
    }

    /// A `user` message — the human/tool turn.
    pub fn user(content: impl Into<String>) -> Self {
        Message {
            role: "user".to_string(),
            content: content.into(),
        }
    }

    /// An `assistant` message — a prior model turn (for few-shot / history).
    pub fn assistant(content: impl Into<String>) -> Self {
        Message {
            role: "assistant".to_string(),
            content: content.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_set_role_and_content() {
        assert_eq!(Message::system("be brief").role, "system");
        assert_eq!(Message::user("hi").role, "user");
        assert_eq!(Message::assistant("ok").role, "assistant");
        assert_eq!(Message::user("hi").content, "hi");
    }

    #[test]
    fn serializes_to_openai_shape() {
        let v = serde_json::to_value(Message::user("hello")).expect("serialize");
        assert_eq!(v, serde_json::json!({"role": "user", "content": "hello"}));
    }

    #[test]
    fn roundtrips_through_json() {
        let m = Message::assistant("answer");
        let s = serde_json::to_string(&m).expect("serialize");
        let back: Message = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(m, back);
    }
}
