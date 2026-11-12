//! Provider presets and configuration for the AI assistant (plan §11).
//!
//! An [`AiConfig`] names an OpenAI-compatible endpoint (base URL + model) and,
//! for providers that require it, an API key read from the environment. The key
//! is never logged: [`AiConfig`] has a redacting `Debug` and is intentionally
//! not `Serialize`/`Deserialize` so it cannot be persisted by accident (plan
//! §11: "No external model/telemetry by default").

use std::fmt;

use serde::{Deserialize, Serialize};

const NVIDIA_BASE_URL: &str = "https://integrate.api.nvidia.com/v1";
const OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
const OLLAMA_BASE_URL: &str = "http://localhost:11434/v1";

/// Which OpenAI-chat-compatible backend a config points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// NVIDIA NIM (`integrate.api.nvidia.com`), key from `NVIDIA_API_KEY`.
    NvidiaNim,
    /// OpenAI (`api.openai.com`), key from `OPENAI_API_KEY`.
    OpenAi,
    /// A local Ollama server (`localhost:11434`), no key required.
    Ollama,
    /// Any other OpenAI-compatible endpoint, configured explicitly.
    Custom,
}

impl Provider {
    /// Stable lower-snake token (matches the serde representation and the
    /// `CAMIO_AI_PROVIDER` values).
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::NvidiaNim => "nvidia_nim",
            Provider::OpenAi => "openai",
            Provider::Ollama => "ollama",
            Provider::Custom => "custom",
        }
    }

    /// The environment variable this provider reads its API key from, if any.
    fn key_env(self) -> Option<&'static str> {
        match self {
            Provider::NvidiaNim => Some("NVIDIA_API_KEY"),
            Provider::OpenAi => Some("OPENAI_API_KEY"),
            Provider::Ollama | Provider::Custom => None,
        }
    }

    /// A sane default model name for the provider, used when
    /// `CAMIO_AI_MODEL` is unset.
    fn default_model(self) -> &'static str {
        match self {
            Provider::NvidiaNim => "meta/llama-3.1-70b-instruct",
            Provider::OpenAi => "gpt-4o-mini",
            Provider::Ollama | Provider::Custom => "llama3.1",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolved AI endpoint: provider, base URL, model, and an optional API key.
///
/// The key is a secret: this type has a **redacting `Debug`** and is **not**
/// `Serialize`/`Deserialize` so it never reaches a log, a project file, or a
/// wire dump by accident (plan §11).
#[derive(Clone, PartialEq, Eq)]
pub struct AiConfig {
    pub provider: Provider,
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
}

impl AiConfig {
    /// NVIDIA NIM preset. Reads the key from `NVIDIA_API_KEY`.
    pub fn nvidia_nim(model: impl Into<String>) -> Self {
        AiConfig {
            provider: Provider::NvidiaNim,
            base_url: NVIDIA_BASE_URL.to_string(),
            model: model.into(),
            api_key: env_nonempty("NVIDIA_API_KEY"),
        }
    }

    /// OpenAI preset. Reads the key from `OPENAI_API_KEY`.
    pub fn openai(model: impl Into<String>) -> Self {
        AiConfig {
            provider: Provider::OpenAi,
            base_url: OPENAI_BASE_URL.to_string(),
            model: model.into(),
            api_key: env_nonempty("OPENAI_API_KEY"),
        }
    }

    /// Local Ollama preset. No key (Ollama needs none).
    pub fn ollama(model: impl Into<String>) -> Self {
        AiConfig {
            provider: Provider::Ollama,
            base_url: OLLAMA_BASE_URL.to_string(),
            model: model.into(),
            api_key: None,
        }
    }

    /// An arbitrary OpenAI-compatible endpoint, configured explicitly.
    pub fn custom(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        AiConfig {
            provider: Provider::Custom,
            base_url: base_url.into(),
            model: model.into(),
            api_key,
        }
    }

    /// Discover a config from the environment (plan §11, opt-in):
    ///
    /// * provider from `CAMIO_AI_PROVIDER` (`nvidia_nim` | `openai` | `ollama`),
    ///   else the first provider whose key env var is set, else Ollama;
    /// * model from `CAMIO_AI_MODEL` if set, else the provider default.
    pub fn from_env() -> Self {
        let provider = provider_from_env();
        let model =
            env_nonempty("CAMIO_AI_MODEL").unwrap_or_else(|| provider.default_model().to_string());
        match provider {
            Provider::OpenAi => Self::openai(model),
            Provider::NvidiaNim => Self::nvidia_nim(model),
            // Ollama is the documented fallback. `provider_from_env` never
            // returns `Custom`, so mapping it here is only defensive (and avoids
            // a panic — the crate forbids `unreachable!`/`unwrap` in non-test
            // code).
            Provider::Ollama | Provider::Custom => Self::ollama(model),
        }
    }

    /// Whether a live call can be made: a key is present, or the provider needs
    /// none (Ollama). This is the on/off gate — [`crate::AiClient::new`] refuses
    /// a config for which this is `false`.
    pub fn is_ready(&self) -> bool {
        self.api_key.is_some() || matches!(self.provider, Provider::Ollama)
    }
}

/// Redacting `Debug`: prints presence of the key, never its value.
impl fmt::Debug for AiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiConfig")
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Read an environment variable, treating unset *and* blank as absent.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Resolve the provider per [`AiConfig::from_env`]'s rules.
fn provider_from_env() -> Provider {
    match env_nonempty("CAMIO_AI_PROVIDER").as_deref() {
        Some("nvidia_nim") => return Provider::NvidiaNim,
        Some("openai") => return Provider::OpenAi,
        Some("ollama") => return Provider::Ollama,
        _ => {}
    }
    // No explicit choice (or an unrecognized one): pick the first provider whose
    // key env var is set, else fall back to the keyless local Ollama.
    if Provider::NvidiaNim
        .key_env()
        .and_then(env_nonempty)
        .is_some()
    {
        Provider::NvidiaNim
    } else if Provider::OpenAi.key_env().and_then(env_nonempty).is_some() {
        Provider::OpenAi
    } else {
        Provider::Ollama
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Environment variables are process-global; serialize every test that reads
    // or writes them so parallel test threads do not race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_ai_env() {
        for k in [
            "CAMIO_AI_PROVIDER",
            "CAMIO_AI_MODEL",
            "NVIDIA_API_KEY",
            "OPENAI_API_KEY",
        ] {
            std::env::remove_var(k);
        }
    }

    // ----- presets: base_url/model/provider are deterministic (no env) -------

    #[test]
    fn nvidia_preset_sets_base_url_and_model() {
        let c = AiConfig::nvidia_nim("meta/llama-3.1-70b-instruct");
        assert_eq!(c.provider, Provider::NvidiaNim);
        assert_eq!(c.base_url, "https://integrate.api.nvidia.com/v1");
        assert_eq!(c.model, "meta/llama-3.1-70b-instruct");
    }

    #[test]
    fn openai_preset_sets_base_url_and_model() {
        let c = AiConfig::openai("gpt-4o-mini");
        assert_eq!(c.provider, Provider::OpenAi);
        assert_eq!(c.base_url, "https://api.openai.com/v1");
        assert_eq!(c.model, "gpt-4o-mini");
    }

    #[test]
    fn ollama_preset_has_no_key_and_is_ready() {
        let c = AiConfig::ollama("llama3.1");
        assert_eq!(c.provider, Provider::Ollama);
        assert_eq!(c.base_url, "http://localhost:11434/v1");
        assert_eq!(c.model, "llama3.1");
        assert!(c.api_key.is_none());
        assert!(c.is_ready(), "Ollama needs no key");
    }

    #[test]
    fn custom_preset_passes_fields_through() {
        let c = AiConfig::custom("http://box:8000/v1", "my-model", Some("k".into()));
        assert_eq!(c.provider, Provider::Custom);
        assert_eq!(c.base_url, "http://box:8000/v1");
        assert_eq!(c.model, "my-model");
        assert_eq!(c.api_key.as_deref(), Some("k"));
    }

    // ----- is_ready logic ----------------------------------------------------

    #[test]
    fn is_ready_requires_key_except_ollama() {
        // Keyed provider with a key -> ready.
        let ready = AiConfig {
            provider: Provider::NvidiaNim,
            base_url: NVIDIA_BASE_URL.into(),
            model: "m".into(),
            api_key: Some("k".into()),
        };
        assert!(ready.is_ready());

        // Keyed provider without a key -> not ready.
        let not_ready = AiConfig {
            provider: Provider::NvidiaNim,
            base_url: NVIDIA_BASE_URL.into(),
            model: "m".into(),
            api_key: None,
        };
        assert!(!not_ready.is_ready());

        // Custom without a key -> not ready.
        assert!(!AiConfig::custom("http://x/v1", "m", None).is_ready());
        // Custom with a key -> ready.
        assert!(AiConfig::custom("http://x/v1", "m", Some("k".into())).is_ready());
        // Ollama is always ready.
        assert!(AiConfig::ollama("m").is_ready());
    }

    // ----- Debug never prints the key ---------------------------------------

    #[test]
    fn debug_redacts_api_key() {
        let c = AiConfig::custom("http://x/v1", "m", Some("super-secret-token".into()));
        let shown = format!("{c:?}");
        assert!(!shown.contains("super-secret-token"), "key leaked: {shown}");
        assert!(shown.contains("redacted"));
        // A keyless config shows `None`, not a fake redaction.
        let none = format!("{:?}", AiConfig::ollama("m"));
        assert!(none.contains("None"));
    }

    // ----- env-dependent behavior (serialized via ENV_LOCK) ------------------

    #[test]
    fn nvidia_reads_key_from_env() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_ai_env();
        std::env::set_var("NVIDIA_API_KEY", "nv-123");
        let c = AiConfig::nvidia_nim("m");
        assert_eq!(c.api_key.as_deref(), Some("nv-123"));
        clear_ai_env();
    }

    #[test]
    fn blank_env_key_counts_as_absent() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_ai_env();
        std::env::set_var("OPENAI_API_KEY", "   ");
        let c = AiConfig::openai("m");
        assert!(c.api_key.is_none(), "blank key must be treated as unset");
        assert!(!c.is_ready());
        clear_ai_env();
    }

    #[test]
    fn from_env_honors_explicit_provider_and_default_model() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_ai_env();
        std::env::set_var("CAMIO_AI_PROVIDER", "ollama");
        let c = AiConfig::from_env();
        assert_eq!(c.provider, Provider::Ollama);
        assert_eq!(c.model, "llama3.1");
        clear_ai_env();
    }

    #[test]
    fn from_env_model_override_wins() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_ai_env();
        std::env::set_var("CAMIO_AI_PROVIDER", "openai");
        std::env::set_var("CAMIO_AI_MODEL", "gpt-4o");
        let c = AiConfig::from_env();
        assert_eq!(c.provider, Provider::OpenAi);
        assert_eq!(c.model, "gpt-4o");
        clear_ai_env();
    }

    #[test]
    fn from_env_picks_provider_by_present_key() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_ai_env();
        // No explicit provider, but an OpenAI key is set.
        std::env::set_var("OPENAI_API_KEY", "sk-abc");
        let c = AiConfig::from_env();
        assert_eq!(c.provider, Provider::OpenAi);
        assert_eq!(c.model, "gpt-4o-mini");
        assert_eq!(c.api_key.as_deref(), Some("sk-abc"));
        clear_ai_env();
    }

    #[test]
    fn from_env_falls_back_to_ollama() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_ai_env();
        let c = AiConfig::from_env();
        assert_eq!(c.provider, Provider::Ollama);
        assert!(c.is_ready());
        clear_ai_env();
    }

    #[test]
    fn provider_as_str_matches_serde() {
        assert_eq!(Provider::NvidiaNim.as_str(), "nvidia_nim");
        assert_eq!(
            serde_json::to_value(Provider::NvidiaNim).expect("serialize"),
            serde_json::json!("nvidia_nim")
        );
        assert_eq!(Provider::OpenAi.as_str(), "openai");
        assert_eq!(Provider::Ollama.as_str(), "ollama");
        assert_eq!(Provider::Custom.as_str(), "custom");
    }
}
