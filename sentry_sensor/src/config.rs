use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SentryConfig {
    #[serde(skip)]
    pub nats_password: Option<String>,

    /// NATS username. The password is stored in the OS credential store.
    pub nats_username: String,

    /// Run without the desktop GUI (headless capture agent).
    pub headless: bool,

    /// NATS server URL for telemetry export (e.g. nats://127.0.0.1:4222).
    pub nats_url: String,

    /// NATS subject to publish flow records to.
    pub subject: String,

    /// Console registration identifier used for health and attribution.
    pub sensor_id: Option<String>,

    /// Network device to capture on ("any" on Linux).
    pub device: String,

    /// Kill switch — NEVER enabled by default (blocks outbound traffic).
    pub kill_switch_active: bool,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            nats_password: None,
            nats_username: String::new(),
            headless: false,
            nats_url: "nats://127.0.0.1:4222".to_string(),
            subject: "sentry.flows".to_string(),
            sensor_id: None,
            device: "any".to_string(),
            kill_switch_active: false,
        }
    }
}

impl SentryConfig {
    fn config_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("sentry_sensor");
        if !path.exists() {
            fs::create_dir_all(&path).unwrap_or_default();
        }
        path.push("config.json");
        path
    }

    fn get_keyring_entry() -> Result<Entry, String> {
        Entry::new("attacksentry_sensor", "nats_password").map_err(|e| e.to_string())
    }

    pub fn load() -> Self {
        let mut config = Self::default();

        let path = Self::config_path();
        if path.exists() {
            if let Ok(contents) = fs::read_to_string(&path) {
                if let Ok(loaded) = serde_json::from_str::<SentryConfig>(&contents) {
                    config = loaded;
                }
            }
        }

        if let Ok(entry) = Self::get_keyring_entry() {
            if let Ok(token) = entry.get_password() {
                config.nats_password = Some(token);
            }
        }

        // Environment overrides (used in containerized deployments).
        if let Ok(v) = std::env::var("SENTRY_NATS_URL") {
            config.nats_url = v;
        }
        if let Ok(v) = std::env::var("SENTRY_NATS_USERNAME") {
            config.nats_username = v;
        }
        if let Ok(v) = std::env::var("SENTRY_NATS_PASSWORD") {
            config.nats_password = Some(v);
        }
        if let Ok(v) = std::env::var("SENTRY_SUBJECT") {
            config.subject = v;
        }
        if let Ok(v) = std::env::var("SENTRY_SENSOR_ID") {
            config.sensor_id = Some(v);
        }
        if let Ok(v) = std::env::var("SENTRY_DEVICE") {
            config.device = v;
        }
        if let Ok(v) = std::env::var("SENTRY_HEADLESS") {
            config.headless = v == "1" || v == "true";
        }
        if let Ok(v) = std::env::var("SENTRY_KILL_SWITCH") {
            config.kill_switch_active = v == "1" || v == "true";
        }

        config
    }

    pub fn save(&self) {
        let path = Self::config_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }

        if let Ok(entry) = Self::get_keyring_entry() {
            match &self.nats_password {
                Some(token) => {
                    let _ = entry.set_password(token);
                }
                None => {
                    let _ = entry.delete_password();
                }
            }
        }
    }
}
