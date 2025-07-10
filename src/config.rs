use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub http_port: u16,
    pub https_port: u16,
    pub http_enabled: bool,
    pub https_enabled: bool,
    pub behind_proxy: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegistrySettings {
    pub upstream_registry: String,
    pub registry_mapping: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsSettings {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerSettings,
    pub registry: RegistrySettings,
    pub tls: TlsSettings,
}

impl Settings {
    pub fn new() -> Result<Self, config::ConfigError> {
        let builder = config::Config::builder()
            .add_source(config::File::with_name("config/default"));

        builder.build()?.try_deserialize()
    }
}