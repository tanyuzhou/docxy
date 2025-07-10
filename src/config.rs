use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub http_port: u16,
    pub https_port: u16,
    pub http_enabled: bool,
    pub https_enabled: bool,
    pub behind_proxy: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum RegistryApiVersion {
    #[serde(rename = "v1")]
    V1,
    #[serde(rename = "v2")]
    V2,
    #[serde(rename = "auto")]
    Auto,
}

impl Default for RegistryApiVersion {
    fn default() -> Self {
        RegistryApiVersion::Auto
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegistryConfig {
    pub url: String,
    pub api_version: RegistryApiVersion,
    pub auth_url: Option<String>,  // 认证服务URL，如果为空则使用 {url}/token
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegistrySettings {
    pub upstream_registry: String,
    #[serde(default)]
    pub registries: HashMap<String, RegistryConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsSettings {
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RegistryCredential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserSettings {
    pub password: String,
    #[serde(default)]
    pub registry_credentials: HashMap<String, RegistryCredential>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub users: HashMap<String, UserSettings>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerSettings,
    pub registry: RegistrySettings,
    pub tls: TlsSettings,
    pub auth: AuthSettings,
}

impl Settings {
    pub fn new() -> Result<Self, config::ConfigError> {
        let builder = config::Config::builder()
            .add_source(config::File::with_name("config/default"));

        builder.build()?.try_deserialize()
    }
}