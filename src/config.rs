use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub drand: DrandConfig,
    pub crypto: CryptoConfig,
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandConfig {
    pub base_url: String,
    pub fallback_urls: Option<Vec<String>>,
    pub quicknet: ChainConfig,
    pub mainnet: ChainConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_hash: String,
    pub public_key: String,
    pub genesis_time: u64,
    pub period: u64,
    pub scheme_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub quicknet_dst: String,
    pub mainnet_dst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub timeout_seconds: u64,
    pub max_retries: Option<u32>,
    pub retry_delay_ms: Option<u64>,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        dotenv::dotenv().ok();

        // Determine where to load config from
        let mut config_path = PathBuf::from(env::current_dir().map_err(|e| ConfigError::Message(e.to_string()))?);
        config_path.push("config.toml");

        let config = Config::builder()
            .add_source(File::from(config_path))
            .add_source(config::Environment::with_prefix("DRAND"))
            .build()?;

        config.try_deserialize()
    }
}