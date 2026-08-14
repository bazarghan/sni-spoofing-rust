use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

fn default_conn_timeout_sec() -> u64 {
    5
}

fn default_handshake_timeout_sec() -> u64 {
    2
}

fn default_keepalive_time_sec() -> u64 {
    11
}

fn default_keepalive_interval_sec() -> u64 {
    2
}

fn default_buffer_size() -> usize {
    64
}

fn default_graceful_shutdown_sec() -> u64 {
    0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub idle_timeout: Option<u64>,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    pub listeners: Vec<ListenerConfig>,
    #[serde(default = "default_graceful_shutdown_sec")]
    pub graceful_shutdown_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub listen: SocketAddr,
    pub connect: SocketAddr,
    pub fake_sni: String,
    #[serde(default = "default_conn_timeout_sec")]
    pub conn_timeout_sec: u64,
    #[serde(default = "default_handshake_timeout_sec")]
    pub handshake_timeout_sec: u64,
    #[serde(default = "default_keepalive_time_sec")]
    pub keepalive_time_sec: u64,
    #[serde(default = "default_keepalive_interval_sec")]
    pub keepalive_interval_sec: u64,
}

pub fn load(path: &str) -> Result<Config, crate::error::ConfigError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| crate::error::ConfigError::Io(path.to_string(), e))?;
    load_from_str(path, &data)
}

pub fn load_from_str(path: &str, data: &str) -> Result<Config, crate::error::ConfigError> {
    let cfg: Config = serde_json::from_str(data)
        .map_err(|e| crate::error::ConfigError::Parse(path.to_string(), e))?;
    validate(&cfg)?;
    Ok(cfg)
}

pub fn validate(cfg: &Config) -> Result<(), crate::error::ConfigError> {
    if cfg.listeners.is_empty() {
        return Err(crate::error::ConfigError::Empty);
    }
    for lc in &cfg.listeners {
        if lc.fake_sni.len() > 219 {
            return Err(crate::error::ConfigError::SniTooLong(lc.fake_sni.clone()));
        }
        if connects_to_listener(lc.listen, lc.connect) {
            return Err(crate::error::ConfigError::SelfLoop(format!(
                "{} -> {}",
                lc.listen, lc.connect
            )));
        }
    }
    Ok(())
}

fn connects_to_listener(listen: SocketAddr, connect: SocketAddr) -> bool {
    if listen == connect {
        return true;
    }

    connect.port() == listen.port()
        && connect.ip().is_loopback()
        && (listen.ip().is_loopback() || listen.ip().is_unspecified())
}

pub fn to_pretty_json(cfg: &Config) -> Result<String, crate::error::ConfigError> {
    serde_json::to_string_pretty(cfg).map_err(crate::error::ConfigError::Serialize)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle_timeout: None,
            buffer_size: default_buffer_size(),
            listeners: vec![ListenerConfig::default()],
            graceful_shutdown_sec: default_graceful_shutdown_sec(),
        }
    }
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:40443".parse().unwrap(),
            connect: "172.67.139.236:443".parse().unwrap(),
            fake_sni: "security.vercel.com".into(),
            conn_timeout_sec: default_conn_timeout_sec(),
            handshake_timeout_sec: default_handshake_timeout_sec(),
            keepalive_time_sec: default_keepalive_time_sec(),
            keepalive_interval_sec: default_keepalive_interval_sec(),
        }
    }
}
