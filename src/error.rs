use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file '{0}': {1}")]
    Io(String, std::io::Error),
    #[error("failed to parse config file '{0}': {1}")]
    Parse(String, serde_json::Error),
    #[error("failed to serialize config: {0}")]
    Serialize(serde_json::Error),
    #[error("config has no listeners")]
    Empty,
    #[error("fake_sni too long (max 219 bytes): '{0}'")]
    SniTooLong(String),
    #[error("listener connects back to itself: {0}")]
    SelfLoop(String),
}

#[derive(Debug, Error)]
pub enum SnifferError {
    #[error("failed to open raw socket: {0}")]
    SocketOpen(std::io::Error),
    #[error("failed to bind raw socket: {0}")]
    SocketBind(std::io::Error),
    #[error("failed to attach BPF filter: {0}")]
    FilterAttach(std::io::Error),
    #[error("recv error: {0}")]
    Recv(std::io::Error),
    #[error("inject error: {0}")]
    Inject(std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("connect failed: {0}")]
    Connect(std::io::Error),
    #[error("sniffer registration failed")]
    Registration,
    #[error("timeout waiting for fake ACK confirmation")]
    Timeout,
    #[error("sniffer reported failure: {0}")]
    SnifferFailed(String),
    #[error("relay error: {0}")]
    Relay(std::io::Error),
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("could not determine local IP for any upstream")]
    NoLocalIp,
    #[error("{0}")]
    Sniffer(#[from] SnifferError),
    #[error("failed to create tokio runtime: {0}")]
    Runtime(std::io::Error),
    #[error("failed to spawn proxy thread: {0}")]
    ThreadSpawn(std::io::Error),
}

#[derive(Debug, Error)]
pub enum XrayParseError {
    #[error("empty share link")]
    Empty,
    #[error("unsupported share link scheme: {0}")]
    UnsupportedScheme(String),
    #[error("{0}")]
    UnsupportedShare(String),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid base64 payload")]
    Base64,
    #[error("invalid vmess JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing host")]
    MissingHost,
    #[error("invalid port: {0}")]
    InvalidPort(String),
}
