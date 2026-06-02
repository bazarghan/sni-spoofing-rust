use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;
use url::Url;

use crate::error::XrayParseError;

#[derive(Clone, Debug)]
pub struct XrayShare {
    pub protocol: String,
    pub name: Option<String>,
    pub user_id: Option<String>,
    pub host: String,
    pub port: u16,
    pub security: Option<String>,
    pub encryption: Option<String>,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    pub network: Option<String>,
    pub fingerprint: Option<String>,
    pub path: Option<String>,
    pub mode: Option<String>,
    pub allow_insecure: bool,
    pub tls: bool,
}

impl XrayShare {
    pub fn label(&self) -> String {
        self.name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.host)
            .to_string()
    }

    pub fn endpoint_is_local(&self) -> bool {
        is_local_host(&self.host)
    }

    pub fn upstream_host(&self) -> &str {
        if self.endpoint_is_local() {
            self.http_host
                .as_deref()
                .or(self.sni.as_deref())
                .unwrap_or(&self.host)
        } else {
            &self.host
        }
    }

    pub fn upstream_port(&self) -> u16 {
        if self.endpoint_is_local() {
            if self.tls {
                443
            } else {
                80
            }
        } else {
            self.port
        }
    }
}

pub fn parse_share_link(input: &str) -> Result<XrayShare, XrayParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(XrayParseError::Empty);
    }

    if trimmed.starts_with("v2rayn://") {
        parse_v2rayn_wrapper(trimmed)
    } else if trimmed.starts_with("vmess://") {
        parse_vmess(trimmed)
    } else {
        parse_url_style(trimmed)
    }
}

pub fn resolve_share_host(share: &XrayShare) -> Result<Vec<SocketAddr>, std::io::Error> {
    (share.host.as_str(), share.port)
        .to_socket_addrs()
        .map(|iter| iter.collect())
}

pub fn resolve_upstream_host(share: &XrayShare) -> Result<Vec<SocketAddr>, std::io::Error> {
    (share.upstream_host(), share.upstream_port())
        .to_socket_addrs()
        .map(|iter| iter.collect())
}

fn is_local_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback() || ip.is_unspecified())
            .unwrap_or(false)
}

fn parse_url_style(input: &str) -> Result<XrayShare, XrayParseError> {
    let url = Url::parse(input)?;
    let protocol = url.scheme().to_ascii_lowercase();
    if !matches!(protocol.as_str(), "vless" | "trojan") {
        return Err(XrayParseError::UnsupportedScheme(protocol));
    }

    let host = url
        .host_str()
        .ok_or(XrayParseError::MissingHost)?
        .to_string();
    let query = url.query_pairs().collect::<Vec<_>>();
    let tls = query
        .iter()
        .any(|(k, v)| k == "security" && v.eq_ignore_ascii_case("tls"));
    let port = url.port().unwrap_or(if tls { 443 } else { 80 });
    let sni = query
        .iter()
        .find(|(k, _)| k == "sni")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let http_host = query
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let network = query
        .iter()
        .find(|(k, _)| k == "type")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let fingerprint = query
        .iter()
        .find(|(k, _)| k == "fp")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let path = query
        .iter()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let mode = query
        .iter()
        .find(|(k, _)| k == "mode")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let security = query
        .iter()
        .find(|(k, _)| k == "security")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let encryption = query
        .iter()
        .find(|(k, _)| k == "encryption")
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty());
    let allow_insecure = query.iter().any(|(k, v)| {
        matches!(k.as_ref(), "allowInsecure" | "insecure") && matches!(v.as_ref(), "1" | "true")
    });
    let name = url
        .fragment()
        .map(|f| f.trim().to_string())
        .filter(|v| !v.is_empty());

    Ok(XrayShare {
        protocol,
        name,
        user_id: Some(url.username().trim().to_string()).filter(|v| !v.is_empty()),
        host,
        port,
        security,
        encryption,
        sni,
        http_host,
        network,
        fingerprint,
        path,
        mode,
        allow_insecure,
        tls,
    })
}

fn parse_v2rayn_wrapper(input: &str) -> Result<XrayShare, XrayParseError> {
    let url = Url::parse(input)?;
    let profile_kind = url.host_str().unwrap_or_default().to_ascii_lowercase();
    match profile_kind.as_str() {
        "shadowsocks" | "ss" => Err(XrayParseError::UnsupportedShare(
            "v2rayN Shadowsocks links are not supported here; use a VLESS/Trojan Cloudflare link"
                .into(),
        )),
        "vless" | "trojan" | "vmess" => Err(XrayParseError::UnsupportedShare(format!(
            "v2rayN wrapped {} links are not supported; export/paste the normal {}:// link",
            profile_kind, profile_kind
        ))),
        "" => Err(XrayParseError::UnsupportedScheme("v2rayn".into())),
        other => Err(XrayParseError::UnsupportedScheme(format!(
            "v2rayn://{}",
            other
        ))),
    }
}

fn parse_vmess(input: &str) -> Result<XrayShare, XrayParseError> {
    let payload = input.trim_start_matches("vmess://").trim();
    let bytes = decode_base64(payload)?;
    let value: Value = serde_json::from_slice(&bytes)?;

    let host = value
        .get("add")
        .and_then(Value::as_str)
        .ok_or(XrayParseError::MissingHost)?
        .to_string();
    let port = match value.get("port") {
        Some(Value::String(s)) => s
            .parse::<u16>()
            .map_err(|_| XrayParseError::InvalidPort(s.clone()))?,
        Some(Value::Number(n)) => n
            .as_u64()
            .filter(|n| *n <= u16::MAX as u64)
            .map(|n| n as u16)
            .ok_or_else(|| XrayParseError::InvalidPort(n.to_string()))?,
        _ => 443,
    };

    let tls = value
        .get("tls")
        .and_then(Value::as_str)
        .map(|v| v.eq_ignore_ascii_case("tls"))
        .unwrap_or(false);

    Ok(XrayShare {
        protocol: "vmess".into(),
        name: value
            .get("ps")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        user_id: value
            .get("id")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        host,
        port,
        security: value
            .get("tls")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        encryption: None,
        sni: value
            .get("sni")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        http_host: value
            .get("host")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        network: value
            .get("net")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        fingerprint: value
            .get("fp")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        path: value
            .get("path")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        mode: None,
        allow_insecure: false,
        tls,
    })
}

fn decode_base64(payload: &str) -> Result<Vec<u8>, XrayParseError> {
    let padded = pad_base64(payload);
    STANDARD
        .decode(padded.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(payload.as_bytes()))
        .map_err(|_| XrayParseError::Base64)
}

fn pad_base64(input: &str) -> String {
    let mut out = input.trim().replace(['\n', '\r', ' '], "");
    let rem = out.len() % 4;
    if rem != 0 {
        for _ in 0..(4 - rem) {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    use super::*;

    #[test]
    fn parses_vless_cloudflare_style_link() {
        let link = "vless://uuid@example.com:443?security=tls&type=ws&host=edge.example.com&sni=real.example.com#sample";
        let share = parse_share_link(link).unwrap();
        assert_eq!(share.protocol, "vless");
        assert_eq!(share.host, "example.com");
        assert_eq!(share.port, 443);
        assert_eq!(share.user_id.as_deref(), Some("uuid"));
        assert_eq!(share.network.as_deref(), Some("ws"));
        assert_eq!(share.http_host.as_deref(), Some("edge.example.com"));
        assert_eq!(share.sni.as_deref(), Some("real.example.com"));
        assert_eq!(share.name.as_deref(), Some("sample"));
        assert!(share.tls);
    }

    #[test]
    fn parses_cloudip_generated_vless_link() {
        let link = "vless://uuid@172.64.82.114:443?encryption=none&security=tls&sni=cf.cloudip.ggff.net&fp=random&insecure=0&allowInsecure=0&type=ws&host=cf.cloudip.ggff.net&path=pyip%3Dproxyip.cmliussss.net#sample";
        let share = parse_share_link(link).unwrap();
        assert_eq!(share.protocol, "vless");
        assert_eq!(share.host, "172.64.82.114");
        assert_eq!(share.port, 443);
        assert_eq!(share.user_id.as_deref(), Some("uuid"));
        assert_eq!(share.network.as_deref(), Some("ws"));
        assert_eq!(share.http_host.as_deref(), Some("cf.cloudip.ggff.net"));
        assert_eq!(share.sni.as_deref(), Some("cf.cloudip.ggff.net"));
        assert_eq!(share.fingerprint.as_deref(), Some("random"));
        assert_eq!(share.path.as_deref(), Some("pyip=proxyip.cmliussss.net"));
        assert_eq!(share.name.as_deref(), Some("sample"));
        assert!(share.tls);
    }

    #[test]
    fn local_rewritten_vless_uses_host_as_upstream() {
        let link = "vless://uuid@127.0.0.1:40443?mode=auto&path=%2FGoOgLe&security=tls&encryption=none&host=tom.dnstt.space&fp=chrome&type=xhttp&sni=tom.dnstt.space#NET_SPOOF";
        let share = parse_share_link(link).unwrap();
        assert_eq!(share.protocol, "vless");
        assert_eq!(share.host, "127.0.0.1");
        assert_eq!(share.port, 40443);
        assert!(share.endpoint_is_local());
        assert_eq!(share.upstream_host(), "tom.dnstt.space");
        assert_eq!(share.upstream_port(), 443);
        assert_eq!(share.network.as_deref(), Some("xhttp"));
        assert_eq!(share.mode.as_deref(), Some("auto"));
        assert_eq!(share.path.as_deref(), Some("/GoOgLe"));
    }

    #[test]
    fn parses_local_rewritten_trojan_link() {
        let link = "trojan://humanity@127.0.0.1:40443?path=%2Fassignment&security=tls&host=www.ignitelimit.com&type=ws&sni=www.ignitelimit.com#NET_SPOOF";
        let share = parse_share_link(link).unwrap();
        assert_eq!(share.protocol, "trojan");
        assert_eq!(share.user_id.as_deref(), Some("humanity"));
        assert_eq!(share.upstream_host(), "www.ignitelimit.com");
        assert_eq!(share.upstream_port(), 443);
        assert_eq!(share.network.as_deref(), Some("ws"));
        assert_eq!(share.path.as_deref(), Some("/assignment"));
    }

    #[test]
    fn parses_vmess_cloudflare_style_link() {
        let json = r#"{
            "v": "2",
            "ps": "sample",
            "id": "uuid",
            "add": "cf.example.com",
            "port": "443",
            "net": "ws",
            "type": "none",
            "host": "edge.example.com",
            "path": "/",
            "tls": "tls",
            "sni": "real.example.com"
        }"#;
        let link = format!("vmess://{}", STANDARD.encode(json));
        let share = parse_share_link(&link).unwrap();
        assert_eq!(share.protocol, "vmess");
        assert_eq!(share.host, "cf.example.com");
        assert_eq!(share.port, 443);
        assert_eq!(share.user_id.as_deref(), Some("uuid"));
        assert_eq!(share.network.as_deref(), Some("ws"));
        assert_eq!(share.http_host.as_deref(), Some("edge.example.com"));
        assert_eq!(share.sni.as_deref(), Some("real.example.com"));
        assert_eq!(share.path.as_deref(), Some("/"));
        assert_eq!(share.name.as_deref(), Some("sample"));
        assert!(share.tls);
    }

    #[test]
    fn rejects_v2rayn_shadowsocks_with_helpful_error() {
        let link = "v2rayn://shadowsocks/eyJJbmRleElkIjoiNFdQNFhRIiwiQ29uZmlnVHlwZSI6MywiQ29uZmlnVmVyc2lvbiI6NCwiRGlzcGxheUxvZyI6dHJ1ZSwiUmVtYXJrcyI6Ilx1RDgzRFx1REQxMiBTUy1UQ1AtTkEgXHVEODNDXHVEREVFXHVEODNDXHVEREY3IElSLTEwOS4xMjIuMjUxLjg0OjgwIiwiQWRkcmVzcyI6IjEwOS4xMjIuMjUxLjg0IiwiUG9ydCI6ODAsIlBhc3N3b3JkIjoiWXVSdDZBWDlQNE5pdXRUd29ETXZEVHJ4SWpvX2xzR3IiLCJBbHRlcklkIjowLCJQcm90b0V4dHJhT2JqIjp7IlNzTWV0aG9kIjoiY2hhY2hhMjAtaWV0Zi1wb2x5MTMwNSJ9fQ";
        let err = parse_share_link(link).expect_err("shadowsocks wrapper should be rejected");
        assert!(err.to_string().contains("v2rayN Shadowsocks"));
    }
}
