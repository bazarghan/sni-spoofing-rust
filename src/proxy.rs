use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::{self, Config};
use crate::error::ProxyError;
use crate::sniffer::RawBackend;
use crate::{listener, proto, shutdown, sniffer};

pub struct RunningProxy {
    stop: Arc<AtomicBool>,
    token: CancellationToken,
    runtime_thread: Option<std::thread::JoinHandle<()>>,
    sniffer_thread: Option<std::thread::JoinHandle<()>>,
}

impl RunningProxy {
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.token.cancel();
    }

    pub fn wait(&mut self) {
        if let Some(handle) = self.runtime_thread.take() {
            if handle.join().is_err() {
                warn!("proxy runtime thread panicked");
            }
        }
        if let Some(handle) = self.sniffer_thread.take() {
            if handle.join().is_err() {
                warn!("sniffer thread panicked");
            }
        }
    }

    pub fn stop(&mut self) {
        self.request_stop();
        self.wait();
    }

    pub fn is_running(&self) -> bool {
        self.runtime_thread
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start_proxy(cfg: Config) -> Result<RunningProxy, ProxyError> {
    config::validate(&cfg)?;

    let upstream_addrs: Vec<(IpAddr, u16)> = cfg
        .listeners
        .iter()
        .map(|lc| (lc.connect.ip(), lc.connect.port()))
        .collect();

    let local_ips: Vec<IpAddr> = upstream_addrs
        .iter()
        .filter_map(|(ip, _)| resolve_local_ip(*ip).ok())
        .collect();

    if local_ips.is_empty() {
        return Err(ProxyError::NoLocalIp);
    }

    info!(
        "config loaded: {} listener(s), local IPs: {:?}",
        cfg.listeners.len(),
        local_ips
    );

    let upstream_sockaddrs: Vec<std::net::SocketAddr> =
        cfg.listeners.iter().map(|lc| lc.connect).collect();

    #[cfg(target_os = "linux")]
    let backend =
        sniffer::linux::AfPacketBackend::open(&upstream_sockaddrs).map_err(ProxyError::Sniffer)?;

    #[cfg(target_os = "macos")]
    let backend =
        sniffer::macos::BpfBackend::open(&upstream_sockaddrs).map_err(ProxyError::Sniffer)?;

    #[cfg(target_os = "windows")]
    let backend = sniffer::windows::WinDivertBackend::open(&upstream_sockaddrs)
        .map_err(ProxyError::Sniffer)?;

    let (raw_cmd_tx, cmd_rx) = std::sync::mpsc::channel::<proto::SnifferCommand>();
    let cmd_tx = proto::SnifferCommandSender::new(raw_cmd_tx, backend.command_waker());
    let stop = Arc::new(AtomicBool::new(false));
    let token = CancellationToken::new();

    let sniffer_stop = stop.clone();
    let sniffer_local_ips = local_ips.clone();
    let sniffer_upstreams = upstream_addrs.clone();
    let sniffer_thread = std::thread::Builder::new()
        .name("sniffer".into())
        .spawn(move || {
            sniffer::run_sniffer(
                backend,
                cmd_rx,
                sniffer_local_ips,
                sniffer_upstreams,
                sniffer_stop,
            );
        })
        .map_err(ProxyError::ThreadSpawn)?;

    let rt = tokio::runtime::Runtime::new().map_err(ProxyError::Runtime)?;
    let runtime_token = token.clone();
    let runtime_thread = std::thread::Builder::new()
        .name("sni-spoof-runtime".into())
        .spawn(move || {
            rt.block_on(async move {
                let graceful_shutdown_sec = cfg.graceful_shutdown_sec;
                let mut handles = Vec::new();
                for lc in cfg.listeners {
                    let tx = cmd_tx.clone();
                    let lip = resolve_local_ip(lc.connect.ip()).unwrap_or(local_ips[0]);
                    let tk = runtime_token.clone();
                    handles.push(tokio::spawn(listener::run_listener(
                        lc,
                        lip,
                        tx,
                        cfg.idle_timeout,
                        cfg.buffer_size,
                        tk,
                    )));
                }

                runtime_token.cancelled().await;

                if graceful_shutdown_sec == 0 {
                    info!("graceful_shutdown_sec=0, exiting immediately");
                } else {
                    info!(
                        "waiting up to {}s for active connections to drain",
                        graceful_shutdown_sec
                    );

                    let drain_all = async {
                        for h in handles {
                            let _ = h.await;
                        }
                    };

                    if tokio::time::timeout(Duration::from_secs(graceful_shutdown_sec), drain_all)
                        .await
                        .is_err()
                    {
                        info!("drain timeout ({}s), forcing exit", graceful_shutdown_sec);
                    }
                }

                info!("shutdown complete");
            });
        })
        .map_err(ProxyError::ThreadSpawn)?;

    Ok(RunningProxy {
        stop,
        token,
        runtime_thread: Some(runtime_thread),
        sniffer_thread: Some(sniffer_thread),
    })
}

pub fn run_proxy_until_signal(config_path: &str) -> Result<(), ProxyError> {
    let cfg = config::load(config_path)?;
    let mut proxy = start_proxy(cfg)?;
    let rt = tokio::runtime::Runtime::new().map_err(ProxyError::Runtime)?;
    rt.block_on(shutdown::wait_for_signal(
        proxy.stop.clone(),
        proxy.token.clone(),
    ));
    proxy.wait();
    Ok(())
}

pub fn resolve_local_ip(dst: IpAddr) -> Result<IpAddr, String> {
    use std::net::UdpSocket;

    let target = match dst {
        IpAddr::V4(v4) => format!("{}:53", v4),
        IpAddr::V6(v6) => format!("[{}]:53", v6),
    };
    let bind = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };

    let sock = UdpSocket::bind(bind).map_err(|e| format!("bind: {}", e))?;
    sock.connect(&target)
        .map_err(|e| format!("connect: {}", e))?;
    Ok(sock
        .local_addr()
        .map_err(|e| format!("local_addr: {}", e))?
        .ip())
}

pub fn platform_privilege_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "Run as root or grant CAP_NET_RAW to the binary."
    }
    #[cfg(target_os = "macos")]
    {
        "Run with sudo so the BPF device can be opened."
    }
    #[cfg(target_os = "windows")]
    {
        "Run as Administrator with WinDivert next to the executable."
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "This platform does not have a packet injection backend."
    }
}
