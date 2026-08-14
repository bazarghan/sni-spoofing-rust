use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::ListenerConfig;
use crate::handler;
use crate::packet::tls;
use crate::proto::SnifferCommandSender;

fn is_fd_exhausted(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

fn log_task_result(result: Result<(), JoinError>) {
    if let Err(e) = result {
        if e.is_panic() {
            error!("connection task panicked: {}", e);
        } else {
            warn!("connection task ended unexpectedly: {}", e);
        }
    }
}

pub async fn run_listener(
    lc: ListenerConfig,
    local_ip: IpAddr,
    cmd_tx: SnifferCommandSender,
    idle_timeout: Option<u64>,
    buffer_size: usize,
    token: CancellationToken,
) {
    let listener = match TcpListener::bind(lc.listen).await {
        Ok(l) => {
            info!(listen = %lc.listen, upstream = %lc.connect, sni = %lc.fake_sni, "listener started");
            l
        }
        Err(e) => {
            error!(listen = %lc.listen, "failed to bind: {}", e);
            return;
        }
    };
    let fake_payload: Arc<[u8]> = tls::build_client_hello(&lc.fake_sni).into();

    let mut tasks = JoinSet::new();

    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            task_result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = task_result {
                    log_task_result(result);
                }
                continue;
            }
            _ = token.cancelled() => break,
        };

        match accepted {
            Ok((stream, peer)) => {
                let upstream = lc.connect;
                let fake_payload = fake_payload.clone();
                let tx = cmd_tx.clone();
                let lip = local_ip;
                let conn_timeout = lc.conn_timeout_sec;
                let handshake_timeout = lc.handshake_timeout_sec;
                let keepalive_time = lc.keepalive_time_sec;
                let keepalive_interval = lc.keepalive_interval_sec;
                tasks.spawn(async move {
                    tracing::debug!(peer = %peer, "accepted connection");
                    handler::handle_connection(
                        stream,
                        upstream,
                        fake_payload,
                        lip,
                        tx,
                        conn_timeout,
                        handshake_timeout,
                        keepalive_time,
                        keepalive_interval,
                        idle_timeout,
                        buffer_size,
                    )
                    .await;
                });
            }
            Err(e) => {
                if is_fd_exhausted(&e) {
                    warn!("accept error (fd exhausted, backing off 500ms): {}", e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    error!("accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    info!(listen = %lc.listen, "stopped accepting, draining active connections");
    while let Some(result) = tasks.join_next().await {
        log_task_result(result);
    }
    info!(listen = %lc.listen, "all connections drained");
}
