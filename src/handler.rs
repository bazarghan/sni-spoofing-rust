use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::error::HandlerError;
use crate::proto::{
    ConnId, Deregistration, Registration, SnifferCommand, SnifferCommandSender, SnifferResult,
};
use crate::relay;

struct SnifferRegistrationGuard {
    cmd_tx: SnifferCommandSender,
    conn_id: ConnId,
}

impl SnifferRegistrationGuard {
    fn new(cmd_tx: &SnifferCommandSender, conn_id: ConnId) -> Self {
        Self {
            cmd_tx: cmd_tx.clone(),
            conn_id,
        }
    }
}

impl Drop for SnifferRegistrationGuard {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(SnifferCommand::Deregister(Deregistration {
            conn_id: self.conn_id,
        }));
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection(
    client: TcpStream,
    upstream_addr: SocketAddr,
    fake_payload: Arc<[u8]>,
    local_ip: std::net::IpAddr,
    cmd_tx: SnifferCommandSender,
    conn_timeout_sec: u64,
    handshake_timeout_sec: u64,
    keepalive_time_sec: u64,
    keepalive_interval_sec: u64,
    idle_timeout: Option<u64>,
    buffer_size: usize,
) {
    if let Err(e) = handle_inner(
        client,
        upstream_addr,
        fake_payload,
        local_ip,
        &cmd_tx,
        conn_timeout_sec,
        handshake_timeout_sec,
        keepalive_time_sec,
        keepalive_interval_sec,
        idle_timeout,
        buffer_size,
    )
    .await
    {
        match &e {
            HandlerError::Timeout => {
                warn!(upstream = %upstream_addr, "timeout waiting for fake ACK");
            }
            _ => {
                warn!(upstream = %upstream_addr, "connection failed: {}", e);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner(
    client: TcpStream,
    upstream_addr: SocketAddr,
    fake_payload: Arc<[u8]>,
    local_ip: std::net::IpAddr,
    cmd_tx: &SnifferCommandSender,
    conn_timeout_sec: u64,
    handshake_timeout_sec: u64,
    keepalive_time_sec: u64,
    keepalive_interval_sec: u64,
    idle_timeout: Option<u64>,
    buffer_size: usize,
) -> Result<(), HandlerError> {
    let upstream_sock = if upstream_addr.is_ipv4() {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
    } else {
        socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
    }
    .map_err(HandlerError::Connect)?;

    upstream_sock
        .set_nonblocking(true)
        .map_err(HandlerError::Connect)?;

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    upstream_sock
        .bind(&bind_addr.into())
        .map_err(HandlerError::Connect)?;

    let local_addr = upstream_sock
        .local_addr()
        .map_err(HandlerError::Connect)?
        .as_socket()
        .ok_or_else(|| {
            HandlerError::Connect(std::io::Error::other("failed to get local socket addr"))
        })?;

    let (result_tx, mut result_rx) = mpsc::channel::<SnifferResult>(4);

    let conn_id = ConnId {
        src_ip: local_ip,
        src_port: local_addr.port(),
        dst_ip: upstream_addr.ip(),
        dst_port: upstream_addr.port(),
    };

    let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(SnifferCommand::Register(Registration {
            conn_id,
            fake_payload,
            result_tx,
            registered_tx,
        }))
        .map_err(|_| HandlerError::Registration)?;

    let _registration_guard = SnifferRegistrationGuard::new(cmd_tx, conn_id);
    registered_rx
        .await
        .map_err(|_| HandlerError::Registration)?;

    match upstream_sock.connect(&upstream_addr.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(HandlerError::Connect(e)),
    }

    let std_stream: std::net::TcpStream = upstream_sock.into();
    let upstream = TcpStream::from_std(std_stream).map_err(HandlerError::Connect)?;

    let connect_result =
        tokio::time::timeout(Duration::from_secs(conn_timeout_sec), upstream.writable()).await;
    match connect_result {
        Ok(Ok(())) => {
            let sock_ref = SockRef::from(&upstream);
            if let Some(err) = sock_ref.take_error().map_err(HandlerError::Connect)? {
                return Err(HandlerError::Connect(err));
            }
        }
        Ok(Err(e)) => return Err(HandlerError::Connect(e)),
        Err(_) => {
            return Err(HandlerError::Connect(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            )));
        }
    }

    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(keepalive_time_sec))
        .with_interval(Duration::from_secs(keepalive_interval_sec));
    let sock_ref = SockRef::from(&upstream);
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
    let _ = upstream.set_nodelay(true);

    let client_ref = SockRef::from(&client);
    let _ = client_ref.set_tcp_keepalive(&keepalive);
    let _ = client.set_nodelay(true);

    debug!(
        port = local_addr.port(),
        "connected, waiting for sniffer confirmation"
    );

    let confirmed = tokio::time::timeout(Duration::from_secs(handshake_timeout_sec), async {
        match result_rx.recv().await {
            Some(SnifferResult::FakeConfirmed) => Ok(()),
            Some(SnifferResult::Failed(e)) => Err(HandlerError::SnifferFailed(e)),
            None => Err(HandlerError::Registration),
        }
    })
    .await;

    match confirmed {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(HandlerError::Timeout),
    }

    debug!(port = local_addr.port(), "fake confirmed, starting relay");

    relay::relay(client, upstream, idle_timeout, buffer_size)
        .await
        .map_err(HandlerError::Relay)
}
