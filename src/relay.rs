use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
mod platform {
    use std::future::Future;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;

    use tokio::io::Interest;
    use tokio::net::TcpStream;

    const MIN_PIPE_SIZE: usize = 4 * 1024;
    const MAX_PIPE_SIZE: usize = 1024 * 1024;
    const SPLICE_FLAGS: libc::c_uint = libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK;

    struct Pipe {
        read: OwnedFd,
        write: OwnedFd,
    }

    impl Pipe {
        fn new(requested_size: usize) -> io::Result<Self> {
            let mut fds = [-1; 2];
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }

            let pipe = Self {
                read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
                write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
            };
            let requested_size = requested_size.clamp(MIN_PIPE_SIZE, MAX_PIPE_SIZE);
            let _ = unsafe {
                libc::fcntl(
                    pipe.write.as_raw_fd(),
                    libc::F_SETPIPE_SZ,
                    requested_size as libc::c_int,
                )
            };
            Ok(pipe)
        }
    }

    fn splice_result(result: libc::ssize_t) -> io::Result<usize> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    async fn with_idle_timeout<T>(
        idle_timeout: Option<Duration>,
        future: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        match idle_timeout {
            Some(duration) => tokio::time::timeout(duration, future)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay idle timeout"))?,
            None => future.await,
        }
    }

    async fn splice_one_way(
        source: &TcpStream,
        destination: &TcpStream,
        idle_timeout: Option<Duration>,
        pipe_size: usize,
    ) -> io::Result<u64> {
        let pipe = Pipe::new(pipe_size)?;
        let mut total = 0u64;

        loop {
            let moved_to_pipe = with_idle_timeout(
                idle_timeout,
                source.async_io(Interest::READABLE, || {
                    splice_result(unsafe {
                        libc::splice(
                            source.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe.write.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe_size,
                            SPLICE_FLAGS,
                        )
                    })
                }),
            )
            .await?;

            if moved_to_pipe == 0 {
                let _ = unsafe { libc::shutdown(destination.as_raw_fd(), libc::SHUT_WR) };
                return Ok(total);
            }

            let mut remaining = moved_to_pipe;
            while remaining > 0 {
                let moved_to_socket = destination
                    .async_io(Interest::WRITABLE, || {
                        splice_result(unsafe {
                            libc::splice(
                                pipe.read.as_raw_fd(),
                                std::ptr::null_mut(),
                                destination.as_raw_fd(),
                                std::ptr::null_mut(),
                                remaining,
                                SPLICE_FLAGS,
                            )
                        })
                    })
                    .await?;
                if moved_to_socket == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "splice wrote zero bytes",
                    ));
                }
                remaining -= moved_to_socket;
                total += moved_to_socket as u64;
            }
        }
    }

    pub async fn relay(
        client: TcpStream,
        upstream: TcpStream,
        idle_timeout: Option<u64>,
        buffer_size: usize,
    ) -> io::Result<()> {
        let idle_timeout = idle_timeout.map(Duration::from_secs);
        let pipe_size = buffer_size
            .saturating_mul(1024)
            .clamp(MIN_PIPE_SIZE, MAX_PIPE_SIZE);

        let (c2u, u2c) = tokio::try_join!(
            splice_one_way(&client, &upstream, idle_timeout, pipe_size),
            splice_one_way(&upstream, &client, idle_timeout, pipe_size),
        )?;
        tracing::debug!(c2u, u2c, "zero-copy relay finished");
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use tokio::io::copy_bidirectional_with_sizes;
    use tokio::net::TcpStream;

    pub async fn relay(
        mut client: TcpStream,
        mut upstream: TcpStream,
        idle_timeout: Option<u64>,
        buffer_size: usize,
    ) -> Result<(), std::io::Error> {
        let (c2u, u2c) = if let Some(idle_timeout) = idle_timeout {
            let mut client_io_timeout = tokio_io_timeout::TimeoutStream::new(client);
            let mut upstream_io_timeout = tokio_io_timeout::TimeoutStream::new(upstream);

            client_io_timeout.set_read_timeout(Some(std::time::Duration::from_secs(idle_timeout)));
            upstream_io_timeout
                .set_read_timeout(Some(std::time::Duration::from_secs(idle_timeout)));

            let mut pin_client_io_timeout = std::pin::pin!(client_io_timeout);
            let mut pin_upstream_io_timeout = std::pin::pin!(upstream_io_timeout);

            copy_bidirectional_with_sizes(
                &mut pin_client_io_timeout,
                &mut pin_upstream_io_timeout,
                buffer_size * 1024,
                buffer_size * 1024,
            )
            .await
        } else {
            copy_bidirectional_with_sizes(
                &mut client,
                &mut upstream,
                buffer_size * 1024,
                buffer_size * 1024,
            )
            .await
        }?;

        tracing::debug!(c2u, u2c, "relay finished");
        Ok(())
    }
}

pub async fn relay(
    client: TcpStream,
    upstream: TcpStream,
    idle_timeout: Option<u64>,
    buffer_size: usize,
) -> Result<(), std::io::Error> {
    platform::relay(client, upstream, idle_timeout, buffer_size).await
}
