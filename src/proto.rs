use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::mpsc;

pub trait SnifferWaker: Send + Sync {
    fn wake(&self);
}

#[derive(Clone)]
pub struct SnifferCommandSender {
    inner: std::sync::mpsc::Sender<SnifferCommand>,
    waker: Option<Arc<dyn SnifferWaker>>,
}

impl SnifferCommandSender {
    pub fn new(
        inner: std::sync::mpsc::Sender<SnifferCommand>,
        waker: Option<Arc<dyn SnifferWaker>>,
    ) -> Self {
        Self { inner, waker }
    }

    pub fn send(
        &self,
        command: SnifferCommand,
    ) -> Result<(), std::sync::mpsc::SendError<SnifferCommand>> {
        self.inner.send(command)?;
        if let Some(waker) = &self.waker {
            waker.wake();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug)]
pub enum SnifferResult {
    FakeConfirmed,
    Failed(String),
}

pub struct Registration {
    pub conn_id: ConnId,
    pub fake_payload: Arc<[u8]>,
    pub result_tx: mpsc::Sender<SnifferResult>,
    pub registered_tx: tokio::sync::oneshot::Sender<()>,
}

pub struct Deregistration {
    pub conn_id: ConnId,
}

pub enum SnifferCommand {
    Register(Registration),
    Deregister(Deregistration),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingWaker(AtomicUsize);

    impl SnifferWaker for CountingWaker {
        fn wake(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn command_sender_wakes_after_enqueuing() {
        let (inner, receiver) = std::sync::mpsc::channel();
        let waker = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let sender = SnifferCommandSender::new(inner, Some(waker.clone()));
        let conn_id = ConnId {
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_ip: "127.0.0.2".parse().unwrap(),
            dst_port: 443,
        };

        sender
            .send(SnifferCommand::Deregister(Deregistration { conn_id }))
            .unwrap();

        assert!(matches!(
            receiver.try_recv(),
            Ok(SnifferCommand::Deregister(Deregistration { conn_id: received })) if received == conn_id
        ));
        assert_eq!(waker.0.load(Ordering::Relaxed), 1);
    }
}
