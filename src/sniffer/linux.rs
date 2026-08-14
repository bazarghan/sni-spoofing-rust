use std::collections::{BTreeSet, HashMap};
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use tracing::info;

use super::RawBackend;
use crate::error::SnifferError;
use crate::proto::SnifferWaker;

const CAPTURE_SNAPLEN: u32 = 256;
const MAX_FILTER_PORTS: usize = 32;

struct EventFdWaker {
    fd: Arc<OwnedFd>,
}

impl SnifferWaker for EventFdWaker {
    fn wake(&self) {
        let value: u64 = 1;
        let _ = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &value as *const u64 as *const libc::c_void,
                mem::size_of::<u64>(),
            )
        };
    }
}

pub struct AfPacketBackend {
    fd: RawFd,
    ifindex: i32,
    wake_fd: Arc<OwnedFd>,
}

impl AfPacketBackend {
    pub fn open(upstreams: &[SocketAddr]) -> Result<Self, SnifferError> {
        let first = upstreams.first().expect("no upstreams");
        let (ifname, ifindex) = get_interface_for(first.ip())?;
        info!(interface = %ifname, ifindex, "binding AF_PACKET socket");

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(SnifferError::SocketOpen(io::Error::last_os_error()));
        }

        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex;

        let ret = unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::SocketBind(io::Error::last_os_error()));
        }

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as u32,
            );
        }

        attach_bpf_filter(fd, upstreams)?;

        let wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if wake_fd < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::SocketOpen(io::Error::last_os_error()));
        }
        let wake_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(wake_fd) });

        Ok(AfPacketBackend {
            fd,
            ifindex,
            wake_fd,
        })
    }

    fn drain_waker(&self) {
        let mut value = 0u64;
        loop {
            let result = unsafe {
                libc::read(
                    self.wake_fd.as_raw_fd(),
                    &mut value as *mut u64 as *mut libc::c_void,
                    mem::size_of::<u64>(),
                )
            };
            if result < 0 {
                break;
            }
        }
    }
}

impl RawBackend for AfPacketBackend {
    fn frame_kind(&self) -> crate::packet::FrameKind {
        crate::packet::FrameKind::Ethernet
    }

    fn command_waker(&self) -> Option<Arc<dyn SnifferWaker>> {
        Some(Arc::new(EventFdWaker {
            fd: self.wake_fd.clone(),
        }))
    }

    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, SnifferError> {
        let mut poll_fds = [
            libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.wake_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        loop {
            let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, 100) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(SnifferError::Recv(error));
            }
            if ready == 0 {
                return Err(SnifferError::Recv(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "receive timeout",
                )));
            }
            if poll_fds[1].revents & libc::POLLIN != 0 {
                self.drain_waker();
                return Ok(0);
            }
            if poll_fds[0].revents & libc::POLLIN != 0 {
                break;
            }
        }

        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(SnifferError::Recv(io::Error::last_os_error()));
        }
        Ok(n as usize)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError> {
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = self.ifindex;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&frame[0..6]);

        let ret = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            return Err(SnifferError::Inject(io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for AfPacketBackend {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn get_interface_for(ip: IpAddr) -> Result<(String, i32), SnifferError> {
    use std::net::UdpSocket;

    let target = match ip {
        IpAddr::V4(v4) => format!("{}:53", v4),
        IpAddr::V6(v6) => format!("[{}]:53", v6),
    };

    let sock = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|e| SnifferError::Other(format!("bind UDP: {}", e)))?;
    sock.connect(&target)
        .map_err(|e| SnifferError::Other(format!("connect UDP to {}: {}", target, e)))?;
    let local_ip = sock
        .local_addr()
        .map_err(|e| SnifferError::Other(format!("local addr: {}", e)))?
        .ip();

    let addrs = nix::ifaddrs::getifaddrs()
        .map_err(|e| SnifferError::Other(format!("getifaddrs: {}", e)))?;
    for ifaddr in addrs {
        if let Some(addr) = ifaddr.address {
            let matches = match (addr.as_sockaddr_in(), addr.as_sockaddr_in6()) {
                (Some(v4), _) => IpAddr::V4(v4.ip()) == local_ip,
                (_, Some(v6)) => IpAddr::V6(v6.ip()) == local_ip,
                _ => false,
            };
            if matches {
                let ifname = ifaddr.interface_name.clone();
                let ifindex = nix::net::if_::if_nametoindex(ifname.as_str())
                    .map_err(|e| SnifferError::Other(format!("if_nametoindex: {}", e)))?;
                return Ok((ifname, ifindex as i32));
            }
        }
    }

    Err(SnifferError::Other(format!(
        "no interface found for local IP {}",
        local_ip
    )))
}

fn attach_bpf_filter(fd: RawFd, upstreams: &[SocketAddr]) -> Result<(), SnifferError> {
    let filter = build_bpf_filter(upstreams)?;

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const libc::sock_fprog as *const libc::c_void,
            mem::size_of::<libc::sock_fprog>() as u32,
        )
    };
    if ret < 0 {
        return Err(SnifferError::FilterAttach(io::Error::last_os_error()));
    }

    info!(
        ports = ?upstreams.iter().map(SocketAddr::port).collect::<BTreeSet<_>>(),
        snaplen = CAPTURE_SNAPLEN,
        "BPF handshake filter attached"
    );
    Ok(())
}

struct FilterBuilder {
    instructions: Vec<libc::sock_filter>,
    labels: HashMap<&'static str, usize>,
    conditional_patches: Vec<(usize, Option<&'static str>, Option<&'static str>)>,
    jump_patches: Vec<(usize, &'static str)>,
}

impl FilterBuilder {
    fn new() -> Self {
        Self {
            instructions: Vec::new(),
            labels: HashMap::new(),
            conditional_patches: Vec::new(),
            jump_patches: Vec::new(),
        }
    }

    fn label(&mut self, name: &'static str) {
        self.labels.insert(name, self.instructions.len());
    }

    fn statement(&mut self, code: u16, k: u32) {
        self.instructions.push(libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        });
    }

    fn conditional(
        &mut self,
        code: u16,
        k: u32,
        on_true: Option<&'static str>,
        on_false: Option<&'static str>,
    ) {
        let index = self.instructions.len();
        self.statement(code, k);
        self.conditional_patches.push((index, on_true, on_false));
    }

    fn jump(&mut self, target: &'static str) {
        let index = self.instructions.len();
        self.statement(0x05, 0); // BPF_JMP | BPF_JA
        self.jump_patches.push((index, target));
    }

    fn finish(mut self) -> Result<Vec<libc::sock_filter>, SnifferError> {
        let conditional_patches = mem::take(&mut self.conditional_patches);
        for (index, on_true, on_false) in conditional_patches {
            if let Some(label) = on_true {
                self.instructions[index].jt = self.conditional_offset(index, label)?;
            }
            if let Some(label) = on_false {
                self.instructions[index].jf = self.conditional_offset(index, label)?;
            }
        }
        let jump_patches = mem::take(&mut self.jump_patches);
        for (index, label) in jump_patches {
            self.instructions[index].k = self.jump_offset(index, label)?;
        }
        Ok(self.instructions)
    }

    fn conditional_offset(&self, index: usize, label: &'static str) -> Result<u8, SnifferError> {
        let offset = self.jump_offset(index, label)?;
        u8::try_from(offset)
            .map_err(|_| SnifferError::Other(format!("BPF jump to {label} is too large: {offset}")))
    }

    fn jump_offset(&self, index: usize, label: &'static str) -> Result<u32, SnifferError> {
        let target = *self
            .labels
            .get(label)
            .ok_or_else(|| SnifferError::Other(format!("missing BPF label: {label}")))?;
        let offset = target.checked_sub(index + 1).ok_or_else(|| {
            SnifferError::Other(format!("BPF jump to {label} would go backwards"))
        })?;
        u32::try_from(offset)
            .map_err(|_| SnifferError::Other(format!("BPF jump to {label} is too large")))
    }
}

fn build_bpf_filter(upstreams: &[SocketAddr]) -> Result<Vec<libc::sock_filter>, SnifferError> {
    let ports: Vec<u16> = upstreams
        .iter()
        .map(SocketAddr::port)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let filter_ports = ports.len() <= MAX_FILTER_PORTS;
    let mut bpf = FilterBuilder::new();

    bpf.statement(0x28, 12); // BPF_LD | BPF_H | BPF_ABS: Ethernet type
    bpf.conditional(0x15, libc::ETH_P_IP as u32, Some("ipv4"), Some("ipv6_type"));

    bpf.label("ipv4");
    bpf.statement(0x30, 23); // IPv4 protocol
    bpf.conditional(0x15, libc::IPPROTO_TCP as u32, None, Some("drop"));
    bpf.statement(0x28, 20); // IPv4 flags and fragment offset
    bpf.conditional(0x45, 0x3fff, Some("drop"), None); // BPF_JSET
    if filter_ports {
        bpf.statement(0xb1, 14); // BPF_LDX | BPF_B | BPF_MSH: IPv4 header length
        bpf.statement(0x48, 14); // TCP source port, Ethernet + IPv4 IHL
        for port in &ports {
            bpf.conditional(0x15, u32::from(*port), Some("inspect_len"), None);
        }
        bpf.statement(0x48, 16); // TCP destination port
        for port in &ports {
            bpf.conditional(0x15, u32::from(*port), Some("inspect_len"), None);
        }
        bpf.jump("drop");
    } else {
        bpf.jump("inspect_len");
    }

    bpf.label("ipv6_type");
    bpf.conditional(0x15, libc::ETH_P_IPV6 as u32, Some("ipv6"), Some("drop"));
    bpf.label("ipv6");
    bpf.statement(0x30, 20); // IPv6 next header
    bpf.conditional(
        0x15,
        libc::IPPROTO_TCP as u32,
        if filter_ports {
            None
        } else {
            Some("inspect_len")
        },
        Some("drop"),
    );
    if filter_ports {
        bpf.statement(0x28, 54); // TCP source port after Ethernet + IPv6
        for port in &ports {
            bpf.conditional(0x15, u32::from(*port), Some("inspect_len"), None);
        }
        bpf.statement(0x28, 56); // TCP destination port
        for port in &ports {
            bpf.conditional(0x15, u32::from(*port), Some("inspect_len"), None);
        }
        bpf.jump("drop");
    }

    bpf.label("inspect_len");
    bpf.statement(0x80, 0); // BPF_LD | BPF_W | BPF_LEN
    bpf.conditional(0x25, CAPTURE_SNAPLEN, Some("drop"), Some("accept")); // BPF_JGT
    bpf.label("accept");
    bpf.statement(0x06, CAPTURE_SNAPLEN); // BPF_RET | BPF_K
    bpf.label("drop");
    bpf.statement(0x06, 0);

    bpf.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_filter(filter: &[libc::sock_filter], packet: &[u8]) -> u32 {
        let mut accumulator = 0u32;
        let mut index_register = 0usize;
        let mut pc = 0usize;

        while pc < filter.len() {
            let instruction = filter[pc];
            match instruction.code {
                0x28 => {
                    let offset = instruction.k as usize;
                    accumulator = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as u32;
                    pc += 1;
                }
                0x30 => {
                    accumulator = packet[instruction.k as usize] as u32;
                    pc += 1;
                }
                0x48 => {
                    let offset = index_register + instruction.k as usize;
                    accumulator = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as u32;
                    pc += 1;
                }
                0x80 => {
                    accumulator = packet.len() as u32;
                    pc += 1;
                }
                0xb1 => {
                    index_register = ((packet[instruction.k as usize] & 0x0f) * 4) as usize;
                    pc += 1;
                }
                0x15 => {
                    let offset = if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    pc += usize::from(offset) + 1;
                }
                0x25 => {
                    let offset = if accumulator > instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    pc += usize::from(offset) + 1;
                }
                0x45 => {
                    let offset = if accumulator & instruction.k != 0 {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    pc += usize::from(offset) + 1;
                }
                0x05 => pc += instruction.k as usize + 1,
                0x06 => return instruction.k,
                code => panic!("unsupported test BPF instruction: {code:#x}"),
            }
        }
        0
    }

    fn ipv4_packet(protocol: u8, source_port: u16, destination_port: u16, len: usize) -> Vec<u8> {
        let mut packet = vec![0; len];
        packet[12..14].copy_from_slice(&(libc::ETH_P_IP as u16).to_be_bytes());
        packet[14] = 0x45;
        packet[23] = protocol;
        packet[34..36].copy_from_slice(&source_port.to_be_bytes());
        packet[36..38].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    fn ipv6_packet(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0; 74];
        packet[12..14].copy_from_slice(&(libc::ETH_P_IPV6 as u16).to_be_bytes());
        packet[20] = libc::IPPROTO_TCP as u8;
        packet[54..56].copy_from_slice(&source_port.to_be_bytes());
        packet[56..58].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    #[test]
    fn bpf_filter_keeps_only_small_tcp_packets_for_upstream_ports() {
        let upstream: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let filter = build_bpf_filter(&[upstream]).unwrap();

        assert_eq!(
            run_filter(
                &filter,
                &ipv4_packet(libc::IPPROTO_TCP as u8, 40_000, 443, 74)
            ),
            CAPTURE_SNAPLEN
        );
        assert_eq!(
            run_filter(
                &filter,
                &ipv4_packet(libc::IPPROTO_TCP as u8, 443, 40_000, 74)
            ),
            CAPTURE_SNAPLEN
        );
        assert_eq!(
            run_filter(&filter, &ipv6_packet(40_000, 443)),
            CAPTURE_SNAPLEN
        );
        assert_eq!(
            run_filter(
                &filter,
                &ipv4_packet(libc::IPPROTO_TCP as u8, 40_000, 80, 74)
            ),
            0
        );
        assert_eq!(
            run_filter(
                &filter,
                &ipv4_packet(libc::IPPROTO_UDP as u8, 40_000, 443, 74)
            ),
            0
        );
        assert_eq!(
            run_filter(
                &filter,
                &ipv4_packet(libc::IPPROTO_TCP as u8, 40_000, 443, 300)
            ),
            0
        );
    }
}
