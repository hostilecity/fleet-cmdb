//! Listening sockets from `/proc/net/{tcp,tcp6,udp,udp6}` (VT-A01): readable by any process, no
//! privilege. A TCP socket in `LISTEN` (`0A`) and a UDP socket that is bound and not connected (`07`,
//! remote address and port zero) count. Each keeps its inode (to find its cgroup), whether it is on a
//! loopback address, and its local address and port only to match a socket systemd itself listens on
//! (socket activation, [`super::units::parse_list_sockets`]). The address and port are never reported.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The files, with whether each is UDP.
pub const SOURCES: [(&str, bool); 4] = [
    ("/proc/net/tcp", false),
    ("/proc/net/tcp6", false),
    ("/proc/net/udp", true),
    ("/proc/net/udp6", true),
];

/// One listening or bound socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub inode: u64,
    pub address: IpAddr,
    pub port: u16,
}

impl Socket {
    /// On a loopback address only (127.0.0.0/8, ::1, or an IPv4-mapped 127.x address). The wildcard
    /// address listens on every interface, so it is not.
    pub fn loopback(&self) -> bool {
        match self.address {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
            }
        }
    }
}

/// The listening (TCP) or bound (UDP) sockets of one `/proc/net` file. A line that cannot be read is
/// an error, so a format change shows up as unreadable rather than as fewer sockets.
pub fn parse(text: &[u8], udp: bool) -> Result<Vec<Socket>, String> {
    let text = std::str::from_utf8(text).map_err(|_| "not UTF-8".to_owned())?;
    let mut sockets = Vec::new();
    for (index, line) in text.lines().enumerate().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let line_error = || format!("line {} cannot be read", index + 1);
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(line_error());
        }
        let (address, port) = endpoint(fields[1]).ok_or_else(line_error)?;
        let (remote, remote_port) = endpoint(fields[2]).ok_or_else(line_error)?;
        let state = u8::from_str_radix(fields[3], 16).map_err(|_| line_error())?;
        let inode: u64 = fields[9].parse().map_err(|_| line_error())?;
        let wanted = if udp {
            state == 0x07 && remote.is_unspecified() && remote_port == 0
        } else {
            state == 0x0a
        };
        if wanted && inode != 0 {
            sockets.push(Socket {
                inode,
                address,
                port,
            });
        }
    }
    Ok(sockets)
}

/// `0100007F:0016` (IPv4) or 32 hex digits and a port (IPv6). The kernel prints each 32-bit word of
/// the address in its own byte order (little-endian on x86_64, DEC-01), and the port as a number.
fn endpoint(field: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let words = |hex: &str| -> Option<Vec<u32>> {
        (0..hex.len() / 8)
            .map(|i| u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok())
            .collect()
    };
    let address = match address.len() {
        8 => {
            let word = words(address)?[0];
            IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, word) in words(address)?.into_iter().enumerate() {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((address, port))
}
