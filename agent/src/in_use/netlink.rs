//! The kernel's `sock_diag` netlink interface (`NETLINK_SOCK_DIAG`, what `ss --cgroup` reads): the
//! listening TCP sockets and bound UDP sockets, IPv4 and IPv6, each with its inode and the id of its
//! cgroup (`INET_DIAG_CGROUP_ID`, Linux 5.7 and later). It needs no privilege and no capability: any
//! process may dump the sockets of its network namespace. The agent's unit already allows `AF_NETLINK`
//! (for `getifaddrs`), so nothing in it changes (VT-A01).
//!
//! Everything unsafe in [`crate::in_use`] is in [`dump`]: one socket, one request per family and
//! protocol, and the replies read into a buffer. [`parse`] reads the replies and is a pure function over
//! bytes, tested with crafted messages.

use std::io;

use crate::facts::host::SocketCgroup;

/// `SOCK_DIAG_BY_FAMILY` (`linux/sock_diag.h`).
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `NLMSG_ERROR` and `NLMSG_DONE` (`linux/netlink.h`).
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `INET_DIAG_CGROUP_ID` (`linux/inet_diag.h`).
const INET_DIAG_CGROUP_ID: u16 = 21;
/// `TCP_LISTEN` and `TCP_CLOSE` as state bits: a UDP socket that is bound but not connected is in
/// `TCP_CLOSE`, as `/proc/net/udp` shows (`07`).
const LISTEN_STATES: u32 = 1 << 10;
const BOUND_UDP_STATES: u32 = 1 << 7;

const NLMSG_HEADER: usize = 16;
/// `struct inet_diag_req_v2`.
const REQUEST: usize = 56;
/// `struct inet_diag_msg`: family, state, timer, retrans, a 48-byte `inet_diag_sockid`, then expires,
/// rqueue, wqueue, uid, and inode.
const DIAG_MSG: usize = 72;
const INODE_OFFSET: usize = 68;

/// The requests, in order: TCP listening, then UDP bound, each for IPv4 and IPv6.
const QUERIES: [(u8, u8, u32); 4] = [
    (libc::AF_INET as u8, libc::IPPROTO_TCP as u8, LISTEN_STATES),
    (libc::AF_INET6 as u8, libc::IPPROTO_TCP as u8, LISTEN_STATES),
    (
        libc::AF_INET as u8,
        libc::IPPROTO_UDP as u8,
        BOUND_UDP_STATES,
    ),
    (
        libc::AF_INET6 as u8,
        libc::IPPROTO_UDP as u8,
        BOUND_UDP_STATES,
    ),
];

/// The sockets of [`QUERIES`] with their cgroup ids; more than `max` is an error. A socket the kernel
/// gives no cgroup id for (a kernel older than 5.7) is an error too: the caller would otherwise count
/// every socket as unnamed without saying why.
pub fn dump(max: usize) -> io::Result<Vec<SocketCgroup>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: socket(2) with constant arguments; the result is checked before it is used.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor this function owns; OwnedFd closes it on every return.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    // SAFETY: a valid descriptor, and a pointer to a `timeval` of the size given, alive for the call.
    let set = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    for (index, (family, protocol, states)) in QUERIES.into_iter().enumerate() {
        let sequence = index as u32 + 1;
        let request = request(family, protocol, states, sequence);
        // SAFETY: `kernel` is a zeroed `sockaddr_nl` (the kernel's address), passed with its size;
        // `request` is a byte buffer of the length given. Both outlive the call.
        let sent = unsafe {
            let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&raw const kernel).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            // SAFETY: `buffer` is writable for its whole length, which is what is passed.
            let received =
                unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let received = received as usize; // not negative, checked above
            let done =
                parse(&buffer[..received], sequence, &mut found).map_err(io::Error::other)?;
            if found.len() > max {
                return Err(io::Error::other(format!("more than {max} sockets")));
            }
            if done {
                break;
            }
        }
    }
    Ok(found)
}

/// One `SOCK_DIAG_BY_FAMILY` dump request (`nlmsghdr` and `inet_diag_req_v2`), in host byte order as
/// netlink wants.
pub fn request(family: u8, protocol: u8, states: u32, sequence: u32) -> Vec<u8> {
    let length = (NLMSG_HEADER + REQUEST) as u32;
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&length.to_ne_bytes());
    out.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // the kernel fills in our port id
    out.push(family);
    out.push(protocol);
    out.push(0); // idiag_ext: the cgroup id comes without asking
    out.push(0);
    out.extend_from_slice(&states.to_ne_bytes());
    out.resize(length as usize, 0); // inet_diag_sockid: all sockets
    out
}

/// Reads one datagram of replies to request `sequence` into `found`. `Ok(true)` once the dump is done.
pub fn parse(bytes: &[u8], sequence: u32, found: &mut Vec<SocketCgroup>) -> Result<bool, String> {
    let mut rest = bytes;
    while rest.len() >= NLMSG_HEADER {
        let length = u32_at(rest, 0) as usize;
        let kind = u16_at(rest, 4);
        let seq = u32_at(rest, 8);
        if length < NLMSG_HEADER || length > rest.len() {
            return Err(format!("a sock_diag reply of {length} bytes does not fit"));
        }
        let body = &rest[NLMSG_HEADER..length];
        rest = &rest[align(length).min(rest.len())..];
        if seq != sequence {
            continue; // not ours (cannot happen on a socket of our own; skipped all the same)
        }
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let errno = if body.len() >= 4 {
                    -(u32_at(body, 0) as i32)
                } else {
                    0
                };
                return Err(format!(
                    "sock_diag refused the request: {}",
                    io::Error::from_raw_os_error(errno)
                ));
            }
            SOCK_DIAG_BY_FAMILY => found.push(socket(body)?),
            _ => {}
        }
    }
    Ok(false)
}

/// One `inet_diag_msg` and its attributes.
fn socket(body: &[u8]) -> Result<SocketCgroup, String> {
    if body.len() < DIAG_MSG {
        return Err(format!(
            "a sock_diag entry of {} bytes is too short",
            body.len()
        ));
    }
    let inode = u64::from(u32_at(body, INODE_OFFSET));
    let mut attributes = &body[DIAG_MSG..];
    while attributes.len() >= 4 {
        let length = usize::from(u16_at(attributes, 0));
        let kind = u16_at(attributes, 2) & 0x3fff; // without NLA_F_NESTED and NLA_F_NET_BYTEORDER
        if length < 4 || length > attributes.len() {
            break;
        }
        if kind == INET_DIAG_CGROUP_ID && length >= 12 {
            let cgroup = u64::from_ne_bytes(attributes[4..12].try_into().unwrap_or_default());
            return Ok(SocketCgroup { inode, cgroup });
        }
        attributes = &attributes[align(length).min(attributes.len())..];
    }
    Err("the kernel gives no cgroup id for sockets (it needs Linux 5.7 or later)".into())
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
