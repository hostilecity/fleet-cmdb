//! The syscalls the collectors need that `std` does not expose: `uname(2)`, `statvfs(3)`, and
//! `getifaddrs(3)`, called through `libc`. Everything unsafe in the collectors is in this file.
//!
//! The [`System`] trait lets tests replace these calls with fixture data.

use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

/// Figures from `statvfs(3)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStats {
    /// `f_frsize`, the unit of the block counts.
    pub fragment_size: u64,
    /// `f_blocks`, the filesystem size.
    pub blocks: u64,
    /// `f_bavail`, blocks free for unprivileged users.
    pub blocks_available: u64,
}

/// One IPv4 or IPv6 address of an interface, from `getifaddrs(3)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfAddr {
    /// Interface name or address label, for example `ens18` or `ens18:1`.
    pub name: String,
    pub up: bool,
    pub loopback: bool,
    pub address: IpAddr,
    pub prefix_len: u8,
}

/// Syscall-backed sources. [`HostSystem`] is the real one.
pub trait System: Send + Sync + 'static {
    /// The `uname(2)` machine field, for example `x86_64`.
    fn machine(&self) -> io::Result<String>;
    /// `statvfs(3)` of a mount point.
    fn statvfs(&self, path: &Path) -> io::Result<FsStats>;
    /// Every IPv4 and IPv6 interface address.
    fn interface_addresses(&self) -> io::Result<Vec<IfAddr>>;
}

/// The running host.
pub struct HostSystem;

impl System for HostSystem {
    fn machine(&self) -> io::Result<String> {
        // SAFETY: `utsname` is a struct of `c_char` arrays, for which all zero bytes is a valid value.
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: `uts` is a valid, writable `utsname` that outlives the call.
        if unsafe { libc::uname(&mut uts) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(c_chars_to_string(&uts.machine))
    }

    fn statvfs(&self, path: &Path) -> io::Result<FsStats> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: `statvfs` is a struct of integers (and padding), for which all zero bytes is valid.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is a NUL-terminated string and `st` a valid, writable `statvfs`; both outlive
        // the call.
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // On x86_64 Linux (glibc and musl, DEC-01) these fields are all 64-bit; the annotations make a
        // different width a compile error rather than a silent truncation.
        let fragment_size: u64 = st.f_frsize;
        let blocks: u64 = st.f_blocks;
        let blocks_available: u64 = st.f_bavail;
        Ok(FsStats {
            fragment_size,
            blocks,
            blocks_available,
        })
    }

    fn interface_addresses(&self) -> io::Result<Vec<IfAddr>> {
        /// Frees the list on every return path.
        struct List(*mut libc::ifaddrs);
        impl Drop for List {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: the pointer came from a successful `getifaddrs` and is freed once.
                    unsafe { libc::freeifaddrs(self.0) };
                }
            }
        }

        let mut head: *mut libc::ifaddrs = ptr::null_mut();
        // SAFETY: `head` is a valid place for `getifaddrs` to store the list pointer.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let list = List(head);

        let mut out = Vec::new();
        let mut cursor = list.0;
        while !cursor.is_null() {
            // SAFETY: `cursor` is a non-null node of the list, which stays allocated until `list` drops.
            let ifa = unsafe { &*cursor };
            cursor = ifa.ifa_next;
            if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
                continue;
            }
            // SAFETY: `ifa_addr` is non-null and points to at least a `sockaddr`.
            let Some(address) = (unsafe { ip_of(ifa.ifa_addr) }) else {
                continue;
            };
            let prefix_len = if ifa.ifa_netmask.is_null() {
                None
            } else {
                // SAFETY: `ifa_netmask` is non-null and points to at least a `sockaddr`.
                unsafe { ip_of(ifa.ifa_netmask) }.and_then(|mask| prefix_of(address, mask))
            };
            // SAFETY: `ifa_name` is a non-null, NUL-terminated string owned by the list.
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let flag = |f: libc::c_int| ifa.ifa_flags & f as libc::c_uint != 0;
            out.push(IfAddr {
                name,
                up: flag(libc::IFF_UP),
                loopback: flag(libc::IFF_LOOPBACK),
                address,
                prefix_len: prefix_len.unwrap_or(if address.is_ipv4() { 32 } else { 128 }),
            });
        }
        Ok(out)
    }
}

/// The IP address in a `sockaddr`, or `None` for other families (such as `AF_PACKET`).
///
/// # Safety
///
/// `sa` must be non-null and point to a `sockaddr` whose family field tells its real size: a
/// `sockaddr_in` for `AF_INET` and a `sockaddr_in6` for `AF_INET6`, as `getifaddrs` guarantees.
unsafe fn ip_of(sa: *const libc::sockaddr) -> Option<IpAddr> {
    // SAFETY: the caller guarantees `sa` points to a `sockaddr`; read unaligned to make no
    // assumption about the allocation's alignment.
    let family = unsafe { ptr::read_unaligned(sa) }.sa_family;
    match libc::c_int::from(family) {
        libc::AF_INET => {
            // SAFETY: the family says this is a `sockaddr_in`.
            let sin = unsafe { ptr::read_unaligned(sa.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this is a `sockaddr_in6`.
            let sin6 = unsafe { ptr::read_unaligned(sa.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Prefix length of a netmask: its leading one bits. `None` if the families differ.
pub fn prefix_of(address: IpAddr, mask: IpAddr) -> Option<u8> {
    let ones = match (address, mask) {
        (IpAddr::V4(_), IpAddr::V4(m)) => u32::from(m).leading_ones(),
        (IpAddr::V6(_), IpAddr::V6(m)) => u128::from(m).leading_ones(),
        _ => return None,
    };
    u8::try_from(ones).ok()
}

fn c_chars_to_string(chars: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = chars
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| c.to_ne_bytes()[0])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_lengths() {
        let v4 = |s: &str| s.parse::<IpAddr>().expect("ip");
        assert_eq!(prefix_of(v4("192.0.2.10"), v4("255.255.255.0")), Some(24));
        assert_eq!(prefix_of(v4("192.0.2.10"), v4("0.0.0.0")), Some(0));
        assert_eq!(
            prefix_of(v4("2001:db8::10"), v4("ffff:ffff:ffff:ffff::")),
            Some(64)
        );
        assert_eq!(prefix_of(v4("2001:db8::10"), v4("255.255.255.0")), None);
    }

    #[test]
    fn c_strings_stop_at_nul() {
        let raw: Vec<libc::c_char> = b"x86_64\0junk"
            .iter()
            .map(|b| libc::c_char::from_ne_bytes([*b]))
            .collect();
        assert_eq!(c_chars_to_string(&raw), "x86_64");
    }

    // The real syscalls work on whatever Linux runs the tests; values are checked loosely.
    #[test]
    fn host_syscalls_answer() {
        assert!(!HostSystem.machine().expect("uname").is_empty());
        let root = HostSystem.statvfs(Path::new("/")).expect("statvfs /");
        assert!(root.fragment_size > 0);
        assert!(
            HostSystem
                .statvfs(Path::new("/nonexistent-fleet-agent"))
                .is_err()
        );
        assert!(
            HostSystem
                .interface_addresses()
                .expect("getifaddrs")
                .iter()
                .any(|a| a.loopback)
        );
    }
}
