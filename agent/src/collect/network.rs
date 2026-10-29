//! Network facts from `getifaddrs(3)` and the kernel routing tables (FR-1.3, P1-A05).
//!
//! # Which interfaces and addresses are reported
//!
//! - An interface is reported when it is up (`IFF_UP`), is not loopback (`IFF_LOOPBACK`), is not a
//!   container or virtual-machine bridge (see [`is_container_interface`]), and has at least one
//!   reportable address. Address labels such as `ens18:1` are reported under the device, `ens18`.
//! - Addresses are IPv4 and IPv6 in CIDR notation (`192.0.2.10/24`, `2001:db8::10/64`). Link-local
//!   (`169.254.0.0/16`, `fe80::/10`), loopback, unspecified, and multicast addresses are left out.
//! - The **primary** interface carries the default route: the IPv4 default route (destination and mask
//!   `0` and `RTF_UP` in `/proc/net/route`) with the lowest metric, or, when there is no IPv4 default
//!   route, the IPv6 one from `/proc/net/ipv6_route` (ignoring `RTF_REJECT` entries such as the one on
//!   `lo`). At most one interface is primary.
//! - Interfaces are sorted by name; addresses IPv4 first, then IPv6, each in numeric order. The list
//!   and the addresses are stable facts (DEC-07).

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::{IfAddr, NetworkInterface};

/// Contract limits.
const MAX_INTERFACES: usize = 64;
const MAX_ADDRESSES: usize = 32;

const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// Bridges and virtual links made by container and virtual-machine runtimes, by name: `docker*`,
/// `br-` followed by 12 hex digits (Docker networks), `veth*`, `virbr*`, `lxcbr*`, `lxdbr*`,
/// `podman*`, `cni*`, `flannel*`, `cali*`, `cilium*`, `weave*`, `kube-bridge`. Other bridges (for
/// example `br0`) may carry the VM's own address and are kept.
pub fn is_container_interface(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "docker",
        "veth",
        "virbr",
        "lxcbr",
        "lxdbr",
        "podman",
        "cni",
        "flannel",
        "cali",
        "cilium",
        "weave",
        "kube-bridge",
    ];
    if PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    name.strip_prefix("br-")
        .is_some_and(|id| id.len() == 12 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether an address is worth reporting (not link-local, loopback, unspecified, or multicast).
pub fn is_reportable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => {
            !(a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast())
        }
        IpAddr::V6(a) => {
            !(a.is_loopback()
                || a.is_unicast_link_local()
                || a.is_unspecified()
                || a.is_multicast())
        }
    }
}

fn text(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "not valid UTF-8".to_owned())
}

fn hex(field: &str) -> Option<u32> {
    u32::from_str_radix(field, 16).ok()
}

/// The interface of the lowest-metric IPv4 default route in `/proc/net/route`, if any.
pub fn default_route_v4(bytes: &[u8]) -> Result<Option<String>, String> {
    let text = text(bytes)?;
    let mut lines = text.lines();
    if !lines.next().is_some_and(|h| h.starts_with("Iface")) {
        return Err("missing \"Iface\" header".to_owned());
    }
    let mut best: Option<(u32, &str)> = None;
    for line in lines {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Some(destination), Some(flags), Ok(metric), Some(mask)) =
            (hex(f[1]), hex(f[3]), f[6].parse::<u32>(), hex(f[7]))
        else {
            continue;
        };
        let default = destination == 0 && mask == 0 && flags & RTF_UP != 0;
        if default && best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, f[0]));
        }
    }
    Ok(best.map(|(_, iface)| iface.to_owned()))
}

/// The interface of the lowest-metric usable IPv6 default route in `/proc/net/ipv6_route`, if any.
pub fn default_route_v6(bytes: &[u8]) -> Result<Option<String>, String> {
    let mut best: Option<(u32, &str)> = None;
    for line in text(bytes)?.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some(prefix_len), Some(metric), Some(flags)) = (hex(f[1]), hex(f[5]), hex(f[8]))
        else {
            continue;
        };
        let iface = f[9];
        let default = f[0].len() == 32 && f[0].bytes().all(|b| b == b'0') && prefix_len == 0;
        let usable = flags & RTF_UP != 0 && flags & RTF_REJECT == 0 && iface != "lo";
        if default && usable && best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, iface));
        }
    }
    Ok(best.map(|(_, iface)| iface.to_owned()))
}

/// Builds the reported interfaces from the addresses `getifaddrs` returned. Also returns a note when a
/// contract limit made it drop interfaces or addresses.
pub fn interfaces(
    addrs: &[IfAddr],
    primary: Option<&str>,
) -> (Vec<NetworkInterface>, Option<String>) {
    let mut by_name: BTreeMap<&str, Vec<(IpAddr, u8)>> = BTreeMap::new();
    for a in addrs {
        // `ens18:1` is an address label on device `ens18`.
        let device = a.name.split(':').next().unwrap_or(&a.name);
        if !a.up
            || a.loopback
            || device.is_empty()
            || is_container_interface(device)
            || !is_reportable(a.address)
        {
            continue;
        }
        by_name
            .entry(device)
            .or_default()
            .push((a.address, a.prefix_len));
    }

    let mut notes = Vec::new();
    let mut interfaces: Vec<NetworkInterface> = by_name
        .into_iter()
        .map(|(name, mut addresses)| {
            addresses.sort();
            addresses.dedup();
            if addresses.len() > MAX_ADDRESSES {
                notes.push(format!(
                    "{name}: {} addresses; reporting the first {MAX_ADDRESSES}",
                    addresses.len()
                ));
                addresses.truncate(MAX_ADDRESSES);
            }
            NetworkInterface {
                name: name.to_owned(),
                primary: primary == Some(name),
                addresses: addresses
                    .into_iter()
                    .map(|(address, prefix)| format!("{address}/{prefix}"))
                    .collect(),
            }
        })
        .collect();
    if interfaces.len() > MAX_INTERFACES {
        notes.push(format!(
            "{} interfaces; reporting the first {MAX_INTERFACES} by name",
            interfaces.len()
        ));
        interfaces.truncate(MAX_INTERFACES);
    }
    let note = (!notes.is_empty()).then(|| notes.join("; "));
    (interfaces, note)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &[u8] = include_bytes!("../../tests/fixtures/collect/debian13/proc/net/route");
    const IPV6_ROUTE: &[u8] =
        include_bytes!("../../tests/fixtures/collect/debian13/proc/net/ipv6_route");

    fn addr(name: &str, address: &str, prefix_len: u8) -> IfAddr {
        IfAddr {
            name: name.to_owned(),
            up: true,
            loopback: false,
            address: address.parse().expect("address"),
            prefix_len,
        }
    }

    #[test]
    fn default_routes_from_fixtures() {
        // ens18 metric 100 beats ens19 metric 200.
        assert_eq!(default_route_v4(ROUTE), Ok(Some("ens18".to_owned())));
        // The reject route on lo is ignored.
        assert_eq!(default_route_v6(IPV6_ROUTE), Ok(Some("ens18".to_owned())));
    }

    #[test]
    fn lowest_metric_default_route_wins_regardless_of_order() {
        let table =
            b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
ens19\t00000000\t016433C6\t0003\t0\t0\t50\t00000000\t0\t0\t0\n\
ens18\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(default_route_v4(table), Ok(Some("ens19".to_owned())));
    }

    #[test]
    fn no_default_route_and_down_routes() {
        let table = b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
ens18\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
ens19\t00000000\t016433C6\t0002\t0\t0\t0\t00000000\n";
        assert_eq!(default_route_v4(table), Ok(None));
        assert!(default_route_v4(b"garbage\n").is_err());
        assert!(default_route_v4(b"\xff\xfe").is_err());
    }

    #[test]
    fn container_interfaces_by_name() {
        for name in [
            "docker0",
            "br-0123456789ab",
            "veth1a2b3c4",
            "virbr0",
            "lxcbr0",
            "podman0",
            "cni0",
            "flannel.1",
            "cali1234",
        ] {
            assert!(is_container_interface(name), "{name}");
        }
        for name in ["ens18", "eth0", "br0", "br-lan", "bond0", "wg0"] {
            assert!(!is_container_interface(name), "{name}");
        }
    }

    #[test]
    fn filters_groups_sorts_and_marks_primary() {
        let mut down = addr("ens20", "198.51.100.20", 24);
        down.up = false;
        let mut lo = addr("lo", "127.0.0.1", 8);
        lo.loopback = true;
        let addrs = vec![
            addr("ens19", "198.51.100.10", 24),
            addr("ens18", "2001:db8::10", 64),
            addr("ens18", "fe80::1", 64),
            addr("ens18:1", "192.0.2.11", 24),
            addr("ens18", "192.0.2.10", 24),
            addr("docker0", "203.0.113.1", 24),
            addr("ens21", "169.254.10.10", 16),
            down,
            lo,
        ];
        let (interfaces, note) = interfaces(&addrs, Some("ens18"));
        assert_eq!(note, None);
        assert_eq!(
            interfaces,
            vec![
                NetworkInterface {
                    name: "ens18".to_owned(),
                    primary: true,
                    addresses: vec![
                        "192.0.2.10/24".to_owned(),
                        "192.0.2.11/24".to_owned(),
                        "2001:db8::10/64".to_owned(),
                    ],
                },
                NetworkInterface {
                    name: "ens19".to_owned(),
                    primary: false,
                    addresses: vec!["198.51.100.10/24".to_owned()],
                },
            ]
        );
    }

    #[test]
    fn no_primary_when_the_route_interface_is_not_reported() {
        let (interfaces, _) = interfaces(&[addr("ens18", "192.0.2.10", 24)], Some("docker0"));
        assert!(interfaces.iter().all(|i| !i.primary));
    }

    #[test]
    fn caps_addresses_at_the_contract_limit() {
        let addrs: Vec<IfAddr> = (1..=40)
            .map(|i| addr("ens18", &format!("192.0.2.{i}"), 24))
            .collect();
        let (interfaces, note) = interfaces(&addrs, None);
        assert_eq!(interfaces[0].addresses.len(), MAX_ADDRESSES);
        assert!(note.expect("note").contains("40 addresses"));
    }
}
