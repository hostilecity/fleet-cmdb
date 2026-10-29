//! Parsers for the system facts. Pure functions over a source file's bytes; errors are short reasons
//! that the caller prefixes with the source path.

use super::OsRelease;

/// Largest integer the API accepts (`2^53 - 1`, exact in JSON numbers).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn text(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "not valid UTF-8".to_owned())
}

/// A single-line file such as `/proc/sys/kernel/hostname`: trimmed, non-empty, at most `max` chars.
fn single_value(bytes: &[u8], max: usize) -> Result<String, String> {
    let value = text(bytes)?.trim();
    if value.is_empty() {
        return Err("empty".to_owned());
    }
    if value.contains('\n') {
        return Err("more than one line".to_owned());
    }
    if value.chars().count() > max {
        return Err(format!("longer than {max} characters"));
    }
    Ok(value.to_owned())
}

/// `/proc/sys/kernel/hostname`.
pub fn parse_hostname(bytes: &[u8]) -> Result<String, String> {
    let name = single_value(bytes, 253)?;
    if name == "(none)" {
        return Err("hostname not set".to_owned());
    }
    Ok(name)
}

/// `/proc/sys/kernel/osrelease`, the `uname -r` string.
pub fn parse_kernel_version(bytes: &[u8]) -> Result<String, String> {
    single_value(bytes, 256)
}

/// The `uname(2)` machine field. The contract accepts only `x86_64` (DEC-01).
pub fn parse_architecture(machine: &str) -> Result<String, String> {
    match machine.trim() {
        "x86_64" => Ok("x86_64".to_owned()),
        "" => Err("machine field empty".to_owned()),
        other => Err(format!(
            "unsupported architecture {other:?}; the fleet is x86_64 only (DEC-01)"
        )),
    }
}

/// `os-release(5)`: `ID`, `VERSION_ID`, and `PRETTY_NAME`, unquoted. A key the file lacks is `None`;
/// a file with no `KEY=value` lines at all is an error.
pub fn parse_os_release(bytes: &[u8]) -> Result<OsRelease, String> {
    let mut release = OsRelease {
        id: None,
        version_id: None,
        pretty_name: None,
    };
    let mut assignments = 0;
    for line in text(bytes)?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            continue;
        }
        let Some(value) = unquote(raw) else {
            continue;
        };
        assignments += 1;
        let (slot, max) = match key {
            "ID" => (&mut release.id, 64),
            "VERSION_ID" => (&mut release.version_id, 64),
            "PRETTY_NAME" => (&mut release.pretty_name, 256),
            _ => continue,
        };
        if value.chars().count() > max {
            return Err(format!("{key} longer than {max} characters"));
        }
        *slot = (!value.is_empty()).then_some(value);
    }
    if assignments == 0 {
        return Err("no KEY=value lines".to_owned());
    }
    Ok(release)
}

/// Shell-style value from os-release: `"double"`, `'single'`, or bare, with backslash escapes outside
/// single quotes. `None` for an unterminated quote.
fn unquote(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => loop {
                match chars.next()? {
                    '"' => break,
                    '\\' => {
                        let escaped = chars.next()?;
                        if !matches!(escaped, '"' | '\\' | '$' | '`') {
                            out.push('\\');
                        }
                        out.push(escaped);
                    }
                    other => out.push(other),
                }
            },
            '\'' => loop {
                match chars.next()? {
                    '\'' => break,
                    other => out.push(other),
                }
            },
            '\\' => out.push(chars.next()?),
            other => out.push(other),
        }
    }
    Some(out)
}

/// `key : value` lines of `/proc/cpuinfo` and similar files.
fn colon_fields(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines().filter_map(|line| {
        let (key, value) = line.split_once(':')?;
        Some((key.trim(), value.trim()))
    })
}

/// The first `model name` in `/proc/cpuinfo`.
pub fn parse_cpu_model(bytes: &[u8]) -> Result<String, String> {
    let model = colon_fields(text(bytes)?)
        .find(|(key, _)| *key == "model name")
        .map(|(_, value)| value)
        .ok_or_else(|| "no \"model name\" line".to_owned())?;
    if model.is_empty() {
        return Err("empty \"model name\"".to_owned());
    }
    if model.chars().count() > 256 {
        return Err("\"model name\" longer than 256 characters".to_owned());
    }
    Ok(model.to_owned())
}

/// Logical CPUs: the number of `processor` entries in `/proc/cpuinfo`.
pub fn parse_cpu_cores(bytes: &[u8]) -> Result<u32, String> {
    let count = colon_fields(text(bytes)?)
        .filter(|(key, value)| *key == "processor" && value.parse::<u32>().is_ok())
        .count();
    match count {
        0 => Err("no \"processor\" lines".to_owned()),
        1..=4096 => Ok(u32::try_from(count).expect("at most 4096")),
        n => Err(format!("{n} processors, above the contract limit of 4096")),
    }
}

/// One `/proc/meminfo` value in bytes, for example `MemTotal:  8131244 kB`.
pub fn parse_meminfo(bytes: &[u8], key: &str) -> Result<u64, String> {
    let value = colon_fields(text(bytes)?)
        .find(|(k, _)| *k == key)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("{key} not found"))?;
    let mut parts = value.split_whitespace();
    let number: u64 = parts
        .next()
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("{key} is not a number"))?;
    let multiplier = match parts.next() {
        None => 1,
        Some("kB") => 1024,
        Some(unit) => return Err(format!("{key} has unknown unit {unit:?}")),
    };
    number
        .checked_mul(multiplier)
        .filter(|b| *b <= MAX_SAFE_INTEGER)
        .ok_or_else(|| format!("{key} out of range"))
}

/// Whole seconds of uptime from `/proc/uptime` (`86400.53 340000.12`).
pub fn parse_uptime(bytes: &[u8]) -> Result<u64, String> {
    let first = text(bytes)?
        .split_whitespace()
        .next()
        .ok_or_else(|| "empty".to_owned())?;
    let (whole, fraction) = first.split_once('.').unwrap_or((first, ""));
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("not a number: {first:?}"));
    }
    whole
        .parse::<u64>()
        .ok()
        .filter(|s| *s <= MAX_SAFE_INTEGER)
        .ok_or_else(|| format!("not a number: {first:?}"))
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `/proc/sys/kernel/random/boot_id`: a lowercase UUID.
pub fn parse_boot_id(bytes: &[u8]) -> Result<String, String> {
    let id = text(bytes)?.trim();
    let groups: Vec<&str> = id.split('-').collect();
    let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    if lengths == [8, 4, 4, 4, 12] && groups.iter().all(|g| is_lower_hex(g)) {
        Ok(id.to_owned())
    } else {
        Err("not a lowercase UUID".to_owned())
    }
}

/// `/etc/machine-id`: 32 lowercase hexadecimal characters.
pub fn parse_machine_id(bytes: &[u8]) -> Result<String, String> {
    let id = text(bytes)?.trim();
    if id == "uninitialized" {
        return Err("not initialised yet (first boot)".to_owned());
    }
    if id.len() == 32 && is_lower_hex(id) {
        Ok(id.to_owned())
    } else {
        Err("not 32 lowercase hexadecimal characters".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OS_RELEASE: &[u8] =
        include_bytes!("../../tests/fixtures/collect/debian13/etc/os-release");
    const CPUINFO: &[u8] = include_bytes!("../../tests/fixtures/collect/debian13/proc/cpuinfo");
    const MEMINFO: &[u8] = include_bytes!("../../tests/fixtures/collect/debian13/proc/meminfo");

    #[test]
    fn os_release_fixture() {
        assert_eq!(
            parse_os_release(OS_RELEASE),
            Ok(OsRelease {
                id: Some("debian".to_owned()),
                version_id: Some("13".to_owned()),
                pretty_name: Some("Debian GNU/Linux 13 (trixie)".to_owned()),
            })
        );
    }

    #[test]
    fn os_release_quoting_comments_and_missing_keys() {
        let text = b"# comment\n\nID='debian'\nPRETTY_NAME=\"Say \\\"hi\\\" \\$HOME\"\nNAME=bare\\ value\n";
        assert_eq!(
            parse_os_release(text),
            Ok(OsRelease {
                id: Some("debian".to_owned()),
                version_id: None,
                pretty_name: Some("Say \"hi\" $HOME".to_owned()),
            })
        );
        // Debian testing has no VERSION_ID: a missing key is null, not an error.
        assert_eq!(
            parse_os_release(b"ID=debian\n").map(|r| r.version_id),
            Ok(None)
        );
    }

    #[test]
    fn os_release_corrupt() {
        assert!(parse_os_release(b"garbage without assignments\n").is_err());
        assert!(parse_os_release(b"\xff\xfe\x00").is_err());
        assert!(parse_os_release(b"ID=\"unterminated\n").is_err());
        let long = format!("ID={}\n", "x".repeat(65));
        assert!(parse_os_release(long.as_bytes()).is_err());
    }

    #[test]
    fn hostname_and_kernel() {
        assert_eq!(
            parse_hostname(b"vm-01.example.lan\n"),
            Ok("vm-01.example.lan".to_owned())
        );
        assert!(parse_hostname(b"\n").is_err());
        assert!(parse_hostname(b"(none)\n").is_err());
        assert!(parse_hostname("a".repeat(254).as_bytes()).is_err());
        assert_eq!(
            parse_kernel_version(b"6.12.48+deb13-amd64\n"),
            Ok("6.12.48+deb13-amd64".to_owned())
        );
        assert!(parse_kernel_version(b"two\nlines\n").is_err());
    }

    #[test]
    fn architecture_is_x86_64_only() {
        assert_eq!(parse_architecture("x86_64"), Ok("x86_64".to_owned()));
        assert!(
            parse_architecture("aarch64")
                .unwrap_err()
                .contains("DEC-01")
        );
        assert!(parse_architecture("").is_err());
    }

    #[test]
    fn cpuinfo_fixture() {
        assert_eq!(
            parse_cpu_model(CPUINFO),
            Ok("Example Virtual CPU @ 2.40GHz".to_owned())
        );
        assert_eq!(parse_cpu_cores(CPUINFO), Ok(4));
        assert!(parse_cpu_model(b"processor\t: 0\n").is_err());
        assert!(parse_cpu_cores(b"model name\t: x\n").is_err());
    }

    #[test]
    fn meminfo_fixture() {
        assert_eq!(parse_meminfo(MEMINFO, "MemTotal"), Ok(8_131_244 * 1024));
        assert_eq!(parse_meminfo(MEMINFO, "MemAvailable"), Ok(6_291_456 * 1024));
        assert!(parse_meminfo(MEMINFO, "Nope").is_err());
        assert!(parse_meminfo(b"MemTotal: lots kB\n", "MemTotal").is_err());
        assert!(parse_meminfo(b"MemTotal: 1 MB\n", "MemTotal").is_err());
        assert!(parse_meminfo(b"MemTotal: 18446744073709551615 kB\n", "MemTotal").is_err());
    }

    #[test]
    fn uptime() {
        assert_eq!(parse_uptime(b"86400.53 340000.12\n"), Ok(86400));
        assert_eq!(parse_uptime(b"12 3\n"), Ok(12));
        assert!(parse_uptime(b"").is_err());
        assert!(parse_uptime(b"-1.0 0\n").is_err());
        assert!(parse_uptime(b"1.x 0\n").is_err());
    }

    #[test]
    fn identifiers() {
        assert_eq!(
            parse_boot_id(b"00000000-0000-4000-8000-0000000000b1\n"),
            Ok("00000000-0000-4000-8000-0000000000b1".to_owned())
        );
        assert!(parse_boot_id(b"00000000-0000-4000-8000-0000000000B1\n").is_err());
        assert!(parse_boot_id(b"not-a-uuid\n").is_err());
        assert_eq!(
            parse_machine_id(b"0123456789abcdef0123456789abcdef\n"),
            Ok("0123456789abcdef0123456789abcdef".to_owned())
        );
        assert!(parse_machine_id(b"uninitialized\n").is_err());
        assert!(parse_machine_id(b"0123\n").is_err());
    }
}
