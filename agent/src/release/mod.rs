//! Signed agent releases (P1-PACKAGING, ADR 0018): the release manifest, the release public keys built
//! into the agent, and `fleet-agent verify-release`.
//!
//! The format is documented in `docs/releases.md`. In short, each release publishes the static binary,
//! a JSON manifest that names its version, target, SHA-256, and size, and a [minisign] signature of the
//! manifest made with the Ed25519 release key in CI. An agent trusts a release only if:
//!
//! 1. the manifest's signature verifies against one of the release public keys built into the agent
//!    ([`embedded_keys`]: the current key and, during a rotation, the next one), in minisign's
//!    pre-hashed mode (legacy signatures are refused);
//! 2. the manifest is well formed: the expected format tag, a strict SemVer version, this agent's only
//!    target ([`TARGET`], DEC-01), a SHA-256, and a size within [`MAX_BINARY_BYTES`]; and
//! 3. the binary has exactly that size and SHA-256.
//!
//! Nothing in the manifest is read before its signature has verified. Comparing the version with the
//! running one (no downgrade) and acting on the server's directive are the updater's job
//! (P1-AGENT-UPDATE); this module gives it [`verify_manifest`] and [`check_binary`].
//!
//! [minisign]: https://jedisct1.github.io/minisign/

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;

use crate::fsx::{self, Symlinks};

#[cfg(test)]
mod tests;

/// The only release target (DEC-01).
pub const TARGET: &str = "x86_64-unknown-linux-musl";

/// The `format` of every manifest this agent understands. It also separates manifests from anything
/// else the release key might ever sign.
pub const MANIFEST_FORMAT: &str = "fleet-agent-release-manifest/1";

/// Largest manifest or signature file read. Both are a few hundred bytes.
const MAX_MANIFEST_BYTES: u64 = 4 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4 * 1024;

/// Largest binary a manifest may describe. Release binaries are a few MiB.
pub const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;

/// Longest version string accepted (SemVer itself has no limit).
const MAX_VERSION_LEN: usize = 64;

/// The release public keys, in minisign `.pub` format, built into the binary. Lines starting with `#`
/// are notes for the reader; a file with nothing else holds no key. See `docs/releases.md` for key
/// generation and rotation.
const CURRENT_KEY_FILE: &str = include_str!("../../release-keys/current.pub");
const NEXT_KEY_FILE: &str = include_str!("../../release-keys/next.pub");

/// Which embedded key verified a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// The key releases are signed with now.
    Current,
    /// The key the next rotation moves to, shipped one release before it is used (ADR 0018).
    Next,
}

impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Next => "next",
        }
    }
}

/// A release public key and its role.
#[derive(Debug, Clone)]
pub struct ReleaseKey {
    pub role: KeyRole,
    key: PublicKey,
}

/// Parses one key file: `#` lines and blank lines are ignored; what is left is either nothing (no key)
/// or exactly a minisign public key (an `untrusted comment:` line and the base64 key line).
fn parse_key_file(text: &str) -> Result<Option<PublicKey>, String> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    match lines.as_slice() {
        [] => Ok(None),
        [comment, key] if comment.starts_with("untrusted comment:") => {
            PublicKey::decode(&format!("{comment}\n{key}\n"))
                .map(Some)
                .map_err(|e| format!("not a minisign Ed25519 public key ({e})"))
        }
        _ => Err("expected the two lines of a minisign .pub file".into()),
    }
}

fn keys_from(current: &str, next: &str) -> Result<Vec<ReleaseKey>, String> {
    let current = parse_key_file(current).map_err(|e| format!("current release key: {e}"))?;
    let next = parse_key_file(next).map_err(|e| format!("next release key: {e}"))?;
    let mut keys = Vec::new();
    match (current, next) {
        (None, Some(_)) => return Err("a next release key without a current one".into()),
        (Some(current), Some(next)) if current == next => {
            return Err("the current and next release keys are the same key".into());
        }
        (current, next) => {
            if let Some(key) = current {
                keys.push(ReleaseKey {
                    role: KeyRole::Current,
                    key,
                });
            }
            if let Some(key) = next {
                keys.push(ReleaseKey {
                    role: KeyRole::Next,
                    key,
                });
            }
        }
    }
    Ok(keys)
}

/// The release public keys built into this binary: none before the owner has generated them (then no
/// release verifies), the current key, or the current and next keys.
pub fn embedded_keys() -> Result<Vec<ReleaseKey>, String> {
    keys_from(CURRENT_KEY_FILE, NEXT_KEY_FILE)
}

/// A verified release manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: semver::Version,
    pub target: String,
    pub sha256: [u8; 32],
    pub size: u64,
}

/// The manifest as published (`docs/releases.md`). Unknown fields are refused, so a field added later
/// cannot be silently ignored by an older agent; a new field means a new `format`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    format: String,
    version: String,
    target: String,
    sha256: String,
    size: u64,
}

/// Why a release is not trusted. Every refusal says what was wrong, never what to do to get around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// This binary has no release key (none generated yet, or a build error).
    NoKeys(String),
    MalformedSignature,
    /// A minisign signature in the legacy, not pre-hashed, mode.
    LegacySignature,
    /// Signed by a key that is not built into this agent.
    UnknownKey,
    BadSignature,
    MalformedManifest(String),
    WrongTarget(String),
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    ChecksumMismatch,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeys(why) => write!(f, "this agent has no usable release key: {why}"),
            Self::MalformedSignature => f.write_str("the signature is not a minisign signature"),
            Self::LegacySignature => {
                f.write_str("the signature uses minisign's legacy mode, which is not accepted")
            }
            Self::UnknownKey => {
                f.write_str("the manifest is signed by a key this agent does not trust")
            }
            Self::BadSignature => f.write_str("the manifest signature is not valid"),
            Self::MalformedManifest(why) => write!(f, "the signed manifest is not valid: {why}"),
            Self::WrongTarget(target) => write!(
                f,
                "the release is for {}, not {TARGET}",
                crate::logging::sanitize(target, 64)
            ),
            Self::SizeMismatch { expected, actual } => write!(
                f,
                "the binary is {actual} bytes but the manifest says {expected}"
            ),
            Self::ChecksumMismatch => {
                f.write_str("the binary's SHA-256 does not match the manifest")
            }
        }
    }
}

/// A manifest whose signature verified, and the key that verified it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub manifest: Manifest,
    pub key: KeyRole,
}

/// Verifies `signature` (a minisign `.minisig` file) over the exact bytes of `manifest` against
/// `keys`, then parses and checks the manifest.
pub fn verify_manifest(
    manifest: &[u8],
    signature: &[u8],
    keys: &[ReleaseKey],
) -> Result<Verified, Refusal> {
    if keys.is_empty() {
        return Err(Refusal::NoKeys(
            "no release public key is built into this binary".into(),
        ));
    }
    let signature = std::str::from_utf8(signature)
        .ok()
        .and_then(|text| Signature::decode(text).ok())
        .ok_or(Refusal::MalformedSignature)?;
    let mut role = None;
    for key in keys {
        match key.key.verify(manifest, &signature, false) {
            Ok(()) => {
                role = Some(key.role);
                break;
            }
            Err(minisign_verify::Error::UnexpectedKeyId) => continue,
            Err(minisign_verify::Error::UnexpectedAlgorithm) => {
                return Err(Refusal::LegacySignature);
            }
            Err(_) => return Err(Refusal::BadSignature),
        }
    }
    let key = role.ok_or(Refusal::UnknownKey)?;
    Ok(Verified {
        manifest: parse_manifest(manifest)?,
        key,
    })
}

/// Parses and checks a manifest. Only called once its signature has verified.
fn parse_manifest(bytes: &[u8]) -> Result<Manifest, Refusal> {
    let bad = |why: &str| Refusal::MalformedManifest(why.to_owned());
    let raw: RawManifest =
        serde_json::from_slice(bytes).map_err(|e| Refusal::MalformedManifest(format!("{e}")))?;
    if raw.format != MANIFEST_FORMAT {
        return Err(bad(&format!(
            "unsupported format (this agent reads {MANIFEST_FORMAT})"
        )));
    }
    if raw.version.len() > MAX_VERSION_LEN {
        return Err(bad("the version is too long"));
    }
    let version = semver::Version::parse(&raw.version)
        .map_err(|_| bad("the version is not a SemVer version such as 1.2.3"))?;
    if !version.build.is_empty() {
        return Err(bad("the version has build metadata (`+...`)"));
    }
    if raw.target != TARGET {
        return Err(Refusal::WrongTarget(raw.target));
    }
    let sha256 = parse_sha256(&raw.sha256)
        .ok_or_else(|| bad("sha256 is not 64 lowercase hexadecimal digits"))?;
    if raw.size == 0 || raw.size > MAX_BINARY_BYTES {
        return Err(bad(&format!(
            "the size is not between 1 and {MAX_BINARY_BYTES} bytes"
        )));
    }
    Ok(Manifest {
        version,
        target: raw.target,
        sha256,
        size: raw.size,
    })
}

fn parse_sha256(hex: &str) -> Option<[u8; 32]> {
    let digits = hex.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let value = |d: u8| match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'a'..=b'f' => Some(d - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = value(pair[0])? << 4 | value(pair[1])?;
    }
    Some(out)
}

/// Lowercase hexadecimal, as in `sha256sum` output and the manifest.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads `binary` to its end, at most one byte more than the manifest's size, and checks its size and
/// SHA-256 against `manifest`.
pub fn check_binary(manifest: &Manifest, binary: impl Read) -> io::Result<Result<(), Refusal>> {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut reader = binary.take(manifest.size + 1);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut actual = 0u64;
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        context.update(&buffer[..n]);
        actual += n as u64;
    }
    if actual != manifest.size {
        return Ok(Err(Refusal::SizeMismatch {
            expected: manifest.size,
            actual,
        }));
    }
    if context.finish().as_ref() != manifest.sha256 {
        return Ok(Err(Refusal::ChecksumMismatch));
    }
    Ok(Ok(()))
}

const USAGE: &str = "\
Usage: fleet-agent verify-release --manifest PATH --signature PATH --binary PATH

Checks a downloaded agent release the way the agent checks one before installing it (ADR 0018): the
manifest's signature against the release keys built into this binary, then the binary's size and
SHA-256 against the manifest. Run it with an agent binary you already trust. It changes nothing.

Options:
  --manifest PATH   The release manifest (fleet-agent-<version>-<target>.manifest.json)
  --signature PATH  Its minisign signature (the same name plus .minisig)
  --binary PATH     The release binary
  -h, --help        Print this help

Exit status: 0 verified, 1 not verified, 2 usage error.";

const EXIT_NOT_VERIFIED: u8 = 1;
const EXIT_USAGE: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Verify {
        manifest: PathBuf,
        signature: PathBuf,
        binary: PathBuf,
    },
    Help,
}

/// Parses the arguments after `verify-release`.
fn parse_args(args: Vec<OsString>) -> Result<Command, String> {
    use crate::cli;
    use lexopt::prelude::*;
    let mut parser = lexopt::Parser::from_args(args);
    let (mut manifest, mut signature, mut binary) = (None, None, None);
    while let Some(arg) = parser.next().map_err(cli::error_text)? {
        let (slot, name) = match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Long("manifest") => (&mut manifest, "--manifest"),
            Long("signature") => (&mut signature, "--signature"),
            Long("binary") => (&mut binary, "--binary"),
            Value(value) => {
                return Err(format!(
                    "unrecognised argument: {}",
                    cli::shown(&value.to_string_lossy())
                ));
            }
            Long(name) => return Err(format!("unrecognised argument: {}", cli::long(name))),
            Short(c) => return Err(format!("unrecognised argument: {}", cli::short(c))),
        };
        let value = parser.value().map_err(cli::error_text)?;
        if value.is_empty() {
            return Err(format!("{name} needs a path"));
        }
        if slot.replace(PathBuf::from(value)).is_some() {
            return Err(format!("{name} given more than once"));
        }
    }
    match (manifest, signature, binary) {
        (Some(manifest), Some(signature), Some(binary)) => Ok(Command::Verify {
            manifest,
            signature,
            binary,
        }),
        _ => Err("--manifest, --signature, and --binary are all required".into()),
    }
}

/// Why `verify-release` stopped: a file it could not read, or a refusal.
enum Failure {
    Unreadable(String),
    Refused(Refusal),
}

fn read_small(what: &str, path: &Path, max: u64) -> Result<Vec<u8>, Failure> {
    fsx::read_regular(path, max, Symlinks::Follow)
        .map_err(|e| Failure::Unreadable(format!("cannot read the {what} {}: {e}", path.display())))
}

fn verify_files(manifest: &Path, signature: &Path, binary: &Path) -> Result<Verified, Failure> {
    let keys = embedded_keys().map_err(|e| Failure::Refused(Refusal::NoKeys(e)))?;
    verify_files_with(&keys, manifest, signature, binary)
}

fn verify_files_with(
    keys: &[ReleaseKey],
    manifest: &Path,
    signature: &Path,
    binary: &Path,
) -> Result<Verified, Failure> {
    let manifest_bytes = read_small("manifest", manifest, MAX_MANIFEST_BYTES)?;
    let signature_bytes = read_small("signature", signature, MAX_SIGNATURE_BYTES)?;
    let verified =
        verify_manifest(&manifest_bytes, &signature_bytes, keys).map_err(Failure::Refused)?;
    let cannot_read = |e: io::Error| {
        Failure::Unreadable(format!("cannot read the binary {}: {e}", binary.display()))
    };
    let file = File::open(binary).map_err(cannot_read)?;
    if !file.metadata().map_err(cannot_read)?.is_file() {
        return Err(cannot_read(io::Error::other("not a regular file")));
    }
    check_binary(&verified.manifest, file)
        .map_err(cannot_read)?
        .map_err(Failure::Refused)?;
    Ok(verified)
}

/// `fleet-agent verify-release`.
pub fn main(args: Vec<OsString>) -> ExitCode {
    // The first argument is `verify-release` itself.
    match parse_args(args.into_iter().skip(1).collect()) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::Verify {
            manifest,
            signature,
            binary,
        }) => match verify_files(&manifest, &signature, &binary) {
            Ok(verified) => {
                let m = &verified.manifest;
                println!("verified: fleet-agent {} for {}", m.version, m.target);
                println!(
                    "  signature: valid, made with the {} release key built into this agent",
                    verified.key.as_str()
                );
                println!(
                    "  binary:    {} bytes, SHA-256 {}, as in the manifest",
                    m.size,
                    hex(&m.sha256)
                );
                ExitCode::SUCCESS
            }
            Err(Failure::Unreadable(why)) => {
                eprintln!("fleet-agent: {why}");
                ExitCode::from(EXIT_NOT_VERIFIED)
            }
            Err(Failure::Refused(refusal)) => {
                eprintln!("fleet-agent: release NOT verified: {refusal}");
                ExitCode::from(EXIT_NOT_VERIFIED)
            }
        },
        Err(message) => {
            eprintln!("fleet-agent: {message}\n\n{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
