//! Acting on an `agent_update` directive up to the point where the supervisor takes over: download,
//! verify, and stage (P1-A11, ADR 0018).
//!
//! Nothing from the server is trusted. The directive says which version and where to fetch it; the
//! agent then checks, in this order, and stops at the first failure with a reason for the operator:
//!
//! 1. the offered version is newer than the running one (never a downgrade, never a re-install);
//! 2. the manifest's signature verifies against the release keys built into this binary, and the
//!    manifest is the offered version, newer than the running one, for this target;
//! 3. there is room for the binary;
//! 4. the binary has exactly the size and SHA-256 the signed manifest gives;
//! 5. the staged binary passes its own self-test (`fleet-agent self-test`), run only after 1 to 4.
//!
//! Only then is the update handed to the supervisor. A refusal installs nothing and changes nothing.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use super::fetch::{self, Fetch, FetchError};
use super::layout::Layout;
use crate::fsx;
use crate::release::{self, Manifest, Refusal, ReleaseKey};

/// Manifests and signatures are a few hundred bytes (`docs/releases.md`).
pub const MAX_SMALL_BYTES: u64 = 4 * 1024;

/// Room to leave on the disk beyond the binary itself.
const FREE_SPACE_MARGIN: u64 = 8 * 1024 * 1024;

/// How long a self-test may take.
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(30);

pub const MANIFEST_NAME: &str = "manifest.json";
pub const SIGNATURE_NAME: &str = "manifest.json.minisig";
pub const BINARY_STAGED: &str = "fleet-agent";
pub const BINARY_PARTIAL: &str = "fleet-agent.partial";

/// The `agent_update` directive (`docs/api/README.md`), already known to be well formed by
/// [`crate::report::envelope`]; parsed again here so this module does not rely on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub rollout_id: u64,
    pub version: semver::Version,
    pub manifest_url: String,
    pub signature_url: String,
    pub binary_url: String,
}

impl Directive {
    pub fn parse(value: &Value) -> Option<Self> {
        let text = |field: &str| value.get(field).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            rollout_id: value
                .get("rollout_id")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0)?,
            version: super::layout::parse_version(&text("version")?)?,
            manifest_url: text("manifest_url")?,
            signature_url: text("signature_url")?,
            binary_url: text("binary_url")?,
        })
    }
}

/// Why staging stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum StageError {
    /// Transient: try again with the next directive. Whatever was downloaded is kept.
    Retry(String),
    /// Refused or impossible: report `failed` with this reason. Nothing is installed.
    Failed(String),
}

/// What staging needs from the machine, so tests can replace each part.
pub struct Stager<'a> {
    pub layout: &'a Layout,
    pub keys: &'a [ReleaseKey],
    pub fetch: &'a dyn Fetch,
    /// The version this agent is running.
    pub running: &'a semver::Version,
    /// Free bytes on the file system holding a path.
    pub free_bytes: &'a dyn Fn(&Path) -> io::Result<u64>,
    /// Runs the staged binary's self-test, expecting it to be this version.
    pub self_test: &'a dyn Fn(&Path, &semver::Version) -> Result<(), String>,
}

impl Stager<'_> {
    /// Downloads, verifies, and stages the release. Returns its (signed) manifest.
    pub fn stage(&self, directive: &Directive) -> Result<Manifest, StageError> {
        let offered = &directive.version;
        if offered <= self.running {
            return Err(StageError::Failed(format!(
                "the offered version {offered} is not newer than the running version {}; an agent never moves to an older or the same version",
                self.running
            )));
        }
        let version = offered.to_string();
        let dir = self.layout.staging(&version);
        self.prepare(&dir, &version)?;

        let manifest_bytes = small(self.fetch, &directive.manifest_url, "manifest")?;
        let signature_bytes = small(self.fetch, &directive.signature_url, "signature")?;
        let verified = release::verify_manifest(&manifest_bytes, &signature_bytes, self.keys)
            .map_err(|refusal| StageError::Failed(refusal_text(&refusal)))?;
        let manifest = verified.manifest;
        if manifest.version != *offered {
            return Err(StageError::Failed(format!(
                "the signed manifest is for version {}, not the offered {offered}",
                manifest.version
            )));
        }
        if manifest.version <= *self.running {
            return Err(StageError::Failed(format!(
                "the signed manifest is for version {}, not newer than the running version {}",
                manifest.version, self.running
            )));
        }
        write(&dir, MANIFEST_NAME, &manifest_bytes)?;
        write(&dir, SIGNATURE_NAME, &signature_bytes)?;

        let partial = dir.join(BINARY_PARTIAL);
        let have = fs::metadata(&partial).map_or(0, |m| m.len().min(manifest.size));
        let needed = (manifest.size - have).saturating_add(FREE_SPACE_MARGIN);
        match (self.free_bytes)(&dir) {
            Ok(free) if free < needed => {
                return Err(StageError::Failed(format!(
                    "not enough free space in {}: {} MiB needed for the download, {} MiB free",
                    self.layout.state_dir.display(),
                    needed.div_ceil(1024 * 1024),
                    free / (1024 * 1024)
                )));
            }
            Ok(_) => {}
            Err(e) => {
                return Err(StageError::Failed(format!(
                    "cannot check the free space in {}: {e}",
                    self.layout.state_dir.display()
                )));
            }
        }

        let validator = fetch::binary_validator(&release::hex(&manifest.sha256));
        fetch::download_binary(
            self.fetch,
            &directive.binary_url,
            &partial,
            manifest.size,
            &validator,
        )
        .map_err(|e| match e {
            FetchError::Transient(why) => StageError::Retry(why),
            FetchError::Permanent(why) => StageError::Failed(why),
            FetchError::RangeNotSatisfiable => {
                StageError::Retry("the server could not resume the download".into())
            }
        })?;

        // The whole file, checked as one: a resumed or damaged download is caught here.
        let checked = fs::File::open(&partial)
            .and_then(|file| release::check_binary(&manifest, file))
            .map_err(|e| StageError::Failed(format!("cannot read the downloaded binary: {e}")))?;
        if let Err(refusal) = checked {
            let _ = fs::remove_file(&partial);
            return Err(StageError::Failed(refusal_text(&refusal)));
        }
        let binary = dir.join(BINARY_STAGED);
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o700))
            .and_then(|()| fs::rename(&partial, &binary))
            .and_then(|()| fsx::sync_dir(&dir))
            .map_err(|e| StageError::Failed(format!("cannot stage the binary: {e}")))?;

        // Only now, with the signature and checksum verified, is the new binary run.
        (self.self_test)(&binary, offered).map_err(|why| {
            StageError::Failed(format!("the new binary failed its self-test: {why}"))
        })?;
        Ok(manifest)
    }

    /// Creates the staging directory (private) and removes what earlier updates left in `update/`.
    fn prepare(&self, dir: &Path, version: &str) -> Result<(), StageError> {
        let failed =
            |e: io::Error| StageError::Failed(format!("cannot prepare {}: {e}", dir.display()));
        let update = self.layout.update_dir();
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&update)
            .map_err(failed)?;
        // Other versions' leftovers and the previous binary, but not this version's partial download.
        for entry in fs::read_dir(&update).map_err(failed)?.flatten() {
            let name = entry.file_name();
            if name != version && name != "backup" {
                let path = entry.path();
                let _ = if path.is_dir() {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
            }
        }
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(failed)?;
        for name in [MANIFEST_NAME, SIGNATURE_NAME, BINARY_STAGED] {
            let _ = fs::remove_file(dir.join(name));
        }
        Ok(())
    }
}

fn small(fetch: &dyn Fetch, url: &str, what: &str) -> Result<Vec<u8>, StageError> {
    fetch::download_small(fetch, url, MAX_SMALL_BYTES).map_err(|e| match e {
        FetchError::Transient(why) => StageError::Retry(format!("the {what}: {why}")),
        FetchError::Permanent(why) => StageError::Failed(format!("the {what}: {why}")),
        FetchError::RangeNotSatisfiable => {
            StageError::Retry(format!("the {what} could not be downloaded"))
        }
    })
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StageError> {
    fsx::write_atomic(&dir.join(name), bytes, 0o600)
        .map_err(|e| StageError::Failed(format!("cannot write {name} in {}: {e}", dir.display())))
}

/// The refusal as the operator reads it, with what was refused.
pub fn refusal_text(refusal: &Refusal) -> String {
    format!("release refused: {refusal}")
}

/// Verifies a staged release again, as the supervisor does just before installing it: the files in
/// `dir` are the ones on disk now, not the ones checked earlier. Returns the manifest.
pub fn verify_staged(
    dir: &Path,
    keys: &[ReleaseKey],
    expect: &semver::Version,
    running: &semver::Version,
) -> Result<Manifest, String> {
    let read = |name: &str, max: u64| {
        fsx::read_regular(&dir.join(name), max, fsx::Symlinks::Refuse)
            .map_err(|e| format!("cannot read the staged {name}: {e}"))
    };
    let manifest_bytes = read(MANIFEST_NAME, MAX_SMALL_BYTES)?;
    let signature_bytes = read(SIGNATURE_NAME, MAX_SMALL_BYTES)?;
    let verified = release::verify_manifest(&manifest_bytes, &signature_bytes, keys)
        .map_err(|r| refusal_text(&r))?;
    let manifest = verified.manifest;
    if manifest.version != *expect {
        return Err(format!(
            "the staged manifest is for version {}, not {expect}",
            manifest.version
        ));
    }
    if manifest.version <= *running {
        return Err(format!(
            "version {} is not newer than the running version {running}",
            manifest.version
        ));
    }
    check_file(&dir.join(BINARY_STAGED), &manifest)?;
    Ok(manifest)
}

/// Checks the file at `path` against the manifest's size and SHA-256.
pub fn check_file(path: &Path, manifest: &Manifest) -> Result<(), String> {
    let file = fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !file
        .metadata()
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .is_file()
    {
        return Err(format!("{} is not a regular file", path.display()));
    }
    release::check_binary(manifest, file)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .map_err(|r| refusal_text(&r))
}

/// Runs `binary self-test --config CONFIG` and checks it reports `version`. The new binary runs with
/// an empty environment, no input, and a time limit.
pub fn run_self_test(
    binary: &Path,
    config: &Path,
    version: &semver::Version,
) -> Result<(), String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new(binary)
        .arg("self-test")
        .arg("--config")
        .arg(config)
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run it: {e}"))?;
    let read = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(pipe) = pipe {
                let _ = pipe.take(8 * 1024).read_to_end(&mut bytes);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let stdout = read(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let stderr = read(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + SELF_TEST_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "it did not finish within {} seconds",
                    SELF_TEST_TIMEOUT.as_secs()
                ));
            }
            Err(e) => return Err(format!("cannot wait for it: {e}")),
        }
    };
    let (stdout, stderr) = (
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default(),
    );
    if !status.success() {
        let why = if stderr.trim().is_empty() {
            stdout
        } else {
            stderr
        };
        return Err(format!(
            "it exited with {status}: {}",
            crate::logging::sanitize(why.trim(), 300)
        ));
    }
    let expected = format!("{SELF_TEST_OK} {version} ");
    if stdout.starts_with(&expected) {
        Ok(())
    } else {
        Err(format!(
            "it reported {:?} instead of version {version}",
            crate::logging::sanitize(stdout.lines().next().unwrap_or(""), 120)
        ))
    }
}

/// The first words of a successful self-test's output, followed by the version.
pub const SELF_TEST_OK: &str = "self-test OK: fleet-agent";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::release::KeyRole;
    use crate::test_support::TempDir;
    use crate::update::fetch::tests::FakeFetch;

    pub(crate) use crate::release::tests::{TestKey, manifest_for as manifest};

    pub const BASE: &str = "https://fleet-agent.example.lan/api/v1/releases";

    /// Puts a signed release for `version` on the fake server and returns its directive.
    pub fn publish(
        fetch: &FakeFetch,
        key: &TestKey,
        version: &str,
        binary: &[u8],
        rollout_id: u64,
    ) -> Directive {
        let manifest = manifest(binary, version);
        fetch.put(&format!("{BASE}/{version}/manifest"), &manifest);
        fetch.put(&format!("{BASE}/{version}/signature"), &key.sign(&manifest));
        fetch.put(&format!("{BASE}/{version}/binary"), binary);
        directive(version, rollout_id)
    }

    pub fn directive(version: &str, rollout_id: u64) -> Directive {
        Directive {
            rollout_id,
            version: semver::Version::parse(version).unwrap(),
            manifest_url: format!("{BASE}/{version}/manifest"),
            signature_url: format!("{BASE}/{version}/signature"),
            binary_url: format!("{BASE}/{version}/binary"),
        }
    }

    pub fn binary(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    struct Fixture {
        _dir: TempDir,
        layout: Layout,
        fetch: FakeFetch,
        key: TestKey,
        running: semver::Version,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = TempDir::new();
            let layout = Layout::new(dir.path("lib"), dir.path("state"));
            fs::create_dir_all(&layout.state_dir).unwrap();
            Self {
                _dir: dir,
                layout,
                fetch: FakeFetch::default(),
                key: TestKey::generate(),
                running: semver::Version::new(0, 1, 0),
            }
        }

        fn stage(
            &self,
            directive: &Directive,
            free: u64,
            self_test: Result<(), String>,
        ) -> Result<Manifest, StageError> {
            let keys = [self.key.release_key(KeyRole::Current)];
            let free_bytes = move |_: &Path| Ok(free);
            let self_test = move |_: &Path, _: &semver::Version| self_test.clone();
            Stager {
                layout: &self.layout,
                keys: &keys,
                fetch: &self.fetch,
                running: &self.running,
                free_bytes: &free_bytes,
                self_test: &self_test,
            }
            .stage(directive)
        }
    }

    const PLENTY: u64 = 10 << 30;

    #[test]
    fn a_signed_newer_release_is_downloaded_verified_and_staged() {
        let f = Fixture::new();
        let bin = binary(50_000);
        let d = publish(&f.fetch, &f.key, "0.2.0", &bin, 3);
        let manifest = f.stage(&d, PLENTY, Ok(())).unwrap();
        assert_eq!(manifest.version, semver::Version::new(0, 2, 0));
        let dir = f.layout.staging("0.2.0");
        assert_eq!(fs::read(dir.join(BINARY_STAGED)).unwrap(), bin);
        assert!(dir.join(MANIFEST_NAME).is_file() && dir.join(SIGNATURE_NAME).is_file());
        assert!(!dir.join(BINARY_PARTIAL).exists());
        // What was staged verifies again from disk, as the supervisor will.
        let keys = [f.key.release_key(KeyRole::Current)];
        verify_staged(&dir, &keys, &d.version, &f.running).unwrap();
    }

    fn refused(f: &Fixture, d: &Directive) -> String {
        match f.stage(d, PLENTY, Ok(())) {
            Err(StageError::Failed(why)) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_binary_is_refused() {
        let f = Fixture::new();
        let bin = binary(50_000);
        let d = publish(&f.fetch, &f.key, "0.2.0", &bin, 3);
        let mut evil = bin.clone();
        evil[10] ^= 0xff;
        f.fetch.put(&d.binary_url, &evil);
        let why = refused(&f, &d);
        assert!(why.contains("SHA-256"), "{why}");
        let dir = f.layout.staging("0.2.0");
        assert!(!dir.join(BINARY_STAGED).exists() && !dir.join(BINARY_PARTIAL).exists());
    }

    #[test]
    fn a_binary_of_the_wrong_size_is_refused() {
        let f = Fixture::new();
        let bin = binary(50_000);
        let d = publish(&f.fetch, &f.key, "0.2.0", &bin, 3);
        f.fetch.put(&d.binary_url, &binary(60_000));
        assert!(refused(&f, &d).contains("more bytes"), "size");
    }

    #[test]
    fn a_bad_unsigned_or_unknown_key_signature_is_refused() {
        let f = Fixture::new();
        let bin = binary(1000);
        let d = publish(&f.fetch, &f.key, "0.2.0", &bin, 3);

        // A manifest changed after signing.
        let changed = String::from_utf8(manifest(&bin, "0.2.0"))
            .unwrap()
            .replace("0.2.0", "0.9.0");
        f.fetch.put(&d.manifest_url, changed.as_bytes());
        assert!(refused(&f, &d).contains("signature is not valid"));

        // No signature at all.
        let d = publish(&f.fetch, &f.key, "0.2.0", &bin, 3);
        f.fetch.put(&d.signature_url, b"");
        assert!(refused(&f, &d).contains("not a minisign signature"));

        // Signed by a key the agent does not have.
        let other = TestKey::generate();
        let d = publish(&f.fetch, &other, "0.2.0", &bin, 3);
        assert!(refused(&f, &d).contains("does not trust"));
        assert!(!f.layout.staging("0.2.0").join(BINARY_STAGED).exists());
    }

    #[test]
    fn an_older_or_the_same_version_is_refused_without_downloading() {
        let f = Fixture::new();
        for version in ["0.0.9", "0.1.0"] {
            let d = publish(&f.fetch, &f.key, version, &binary(100), 3);
            let why = refused(&f, &d);
            assert!(why.contains("not newer"), "{why}");
        }
        assert!(f.fetch.requests.lock().unwrap().is_empty());
        // A pre-release of the running version is older than it.
        let d = publish(&f.fetch, &f.key, "0.1.0-rc.1", &binary(100), 3);
        assert!(refused(&f, &d).contains("not newer"));
    }

    #[test]
    fn a_validly_signed_older_manifest_behind_a_newer_directive_is_refused() {
        // The server offers 0.3.0 but points at the signed manifest of 0.0.9.
        let f = Fixture::new();
        let old = publish(&f.fetch, &f.key, "0.0.9", &binary(100), 3);
        let mut d = directive("0.3.0", 3);
        d.manifest_url = old.manifest_url;
        d.signature_url = old.signature_url;
        d.binary_url = old.binary_url;
        let why = refused(&f, &d);
        assert!(
            why.contains("0.0.9") && why.contains("not the offered 0.3.0"),
            "{why}"
        );
    }

    #[test]
    fn a_release_without_a_built_in_key_is_refused() {
        let f = Fixture::new();
        let d = publish(&f.fetch, &f.key, "0.2.0", &binary(100), 3);
        let self_test = |_: &Path, _: &semver::Version| Ok(());
        let free = |_: &Path| Ok(PLENTY);
        let result = Stager {
            layout: &f.layout,
            keys: &[],
            fetch: &f.fetch,
            running: &f.running,
            free_bytes: &free,
            self_test: &self_test,
        }
        .stage(&d);
        match result {
            Err(StageError::Failed(why)) => assert!(why.contains("no usable release key"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn running_out_of_disk_space_fails_cleanly_before_the_binary_is_fetched() {
        let f = Fixture::new();
        let d = publish(&f.fetch, &f.key, "0.2.0", &binary(5_000_000), 3);
        let result = f.stage(&d, 1024 * 1024, Ok(()));
        match result {
            Err(StageError::Failed(why)) => assert!(why.contains("not enough free space"), "{why}"),
            other => panic!("{other:?}"),
        }
        let requests = f.fetch.requests.lock().unwrap().clone();
        assert!(requests.iter().all(|(url, _)| !url.ends_with("/binary")));
        assert!(!f.layout.staging("0.2.0").join(BINARY_PARTIAL).exists());
    }

    #[test]
    fn an_interrupted_download_resumes_on_the_next_attempt() {
        let f = Fixture::new();
        let bin = binary(200_000);
        let d = publish(&f.fetch, &f.key, "0.2.0", &bin, 3);
        let first = {
            let keys = [f.key.release_key(KeyRole::Current)];
            let free = |_: &Path| Ok(PLENTY);
            let self_test = |_: &Path, _: &semver::Version| Ok(());
            let cutting = CutBinary {
                inner: &f.fetch,
                cut: Some(70_000),
            };
            Stager {
                layout: &f.layout,
                keys: &keys,
                fetch: &cutting,
                running: &f.running,
                free_bytes: &free,
                self_test: &self_test,
            }
            .stage(&d)
        };
        assert!(matches!(first, Err(StageError::Retry(_))), "{first:?}");
        let partial = f.layout.staging("0.2.0").join(BINARY_PARTIAL);
        assert_eq!(fs::metadata(&partial).unwrap().len(), 70_000);

        f.stage(&d, PLENTY, Ok(())).unwrap();
        assert_eq!(
            fs::read(f.layout.staging("0.2.0").join(BINARY_STAGED)).unwrap(),
            bin
        );
        let resumed = f
            .fetch
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(url, from)| url.ends_with("/binary") && *from == Some(70_000));
        assert!(
            resumed,
            "the second attempt asked for the bytes after 70000"
        );
    }

    /// Cuts only the binary download short.
    struct CutBinary<'a> {
        inner: &'a FakeFetch,
        cut: Option<usize>,
    }

    impl Fetch for CutBinary<'_> {
        fn open(
            &self,
            url: &str,
            resume: Option<fetch::Resume<'_>>,
        ) -> Result<fetch::Opened, FetchError> {
            if url.ends_with("/binary") {
                *self.inner.cut.lock().unwrap() = self.cut;
            }
            self.inner.open(url, resume)
        }
    }

    #[test]
    fn a_failed_self_test_refuses_the_release() {
        let f = Fixture::new();
        let d = publish(&f.fetch, &f.key, "0.2.0", &binary(1000), 3);
        match f.stage(&d, PLENTY, Err("the config is not valid".into())) {
            Err(StageError::Failed(why)) => {
                assert!(
                    why.contains("failed its self-test") && why.contains("config"),
                    "{why}"
                )
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_transient_download_failure_is_retried_not_reported() {
        let f = Fixture::new();
        let d = publish(&f.fetch, &f.key, "0.2.0", &binary(1000), 3);
        f.fetch.errors.lock().unwrap().insert(
            d.manifest_url.clone(),
            FetchError::Transient("cannot reach the download address".into()),
        );
        assert!(matches!(
            f.stage(&d, PLENTY, Ok(())),
            Err(StageError::Retry(_))
        ));
    }

    #[test]
    fn a_missing_release_is_reported() {
        let f = Fixture::new();
        let d = directive("0.2.0", 3);
        assert!(refused(&f, &d).contains("404"));
    }

    #[test]
    fn directives_are_parsed_strictly() {
        let good = serde_json::json!({
            "rollout_id": 4, "version": "1.2.3",
            "manifest_url": "https://h/m", "signature_url": "https://h/s", "binary_url": "https://h/b"
        });
        assert_eq!(Directive::parse(&good).unwrap().rollout_id, 4);
        for (field, value) in [
            ("version", serde_json::json!("../1.2.3")),
            ("version", serde_json::json!("1.2.3+x")),
            ("rollout_id", serde_json::json!(0)),
            ("rollout_id", serde_json::json!("4")),
            ("binary_url", serde_json::json!(7)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(Directive::parse(&bad).is_none(), "{bad}");
        }
    }
}
