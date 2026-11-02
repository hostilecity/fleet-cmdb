//! Downloading a release: the manifest, its signature, and the binary (P1-A11).
//!
//! Downloads are bounded: the manifest and signature to a few KiB, the binary to exactly the size the
//! signed manifest gives. The binary is resumable: bytes already in the staging directory are kept,
//! and the rest is asked for with a `Range` request conditional on the file's `ETag` (the server uses
//! the manifest's SHA-256 for the binary, `docs/api/README.md`). Whatever arrives is only trusted after
//! [`crate::release::check_binary`] has passed over the whole file.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::client::{ApiError, Client};

/// Why a download did not complete.
#[derive(Debug, PartialEq, Eq)]
pub enum FetchError {
    /// Worth trying again later: the network, a busy server, a download that ended early.
    Transient(String),
    /// Trying again will not help: the server does not have the file, or sent too much.
    Permanent(String),
    /// The server cannot serve the byte range asked for.
    RangeNotSatisfiable,
}

/// An open download.
pub struct Opened {
    /// The body starts at the requested byte (`206`), not at the start of the file (`200`).
    pub partial: bool,
    pub body: Box<dyn Read>,
}

/// Where the byte range of a resumed download starts, and the validator it depends on.
pub struct Resume<'a> {
    pub from: u64,
    /// The `ETag` of the file the bytes so far came from, as the server sent it (quoted).
    pub validator: &'a str,
}

/// Opens release files. [`Client`] in production; a fake in tests.
pub trait Fetch: Send + Sync {
    fn open(&self, url: &str, resume: Option<Resume<'_>>) -> Result<Opened, FetchError>;
}

impl Fetch for Client {
    fn open(&self, url: &str, resume: Option<Resume<'_>>) -> Result<Opened, FetchError> {
        let resume = resume.map(|r| (r.from, r.validator));
        match self.open_download(url, resume) {
            Ok(download) => Ok(Opened {
                partial: download.partial,
                body: Box::new(download.body.into_reader()),
            }),
            Err(ApiError::Rejected { status: 416, .. }) => Err(FetchError::RangeNotSatisfiable),
            Err(
                e @ (ApiError::Transport(_)
                | ApiError::RateLimited { .. }
                | ApiError::Server { .. }),
            ) => Err(FetchError::Transient(describe(&e))),
            Err(e) => Err(FetchError::Permanent(describe(&e))),
        }
    }
}

fn describe(error: &ApiError) -> String {
    match error {
        ApiError::Transport(why) => format!("cannot reach the download address ({why})"),
        ApiError::RateLimited { .. } => "the server is limiting downloads (429)".into(),
        other => match other.status() {
            404 => "the server does not have this release (404)".into(),
            status => format!("the download was refused (HTTP {status})"),
        },
    }
}

/// The validator the server gives the binary: its SHA-256, quoted, which the signed manifest already
/// states (ETag rules of `docs/api/README.md`).
pub fn binary_validator(sha256_hex: &str) -> String {
    format!("\"{sha256_hex}\"")
}

/// Downloads a small file (a manifest or a signature) of at most `max` bytes.
pub fn download_small(fetch: &dyn Fetch, url: &str, max: u64) -> Result<Vec<u8>, FetchError> {
    let mut body = fetch.open(url, None)?.body.take(max + 1);
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes)
        .map_err(|e| FetchError::Transient(format!("the download was interrupted ({e})")))?;
    if bytes.len() as u64 > max {
        return Err(FetchError::Permanent(format!(
            "the file is larger than the {max} bytes allowed"
        )));
    }
    Ok(bytes)
}

/// Downloads the binary of `size` bytes into `partial`, continuing from what is already there.
///
/// Returns once `partial` holds exactly `size` bytes; the caller then checks its SHA-256. A file that
/// ends early is [`FetchError::Transient`] and keeps what arrived, for the next attempt to continue.
/// More than `size` bytes, or no room on the disk, is [`FetchError::Permanent`] and removes the file.
pub fn download_binary(
    fetch: &dyn Fetch,
    url: &str,
    partial: &Path,
    size: u64,
    validator: &str,
) -> Result<(), FetchError> {
    let mut have = match fs::symlink_metadata(partial) {
        Ok(m) if m.is_file() => m.len(),
        Ok(_) => {
            let _ = fs::remove_file(partial);
            0
        }
        Err(_) => 0,
    };
    if have > size {
        let _ = fs::remove_file(partial);
        have = 0;
    }
    if have == size {
        return Ok(());
    }
    let resume = (have > 0).then_some(Resume {
        from: have,
        validator,
    });
    let opened = match fetch.open(url, resume) {
        Err(FetchError::RangeNotSatisfiable) => {
            // The bytes kept do not fit what the server has; start again from the beginning.
            let _ = fs::remove_file(partial);
            have = 0;
            fetch.open(url, None)?
        }
        other => other?,
    };
    let append = opened.partial && have > 0;
    if !append {
        have = 0;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(partial)
        .map_err(|e| write_error(partial, &e))?;
    let want = size - have;
    let mut body = opened.body.take(want + 1);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut got = 0u64;
    let result = loop {
        match body.read(&mut buffer) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Err(e) = file.write_all(&buffer[..n]) {
                    break Err(write_error(partial, &e));
                }
                got += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                break Err(FetchError::Transient(format!(
                    "the download was interrupted ({e})"
                )));
            }
        }
    };
    let synced = file.sync_all();
    match result {
        Err(e @ FetchError::Permanent(_)) => {
            let _ = fs::remove_file(partial);
            return Err(e);
        }
        Err(e) => return Err(e),
        Ok(()) => {}
    }
    synced.map_err(|e| write_error(partial, &e))?;
    if got > want {
        let _ = fs::remove_file(partial);
        return Err(FetchError::Permanent(
            "the server sent more bytes than the signed manifest says the binary has".into(),
        ));
    }
    if got < want {
        return Err(FetchError::Transient(format!(
            "the download ended after {} of {size} bytes",
            have + got
        )));
    }
    Ok(())
}

/// A failed write is not retried: a full disk stays full.
fn write_error(path: &Path, error: &io::Error) -> FetchError {
    let why = if error.raw_os_error() == Some(libc::ENOSPC) {
        "there is no space left on the disk".to_owned()
    } else {
        error.to_string()
    };
    FetchError::Permanent(format!("cannot write {}: {why}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    /// Files by URL. A download can be made to end early after `cut` bytes, or to be unavailable.
    #[derive(Default)]
    pub struct FakeFetch {
        pub files: Mutex<HashMap<String, Vec<u8>>>,
        /// Serve at most this many bytes of the next binary download, then end the body.
        pub cut: Mutex<Option<usize>>,
        /// Ignore ranges and always answer `200` with the whole file.
        pub ignore_ranges: Mutex<bool>,
        /// Errors by URL, taken before any file.
        pub errors: Mutex<HashMap<String, FetchError>>,
        /// Every request: URL and the byte it started from.
        pub requests: Mutex<Vec<(String, Option<u64>)>>,
    }

    impl FakeFetch {
        pub fn put(&self, url: &str, bytes: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(url.to_owned(), bytes.to_vec());
        }
    }

    impl Fetch for FakeFetch {
        fn open(&self, url: &str, resume: Option<Resume<'_>>) -> Result<Opened, FetchError> {
            self.requests
                .lock()
                .unwrap()
                .push((url.to_owned(), resume.as_ref().map(|r| r.from)));
            if let Some(error) = self.errors.lock().unwrap().remove(url) {
                return Err(error);
            }
            let files = self.files.lock().unwrap();
            let Some(file) = files.get(url) else {
                return Err(FetchError::Permanent(
                    "the server does not have this release (404)".into(),
                ));
            };
            let ignore = *self.ignore_ranges.lock().unwrap();
            let (partial, mut bytes) = match resume {
                Some(r) if !ignore => {
                    if r.from as usize > file.len() {
                        return Err(FetchError::RangeNotSatisfiable);
                    }
                    (true, file[r.from as usize..].to_vec())
                }
                _ => (false, file.clone()),
            };
            if let Some(cut) = self.cut.lock().unwrap().take() {
                bytes.truncate(cut);
            }
            Ok(Opened {
                partial,
                body: Box::new(Cursor::new(bytes)),
            })
        }
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn a_small_file_is_downloaded_within_its_limit() {
        let fetch = FakeFetch::default();
        fetch.put("https://h/m", b"{}");
        assert_eq!(download_small(&fetch, "https://h/m", 4).unwrap(), b"{}");
        fetch.put("https://h/big", &data(5000));
        assert!(matches!(
            download_small(&fetch, "https://h/big", 4096),
            Err(FetchError::Permanent(_))
        ));
        assert!(matches!(
            download_small(&fetch, "https://h/missing", 4096),
            Err(FetchError::Permanent(_))
        ));
    }

    #[test]
    fn an_interrupted_download_resumes_from_the_bytes_it_has() {
        let dir = TempDir::new();
        let partial = dir.path("fleet-agent.partial");
        let file = data(100_000);
        let fetch = FakeFetch::default();
        fetch.put("https://h/b", &file);
        *fetch.cut.lock().unwrap() = Some(40_000);
        let error = download_binary(&fetch, "https://h/b", &partial, 100_000, "\"x\"").unwrap_err();
        assert!(matches!(error, FetchError::Transient(_)), "{error:?}");
        assert_eq!(fs::metadata(&partial).unwrap().len(), 40_000);

        download_binary(&fetch, "https://h/b", &partial, 100_000, "\"x\"").unwrap();
        assert_eq!(fs::read(&partial).unwrap(), file);
        let requests = fetch.requests.lock().unwrap().clone();
        assert_eq!(requests[0].1, None);
        assert_eq!(requests[1].1, Some(40_000), "the second request resumes");
    }

    #[test]
    fn a_server_that_answers_a_range_with_the_whole_file_is_handled() {
        let dir = TempDir::new();
        let partial = dir.path("p");
        let file = data(10_000);
        fs::write(&partial, &file[..3000]).unwrap();
        let fetch = FakeFetch::default();
        fetch.put("https://h/b", &file);
        *fetch.ignore_ranges.lock().unwrap() = true;
        download_binary(&fetch, "https://h/b", &partial, 10_000, "\"x\"").unwrap();
        assert_eq!(fs::read(&partial).unwrap(), file);
    }

    #[test]
    fn bytes_that_do_not_fit_the_file_start_over() {
        let dir = TempDir::new();
        let partial = dir.path("p");
        let file = data(10_000);
        // Longer than the file the server has now (a different release was published under the name).
        fs::write(&partial, data(9_999)).unwrap();
        let fetch = FakeFetch::default();
        fetch.put("https://h/b", &file[..9_000]);
        let error = download_binary(&fetch, "https://h/b", &partial, 10_000, "\"x\"").unwrap_err();
        assert!(matches!(error, FetchError::Transient(_)), "{error:?}");
        assert_eq!(fs::metadata(&partial).unwrap().len(), 9_000);
        // A partial file longer than the manifest's size is discarded.
        fs::write(&partial, data(20_000)).unwrap();
        fetch.put("https://h/b", &file);
        download_binary(&fetch, "https://h/b", &partial, 10_000, "\"x\"").unwrap();
        assert_eq!(fs::read(&partial).unwrap(), file);
    }

    #[test]
    fn more_bytes_than_the_manifest_gives_are_refused_and_removed() {
        let dir = TempDir::new();
        let partial = dir.path("p");
        let fetch = FakeFetch::default();
        fetch.put("https://h/b", &data(10_001));
        let error = download_binary(&fetch, "https://h/b", &partial, 10_000, "\"x\"").unwrap_err();
        assert!(matches!(error, FetchError::Permanent(_)), "{error:?}");
        assert!(!partial.exists());
    }

    #[test]
    fn a_planted_link_is_replaced_never_written_through() {
        let dir = TempDir::new();
        let partial = dir.path("p");
        let target = dir.write("target", "untouched");
        std::os::unix::fs::symlink(&target, &partial).unwrap();
        let fetch = FakeFetch::default();
        fetch.put("https://h/b", &data(100));
        download_binary(&fetch, "https://h/b", &partial, 100, "\"x\"").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        assert_eq!(fs::read(&partial).unwrap(), data(100));
    }

    #[test]
    fn a_write_that_runs_out_of_space_is_a_clean_permanent_failure() {
        let dir = TempDir::new();
        let partial = dir.path("p");
        assert_eq!(
            write_error(&partial, &io::Error::from_raw_os_error(libc::ENOSPC)),
            FetchError::Permanent(format!(
                "cannot write {}: there is no space left on the disk",
                partial.display()
            ))
        );
    }
}
