//! Test helpers: temporary directories, a throwaway certificate authority, and a minimal local TLS
//! server. Compiled only for tests. Certificates are generated per test for `localhost`; nothing is
//! checked in.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A directory under the system temp dir, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!(
            "fleet-agent-test-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes `contents` to `name` with mode `0600` and returns its path.
    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    pub fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A throwaway CA and a `localhost` server certificate it issued.
pub struct TestPki {
    pub ca_pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

impl TestPki {
    pub fn generate() -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &ca)
            .unwrap();
        Self {
            ca_pem: ca.pem(),
            chain: vec![leaf.der().clone(), ca.der().clone()],
            key: leaf_key.serialize_der(),
        }
    }

    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                self.chain.clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone())),
            )
            .unwrap();
        Arc::new(config)
    }
}

/// A local HTTPS server that answers one canned reply per connection, then stops.
pub struct TlsServer {
    pub port: u16,
    handle: JoinHandle<Vec<String>>,
}

impl TlsServer {
    /// Serves `replies` (complete HTTP responses) one per connection, in order. A connection whose
    /// TLS handshake fails uses up its reply without recording a request.
    pub fn start(pki: &TestPki, replies: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = pki.server_config();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let deadline = Instant::now() + Duration::from_secs(20);
                let tcp = loop {
                    match listener.accept() {
                        Ok((tcp, _)) => break tcp,
                        Err(_) if Instant::now() < deadline => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => return requests,
                    }
                };
                tcp.set_nonblocking(false).unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let Some(request) = read_request(&mut tls) else {
                    continue;
                };
                requests.push(request);
                let _ = tls.write_all(reply.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
            requests
        });
        Self { port, handle }
    }

    /// Waits for the server to finish and returns the requests it received.
    pub fn finish(self) -> Vec<String> {
        self.handle.join().unwrap()
    }
}

fn read_request(stream: &mut impl Read) -> Option<String> {
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let length = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    head.push_str(&String::from_utf8_lossy(&body));
    Some(head)
}
