//! Release verification tests. Every key is generated here for the test and thrown away; no private
//! key is checked in (P1-PACKAGING).

use std::io::Cursor;

use super::*;

/// A throwaway minisign key pair, as `minisign -G` would make.
struct TestKey {
    pair: minisign::KeyPair,
}

impl TestKey {
    fn generate() -> Self {
        Self {
            pair: minisign::KeyPair::generate_unencrypted_keypair().expect("generate a key"),
        }
    }

    /// The `.pub` file text.
    fn pub_file(&self) -> String {
        self.pair.pk.to_box().expect("public key box").into_string()
    }

    /// A `.minisig` over `data` (pre-hashed, as minisign signs by default).
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        minisign::sign(
            Some(&self.pair.pk),
            &self.pair.sk,
            Cursor::new(data),
            Some("timestamp:1767268800\tfile:fleet-agent-1.2.3-x86_64-unknown-linux-musl.manifest.json hashed"),
            None,
        )
        .expect("sign")
        .into_string()
        .into_bytes()
    }

    fn release_key(&self, role: KeyRole) -> ReleaseKey {
        ReleaseKey {
            role,
            key: parse_key_file(&self.pub_file()).unwrap().unwrap(),
        }
    }
}

const BINARY: &[u8] = b"\x7fELF not really a binary, but bytes to check";

fn manifest_for(binary: &[u8], version: &str) -> Vec<u8> {
    let sha = hex(ring::digest::digest(&ring::digest::SHA256, binary).as_ref());
    format!(
        "{{\"format\":\"{MANIFEST_FORMAT}\",\"version\":\"{version}\",\"target\":\"{TARGET}\",\"sha256\":\"{sha}\",\"size\":{}}}\n",
        binary.len()
    )
    .into_bytes()
}

fn signed(key: &TestKey, manifest: &[u8]) -> Vec<u8> {
    key.sign(manifest)
}

#[test]
fn a_release_signed_by_the_current_key_verifies() {
    let key = TestKey::generate();
    let manifest = manifest_for(BINARY, "1.2.3");
    let verified = verify_manifest(
        &manifest,
        &signed(&key, &manifest),
        &[key.release_key(KeyRole::Current)],
    )
    .expect("verifies");
    assert_eq!(verified.key, KeyRole::Current);
    assert_eq!(verified.manifest.version, semver::Version::new(1, 2, 3));
    assert_eq!(verified.manifest.target, TARGET);
    assert_eq!(verified.manifest.size, BINARY.len() as u64);
    assert_eq!(check_binary(&verified.manifest, BINARY).unwrap(), Ok(()));
}

#[test]
fn a_release_signed_by_the_next_key_verifies_during_a_rotation() {
    let (current, next) = (TestKey::generate(), TestKey::generate());
    let keys = [
        current.release_key(KeyRole::Current),
        next.release_key(KeyRole::Next),
    ];
    let manifest = manifest_for(BINARY, "2.0.0");
    let verified = verify_manifest(&manifest, &signed(&next, &manifest), &keys).unwrap();
    assert_eq!(verified.key, KeyRole::Next);
    let verified = verify_manifest(&manifest, &signed(&current, &manifest), &keys).unwrap();
    assert_eq!(verified.key, KeyRole::Current);
}

#[test]
fn a_signature_by_an_unknown_key_is_refused() {
    let (trusted, other) = (TestKey::generate(), TestKey::generate());
    let manifest = manifest_for(BINARY, "1.2.3");
    assert_eq!(
        verify_manifest(
            &manifest,
            &signed(&other, &manifest),
            &[trusted.release_key(KeyRole::Current)]
        ),
        Err(Refusal::UnknownKey)
    );
}

#[test]
fn a_tampered_manifest_is_refused() {
    let key = TestKey::generate();
    let keys = [key.release_key(KeyRole::Current)];
    let manifest = manifest_for(BINARY, "1.2.3");
    let signature = signed(&key, &manifest);
    // Same length, different version: the signature no longer matches.
    let tampered = String::from_utf8(manifest.clone())
        .unwrap()
        .replace("1.2.3", "9.2.3");
    assert_eq!(
        verify_manifest(tampered.as_bytes(), &signature, &keys),
        Err(Refusal::BadSignature)
    );
    // Even trailing whitespace changes the signed bytes.
    let mut padded = manifest.clone();
    padded.push(b' ');
    assert_eq!(
        verify_manifest(&padded, &signature, &keys),
        Err(Refusal::BadSignature)
    );
}

#[test]
fn a_signature_with_a_modified_trusted_comment_is_refused() {
    // minisign's global signature covers the trusted comment.
    let key = TestKey::generate();
    let manifest = manifest_for(BINARY, "1.2.3");
    let signature = String::from_utf8(signed(&key, &manifest)).unwrap();
    let modified = signature.replace("timestamp:1767268800", "timestamp:1767268801");
    assert_ne!(modified, signature);
    assert_eq!(
        verify_manifest(
            &manifest,
            modified.as_bytes(),
            &[key.release_key(KeyRole::Current)]
        ),
        Err(Refusal::BadSignature)
    );
}

#[test]
fn malformed_and_legacy_signatures_are_refused() {
    let key = TestKey::generate();
    let keys = [key.release_key(KeyRole::Current)];
    let manifest = manifest_for(BINARY, "1.2.3");
    for junk in [
        &b""[..],
        b"not a signature",
        b"\xff\xfe",
        b"untrusted comment: x\nAAAA\ntrusted comment: y\nAAAA\n",
    ] {
        assert_eq!(
            verify_manifest(&manifest, junk, &keys),
            Err(Refusal::MalformedSignature),
            "{junk:?}"
        );
    }
    // minisign's own published test vector: a legacy (not pre-hashed) signature over "test".
    let legacy_key = ReleaseKey {
        role: KeyRole::Current,
        key: parse_key_file(
            "untrusted comment: minisign public key E7620F1842B4E81F\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n",
        )
        .unwrap()
        .unwrap(),
    };
    let legacy = "untrusted comment: signature from minisign secret key\n\
RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n\
trusted comment: timestamp:1555779966\tfile:test\n\
QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==\n";
    assert_eq!(
        verify_manifest(b"test", legacy.as_bytes(), &[legacy_key]),
        Err(Refusal::LegacySignature)
    );
}

#[test]
fn without_keys_nothing_verifies() {
    let key = TestKey::generate();
    let manifest = manifest_for(BINARY, "1.2.3");
    assert!(matches!(
        verify_manifest(&manifest, &signed(&key, &manifest), &[]),
        Err(Refusal::NoKeys(_))
    ));
}

/// A manifest signed by a trusted key but with bad content is still refused.
fn refusal_for_signed(manifest: &str) -> Refusal {
    let key = TestKey::generate();
    verify_manifest(
        manifest.as_bytes(),
        &key.sign(manifest.as_bytes()),
        &[key.release_key(KeyRole::Current)],
    )
    .expect_err(manifest)
}

#[test]
fn signed_manifests_with_bad_content_are_refused() {
    let sha = "a".repeat(64);
    let good = |field: &str, value: &str| {
        let mut fields = vec![
            ("format", format!("\"{MANIFEST_FORMAT}\"")),
            ("version", "\"1.2.3\"".to_owned()),
            ("target", format!("\"{TARGET}\"")),
            ("sha256", format!("\"{sha}\"")),
            ("size", "1000".to_owned()),
        ];
        for (name, v) in &mut fields {
            if *name == field {
                *v = value.to_owned();
            }
        }
        let body: Vec<String> = fields
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect();
        format!("{{{}}}", body.join(","))
    };
    // The template itself is fine.
    let key = TestKey::generate();
    let manifest = good("", "");
    verify_manifest(
        manifest.as_bytes(),
        &key.sign(manifest.as_bytes()),
        &[key.release_key(KeyRole::Current)],
    )
    .expect("template verifies");

    let malformed = [
        good("format", "\"fleet-agent-release-manifest/2\""),
        good("format", ""),
        good("version", "\"1.2\""),
        good("version", "\"v1.2.3\""),
        good("version", "\"01.2.3\""),
        good("version", "\"1.2.3+build.5\""),
        good("version", &format!("\"1.2.3-{}\"", "a".repeat(60))),
        good("version", "123"),
        good("sha256", &format!("\"{}\"", "A".repeat(64))),
        good("sha256", &format!("\"{}\"", "a".repeat(63))),
        good("sha256", &format!("\"{}g\"", "a".repeat(63))),
        good("size", "0"),
        good("size", &(MAX_BINARY_BYTES + 1).to_string()),
        good("size", "-1"),
        good("size", ""),
        format!("{},\"extra\":1}}", good("", "").trim_end_matches('}')),
        "[]".to_owned(),
        "not json".to_owned(),
    ];
    for manifest in &malformed {
        assert!(
            matches!(refusal_for_signed(manifest), Refusal::MalformedManifest(_)),
            "{manifest}"
        );
    }
    assert_eq!(
        refusal_for_signed(&good("target", "\"aarch64-unknown-linux-musl\"")),
        Refusal::WrongTarget("aarch64-unknown-linux-musl".into())
    );
}

#[test]
fn pre_release_versions_are_accepted_and_ordered_before_the_release() {
    let key = TestKey::generate();
    let manifest = manifest_for(BINARY, "1.3.0-rc.1");
    let verified = verify_manifest(
        &manifest,
        &key.sign(&manifest),
        &[key.release_key(KeyRole::Current)],
    )
    .unwrap();
    assert!(verified.manifest.version < semver::Version::new(1, 3, 0));
    assert!(verified.manifest.version > semver::Version::new(1, 2, 9));
}

#[test]
fn a_binary_of_the_wrong_size_or_content_is_refused() {
    let key = TestKey::generate();
    let manifest_bytes = manifest_for(BINARY, "1.2.3");
    let manifest = verify_manifest(
        &manifest_bytes,
        &key.sign(&manifest_bytes),
        &[key.release_key(KeyRole::Current)],
    )
    .unwrap()
    .manifest;
    let mut longer = BINARY.to_vec();
    longer.push(0);
    assert_eq!(
        check_binary(&manifest, &longer[..]).unwrap(),
        Err(Refusal::SizeMismatch {
            expected: BINARY.len() as u64,
            actual: BINARY.len() as u64 + 1
        })
    );
    assert_eq!(
        check_binary(&manifest, &BINARY[1..]).unwrap(),
        Err(Refusal::SizeMismatch {
            expected: BINARY.len() as u64,
            actual: BINARY.len() as u64 - 1
        })
    );
    let mut flipped = BINARY.to_vec();
    flipped[10] ^= 1;
    assert_eq!(
        check_binary(&manifest, &flipped[..]).unwrap(),
        Err(Refusal::ChecksumMismatch)
    );
}

#[test]
fn an_endless_binary_is_read_only_to_one_byte_past_the_size() {
    let manifest = Manifest {
        version: semver::Version::new(1, 0, 0),
        target: TARGET.into(),
        sha256: [0; 32],
        size: 10,
    };
    let result = check_binary(&manifest, io::repeat(0)).unwrap();
    assert_eq!(
        result,
        Err(Refusal::SizeMismatch {
            expected: 10,
            actual: 11
        })
    );
}

#[test]
fn the_embedded_key_files_parse() {
    // Fails the build's tests if a key file is edited into something the agent cannot read.
    let keys = embedded_keys().expect("release-keys/*.pub parse");
    assert!(keys.len() <= 2);
    if let Some(first) = keys.first() {
        assert_eq!(first.role, KeyRole::Current);
    }
}

#[test]
fn key_files_are_strict() {
    let (a, b) = (TestKey::generate(), TestKey::generate());
    let (a_pub, b_pub) = (a.pub_file(), b.pub_file());
    let none = "# no key yet\n\n# still none\n";
    assert_eq!(keys_from(none, none).unwrap().len(), 0);
    let keys = keys_from(&format!("# notes\n{a_pub}"), none).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].role, KeyRole::Current);
    let keys = keys_from(&a_pub, &b_pub).unwrap();
    assert_eq!(
        keys.iter().map(|k| k.role).collect::<Vec<_>>(),
        [KeyRole::Current, KeyRole::Next]
    );

    assert!(keys_from(none, &b_pub).is_err(), "next without current");
    assert!(keys_from(&a_pub, &a_pub).is_err(), "the same key twice");
    let key_line = a_pub.lines().nth(1).unwrap().to_owned();
    for bad in [
        key_line.clone(),
        format!("{a_pub}{b_pub}"),
        format!(
            "untrusted comment: x\n{}\n",
            &key_line[..key_line.len() - 4]
        ),
        "untrusted comment: x\nnot base64\n".to_owned(),
        // A secret key file is not a public key.
        a.pair
            .sk
            .to_box(None)
            .expect("secret key box")
            .into_string(),
    ] {
        assert!(keys_from(&bad, none).is_err(), "{bad}");
    }
}

#[test]
fn sha256_parsing_is_strict() {
    assert_eq!(parse_sha256(&"0".repeat(64)), Some([0; 32]));
    let digest = ring::digest::digest(&ring::digest::SHA256, b"abc");
    assert_eq!(
        parse_sha256(&hex(digest.as_ref())).unwrap(),
        digest.as_ref()
    );
    assert_eq!(parse_sha256(&"0".repeat(62)), None);
    assert_eq!(parse_sha256(&format!("{}é", "0".repeat(62))), None);
    assert_eq!(parse_sha256(&"F".repeat(64)), None);
}

#[test]
fn verify_release_arguments_parse() {
    let args = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
    assert_eq!(
        parse_args(args(&[
            "--manifest",
            "m.json",
            "--signature=m.json.minisig",
            "--binary",
            "bin"
        ])),
        Ok(Command::Verify {
            manifest: "m.json".into(),
            signature: "m.json.minisig".into(),
            binary: "bin".into(),
        })
    );
    assert_eq!(parse_args(args(&["--help"])), Ok(Command::Help));
    for bad in [
        &["--manifest", "m"][..],
        &["--manifest", "m", "--signature", "s"],
        &[
            "--manifest",
            "m",
            "--manifest",
            "m",
            "--signature",
            "s",
            "--binary",
            "b",
        ],
        &["--manifest=", "--signature", "s", "--binary", "b"],
        &[
            "--manifest",
            "m",
            "--signature",
            "s",
            "--binary",
            "b",
            "extra",
        ],
        &["--bogus"],
        &["--binary"],
    ] {
        assert!(parse_args(args(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn verify_files_checks_everything_on_disk() {
    let dir = crate::test_support::TempDir::new();
    let key = TestKey::generate();
    let keys = [key.release_key(KeyRole::Current)];
    let manifest = manifest_for(BINARY, "1.2.3");
    std::fs::write(dir.path("m.json"), &manifest).unwrap();
    std::fs::write(dir.path("m.json.minisig"), key.sign(&manifest)).unwrap();
    std::fs::write(dir.path("bin"), BINARY).unwrap();
    std::fs::write(dir.path("other"), b"another binary").unwrap();
    std::fs::create_dir(dir.path("dir")).unwrap();
    let run = |m: &str, s: &str, b: &str| {
        verify_files_with(&keys, &dir.path(m), &dir.path(s), &dir.path(b))
    };

    let verified = run("m.json", "m.json.minisig", "bin")
        .ok()
        .expect("verifies");
    assert_eq!(verified.manifest.version.to_string(), "1.2.3");
    assert!(matches!(
        run("m.json", "m.json.minisig", "other"),
        Err(Failure::Refused(Refusal::SizeMismatch { .. }))
    ));
    for (m, s, b) in [
        ("missing", "m.json.minisig", "bin"),
        ("m.json", "missing", "bin"),
        ("m.json", "m.json.minisig", "missing"),
        ("m.json", "m.json.minisig", "dir"),
        ("dir", "m.json.minisig", "bin"),
    ] {
        assert!(
            matches!(run(m, s, b), Err(Failure::Unreadable(_))),
            "{m} {s} {b}"
        );
    }
    // An oversized manifest is not read.
    std::fs::write(dir.path("big.json"), vec![b' '; 8192]).unwrap();
    assert!(matches!(
        run("big.json", "m.json.minisig", "bin"),
        Err(Failure::Unreadable(_))
    ));

    // This test binary embeds whatever release-keys/ holds, never this throwaway key.
    assert!(matches!(
        verify_files(
            &dir.path("m.json"),
            &dir.path("m.json.minisig"),
            &dir.path("bin")
        ),
        Err(Failure::Refused(Refusal::NoKeys(_) | Refusal::UnknownKey))
    ));
}

/// Runs `scripts/release-manifest.sh`, which the release workflow uses to write the manifest.
fn manifest_script(version: &str, target: &str, binary: &Path) -> std::process::Output {
    std::process::Command::new("sh")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/release-manifest.sh"
        ))
        .args([version, target])
        .arg(binary)
        .output()
        .expect("run scripts/release-manifest.sh")
}

#[test]
fn the_release_workflow_script_writes_a_manifest_the_agent_accepts() {
    let dir = crate::test_support::TempDir::new();
    std::fs::write(dir.path("bin"), BINARY).unwrap();
    let output = manifest_script("1.4.0-rc.2", TARGET, &dir.path("bin"));
    assert!(output.status.success(), "{output:?}");
    let manifest = parse_manifest(&output.stdout).expect("the script's manifest parses");
    assert_eq!(manifest.version.to_string(), "1.4.0-rc.2");
    assert_eq!(check_binary(&manifest, BINARY).unwrap(), Ok(()));
    // Exactly the format the tests sign, so the bytes the agent verifies are the bytes published.
    assert_eq!(output.stdout, manifest_for(BINARY, "1.4.0-rc.2"));

    std::fs::write(dir.path("empty"), b"").unwrap();
    for (version, target, binary) in [
        ("1.2", TARGET, "bin"),
        ("v1.2.3", TARGET, "bin"),
        ("1.2.3+build", TARGET, "bin"),
        ("1.2.3\",\"size\":1,\"x\":\"", TARGET, "bin"),
        ("1.2.3", "x86_64\"", "bin"),
        ("1.2.3", TARGET, "missing"),
        ("1.2.3", TARGET, "empty"),
    ] {
        let output = manifest_script(version, target, &dir.path(binary));
        assert!(
            !output.status.success() && output.stdout.is_empty(),
            "{version} {target} {binary}: {output:?}"
        );
    }
}
