//! Package collector tests (P2-AGENT-PACKAGES): the parser on the Debian 13 fixture and on what does
//! not fit the contract, detection on a fake host, and the real `dpkg-query` where there is one.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use super::*;
use crate::facts::fake::{FakeHost, package_fixture};
use crate::facts::host::RealHost;
use crate::test_support::TempDir;

fn find<'a>(listing: &'a Listing, name: &str, architecture: &str) -> &'a Package {
    listing
        .packages
        .iter()
        .find(|p| p.name == name && p.architecture == architecture)
        .unwrap_or_else(|| panic!("{name}:{architecture} not listed"))
}

fn package(name: &str, version: &str, architecture: &str, source: &str) -> Package {
    Package {
        name: name.into(),
        version: version.into(),
        architecture: architecture.into(),
        source: Some(source.into()),
    }
}

#[test]
fn the_debian13_listing_is_parsed_in_full() {
    let listing = parse(&package_fixture("dpkg-query-show"));
    assert_eq!(listing.warnings, Vec::<String>::new());
    // 31 lines: one removed package (config-files) is left out; `nano` (purged) is not listed by dpkg.
    assert_eq!(listing.packages.len(), 30);
    assert_eq!(listing.removed, 1);
    assert_eq!(listing.not_configured, 1, "qemu-guest-agent is unpacked");
    for (name, architecture, version, source) in [
        // Epochs.
        ("vim", "amd64", "2:9.1.1230-2", "vim"),
        ("openssh-server", "amd64", "1:10.0p1-7", "openssh"),
        ("zlib1g", "amd64", "1:1.3.dfsg+really1.3.1-1+b1", "zlib"),
        // A Source field with a version: dpkg's own source name, without it.
        ("bsdutils", "amd64", "1:2.41-5", "util-linux"),
        ("libgcc-s1", "i386", "14.2.0-19", "gcc-14"),
        // Plus signs in names and versions, tildes in versions.
        ("libstdc++6", "amd64", "14.2.0-19", "gcc-14"),
        (
            "grub-efi-amd64-signed",
            "amd64",
            "1+2.12+9",
            "grub-efi-amd64-signed",
        ),
        (
            "linux-image-6.12.48+deb13-cloud-amd64",
            "amd64",
            "6.12.48-1",
            "linux-signed-amd64",
        ),
        ("cloud-init", "all", "25.1.4-1~deb13u1", "cloud-init"),
        ("systemd", "amd64", "257.8-1~deb13u2", "systemd"),
        // Multi-arch: the same package for two architectures, and `all`.
        ("libc6", "amd64", "2.41-12", "glibc"),
        ("libc6", "i386", "2.41-12", "glibc"),
        ("tzdata", "all", "2025b-4+deb13u1", "tzdata"),
        // No Source field: the package's own name.
        ("local-tool", "amd64", "0.1", "local-tool"),
        // Held (`hi`) is installed; unpacked is on disk.
        (
            "linux-image-cloud-amd64",
            "amd64",
            "6.12.48-1",
            "linux-signed-amd64",
        ),
        ("qemu-guest-agent", "amd64", "1:10.0.2+ds-2", "qemu"),
    ] {
        assert_eq!(
            find(&listing, name, architecture),
            &package(name, version, architecture, source)
        );
    }
    assert!(
        !listing
            .packages
            .iter()
            .any(|p| p.name.starts_with("linux-image-6.12.33")),
        "a removed package (config-files) is not installed"
    );
    // Sorted by name, then architecture, each pair once.
    let keys: Vec<(&str, &str)> = listing
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.architecture.as_str()))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted);
}

#[test]
fn the_fixture_is_what_the_real_dpkg_query_prints_for_its_status_file() {
    // The fixture is output, not a hand-written imitation: dpkg-query, run with the agent's own
    // arguments against `status` (next to it), prints exactly it. Skipped where there is no dpkg.
    if !Path::new(DPKG_QUERY[0]).exists() {
        return;
    }
    let admin = TempDir::new();
    std::fs::create_dir_all(admin.path("updates")).unwrap();
    std::fs::create_dir_all(admin.path("info")).unwrap();
    std::fs::write(admin.path("status"), package_fixture("status")).unwrap();
    let mut command = Command::new(DPKG_QUERY, LIST);
    command
        .args
        .insert(0, format!("--admindir={}", admin.root().display()));
    let output = RealHost::new().run(&command).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        String::from_utf8(package_fixture("dpkg-query-show")).unwrap()
    );
}

/// The reference listing for AC-2.3, read independently of [`LIST`]: `name:arch version` for every
/// package `dpkg-query --show` lists whose status abbreviation is not `rc`-like (config-files).
fn reference_listing(admindir: Option<&Path>) -> BTreeSet<String> {
    let mut args = vec![
        "--show".to_owned(),
        "--showformat=${db:Status-Abbrev}|${binary:Package}|${Architecture}|${Version}\\n"
            .to_owned(),
    ];
    if let Some(dir) = admindir {
        args.insert(0, format!("--admindir={}", dir.display()));
    }
    let command = Command {
        programs: DPKG_QUERY,
        args,
        timeout: TIMEOUT,
        max_output: MAX_OUTPUT,
    };
    let output = String::from_utf8(RealHost::new().run(&command).unwrap()).unwrap();
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('|').collect();
            // The second letter of the abbreviation is the status: `c` is config-files.
            if fields[0].as_bytes().get(1) == Some(&b'c') {
                return None;
            }
            // `${binary:Package}` qualifies only Multi-Arch: same packages; qualify them all.
            let name = fields[1].split(':').next().unwrap();
            Some(format!("{name}:{} {}", fields[2], fields[3]))
        })
        .collect()
}

fn reported(listing: &Listing) -> BTreeSet<String> {
    listing
        .packages
        .iter()
        .map(|p| format!("{}:{} {}", p.name, p.architecture, p.version))
        .collect()
}

#[test]
fn the_fixture_listing_matches_dpkgs_own_listing() {
    // AC-2.3 on the fixture: no package missing or invented.
    if !Path::new(DPKG_QUERY[0]).exists() {
        return;
    }
    let admin = TempDir::new();
    std::fs::create_dir_all(admin.path("updates")).unwrap();
    std::fs::create_dir_all(admin.path("info")).unwrap();
    std::fs::write(admin.path("status"), package_fixture("status")).unwrap();
    let listing = parse(&package_fixture("dpkg-query-show"));
    assert_eq!(reported(&listing), reference_listing(Some(admin.root())));
}

#[test]
fn on_this_machine_the_report_matches_dpkgs_own_listing() {
    // AC-2.3 wherever the tests run on a dpkg system (the CI runners are Ubuntu): the real host, the
    // real command, the whole package database. A real Debian 13 VM is still the acceptance check.
    if !Path::new(DPKG_QUERY[0]).exists() || !Path::new(DPKG_STATUS).exists() {
        return;
    }
    let Collected::Dpkg(listing) = collect(&RealHost::new(), None) else {
        panic!("dpkg is here but was not detected");
    };
    assert!(listing.warnings.is_empty(), "{:?}", listing.warnings);
    assert!(!listing.packages.is_empty());
    assert_eq!(reported(&listing), reference_listing(None));
}

#[test]
fn the_listing_runs_one_fixed_command() {
    let host = FakeHost::debian13();
    let Collected::Dpkg(listing) = collect(&host, None) else {
        panic!("not detected");
    };
    assert_eq!(listing.packages.len(), 30);
    assert_eq!(
        host.log(),
        [
            "stat /var/lib/dpkg/status".to_owned(),
            "run /usr/bin/dpkg-query --show --showformat=${db:Status-Status}\\t${Package}\\t${Architecture}\\t${Version}\\t${source:Package}\\n".to_owned(),
        ]
    );
}

#[test]
fn a_host_without_dpkg_is_unsupported_and_says_what_it_has() {
    let host = FakeHost::default();
    assert_eq!(
        collect(&host, None),
        Collected::Unsupported(
            "no dpkg database at /var/lib/dpkg/status; only dpkg is supported (DEC-01)".into()
        )
    );
    assert!(
        !host.log().iter().any(|l| l.starts_with("run ")),
        "{:?}",
        host.log()
    );
    let rpm = FakeHost::default().with_stat("/usr/bin/rpm", 0o755, 0, 0);
    assert_eq!(
        collect(&rpm, None),
        Collected::Unsupported(
            "no dpkg database at /var/lib/dpkg/status; rpm was found, which is not supported (only dpkg is, DEC-01)"
                .into()
        )
    );
    let both = FakeHost::default()
        .with_stat("/usr/bin/rpm", 0o755, 0, 0)
        .with_stat("/sbin/apk", 0o755, 0, 0);
    let Collected::Unsupported(reason) = collect(&both, None) else {
        panic!()
    };
    assert!(reason.contains("rpm and apk were found"), "{reason}");
}

#[test]
fn a_listing_that_cannot_be_read_is_unsupported_with_the_reason() {
    let cases: [(FakeHost, &str); 5] = [
        (
            FakeHost::debian13().without_output("dpkg-query --show"),
            "dpkg-query --show is not installed (/usr/bin/dpkg-query not found)",
        ),
        (
            FakeHost::debian13().with_output(
                "dpkg-query --show",
                Err(RunError::Failed {
                    status: "exit status 2".into(),
                    stderr: "dpkg-query: error: parsing file '/var/lib/dpkg/status' near line 3"
                        .into(),
                }),
            ),
            "dpkg-query --show failed (exit status 2): dpkg-query: error: parsing file '/var/lib/dpkg/status' near line 3",
        ),
        (
            FakeHost::debian13().with_output("dpkg-query --show", Err(RunError::TimedOut(TIMEOUT))),
            "dpkg-query --show did not finish within 20 seconds",
        ),
        (
            FakeHost::debian13().with_output(
                "dpkg-query --show",
                Err(RunError::TooMuchOutput(MAX_OUTPUT)),
            ),
            "dpkg-query --show printed more than 8388608 bytes; stopped it",
        ),
        (
            FakeHost::debian13().denying(DPKG_STATUS),
            "permission denied reading /var/lib/dpkg/status",
        ),
    ];
    for (host, reason) in cases {
        assert_eq!(collect(&host, None), Collected::Unsupported(reason.into()));
    }
}

#[test]
fn a_stopping_agent_runs_nothing() {
    let host = FakeHost::debian13();
    let stop = Shutdown::default();
    stop.request();
    assert_eq!(collect(&host, Some(&stop)), Collected::Stopping);
    assert!(host.log().is_empty(), "{:?}", host.log());
}

#[test]
fn more_packages_than_a_report_may_list_is_unsupported_not_cut() {
    let output = synthetic_output(MAX_PACKAGES + 1);
    let host = FakeHost::default()
        .with_stat(DPKG_STATUS, 0o644, 0, 0)
        .with_output("dpkg-query --show", Ok(output));
    assert_eq!(
        collect(&host, None),
        Collected::Unsupported(too_many(MAX_PACKAGES + 1))
    );
    let exactly = FakeHost::default()
        .with_stat(DPKG_STATUS, 0o644, 0, 0)
        .with_output("dpkg-query --show", Ok(synthetic_output(MAX_PACKAGES)));
    let Collected::Dpkg(listing) = collect(&exactly, None) else {
        panic!()
    };
    assert_eq!(listing.packages.len(), MAX_PACKAGES);
}

#[test]
fn lines_the_contract_cannot_carry_are_skipped_with_a_warning_never_cut() {
    let long_version = "1".repeat(257);
    let long_name = "a".repeat(129);
    let output = format!(
        "installed\tgood\tamd64\t1.0-1\tgood\n\
         installed\tBad-Name\tamd64\t1.0\tbad\n\
         installed\t{long_name}\tamd64\t1.0\tx\n\
         installed\tspaced\tamd64\t1.0 beta\tspaced\n\
         installed\tlong\tamd64\t{long_version}\tlong\n\
         installed\tweird-arch\tAMD64\t1.0\tweird-arch\n\
         installed\tno-arch\t\t1.0\tno-arch\n\
         installed\todd-source\tamd64\t1.0\tOdd_Source\n\
         installed\ttoo\tmany\tfields\there\textra\n\
         installed\ttoo-few\tamd64\t1.0\n\
         frobnicated\tstrange\tamd64\t1.0\tstrange\n\
         installed\tgood\tamd64\t1.0-2\tgood\n\
         installed\tctl\x1b[31m\tamd64\t1.0\tctl\n"
    );
    let mut bytes = output.into_bytes();
    bytes.extend_from_slice(b"installed\tlatin\xe9\tamd64\t1.0\tlatin\n");
    let listing = parse(&bytes);
    assert_eq!(
        listing.packages,
        [
            package("good", "1.0-1", "amd64", "good"),
            Package {
                source: None,
                ..package("odd-source", "1.0", "amd64", "")
            },
        ]
    );
    let warnings = listing.warnings.join("\n");
    for expected in [
        "package name `Bad-Name` is not one a package report can carry; skipped",
        "package spaced:amd64 has the version `1.0 beta`, which a package report cannot carry; skipped",
        "package long:amd64 has the version `",
        "package weird-arch has the architecture `AMD64`",
        "package no-arch has the architecture ``",
        "package odd-source:amd64 has the source package name `Odd_Source`, which a package report cannot carry; reported without a source",
        "line 9 of the dpkg-query output has 6 fields, not 5; skipped",
        "line 10 of the dpkg-query output has 4 fields, not 5; skipped",
        "package `strange` has the dpkg status `frobnicated`, which this agent does not know; skipped",
        "package good:amd64 is listed more than once; the first is reported",
        "line 14 of the dpkg-query output is not UTF-8; skipped",
    ] {
        assert!(warnings.contains(expected), "{expected}\n---\n{warnings}");
    }
    // A control character from the output never reaches a warning.
    assert!(!warnings.contains('\x1b'), "{warnings}");
    assert_eq!(listing.warnings.len(), 13, "{warnings}");
    assert!(
        listing
            .warnings
            .iter()
            .all(|w| (1..=512).contains(&w.len()))
    );
}

#[test]
fn warnings_are_capped_with_a_count_of_the_rest() {
    let mut output = String::new();
    for i in 0..100 {
        output.push_str(&format!("installed\tBAD{i}\tamd64\t1.0\tx\n"));
    }
    output.push_str("installed\tfine\tall\t1\tfine\n");
    let listing = parse(output.as_bytes());
    assert_eq!(listing.packages.len(), 1);
    assert_eq!(listing.warnings.len(), MAX_WARNINGS);
    assert!(listing.warnings[62].contains("`BAD62`"));
    assert_eq!(
        listing.warnings[63],
        "37 more problems with the dpkg-query output are not listed"
    );
    // Exactly the limit: every one listed.
    let exactly: String = (0..64)
        .map(|i| format!("installed\tBAD{i}\tamd64\t1.0\tx\n"))
        .collect();
    let listing = parse(exactly.as_bytes());
    assert_eq!(listing.warnings.len(), 64);
    assert!(listing.warnings[63].contains("`BAD63`"));
}

#[test]
fn every_status_dpkg_defines_is_handled() {
    let statuses = [
        ("installed", true),
        ("triggers-awaited", true),
        ("triggers-pending", true),
        ("half-configured", true),
        ("unpacked", true),
        ("half-installed", true),
        ("config-files", false),
        ("not-installed", false),
    ];
    let output: String = statuses
        .iter()
        .map(|(status, _)| format!("{status}\tp-{status}\tamd64\t1\tp\n"))
        .collect();
    let listing = parse(output.as_bytes());
    assert!(listing.warnings.is_empty(), "{:?}", listing.warnings);
    let names: Vec<&str> = listing.packages.iter().map(|p| p.name.as_str()).collect();
    for (status, reported) in statuses {
        assert_eq!(
            names.contains(&format!("p-{status}").as_str()),
            reported,
            "{status}"
        );
    }
    assert_eq!(listing.not_configured, 3);
    assert_eq!(listing.removed, 1);
}

#[test]
fn empty_output_and_a_missing_final_newline_are_read() {
    assert_eq!(parse(b""), Listing::default());
    let listing = parse(b"installed\tx\tall\t1\tx");
    assert_eq!(listing.packages, [package("x", "1", "all", "x")]);
}

#[test]
fn the_checks_match_the_contracts_patterns() {
    for name in [
        "a",
        "0ad",
        "libstdc++6",
        "g++-14",
        "python3.13",
        "x_y",
        &"a".repeat(128),
    ] {
        assert!(valid_name(name), "{name}");
    }
    for name in [
        "",
        "-a",
        "+a",
        ".a",
        "A",
        "a b",
        "a:b",
        "ä",
        &"a".repeat(129),
    ] {
        assert!(!valid_name(name), "{name}");
    }
    for arch in [
        "amd64",
        "all",
        "i386",
        "x32",
        "kfreebsd-amd64",
        &"a".repeat(32),
    ] {
        assert!(valid_architecture(arch), "{arch}");
    }
    for arch in ["", "-amd64", "AMD64", "arm_64", &"a".repeat(33)] {
        assert!(!valid_architecture(arch), "{arch}");
    }
    for version in [
        "1",
        "1:2.3-4+deb13u1~bpo1",
        "2.0-1$local",
        "1.0-",
        &"1".repeat(256),
    ] {
        assert!(valid_version(version), "{version}");
    }
    for version in ["", "1 2", "1\t2", "1.0ä", &"1".repeat(257)] {
        assert!(!valid_version(version), "{version}");
    }
}

/// `count` lines of `dpkg-query --show` output, shaped like a large Debian host: names and versions of
/// realistic length, a source package shared by about three binaries, a sixth of them `all`, a few
/// `i386`, epochs and Debian revisions.
pub(crate) fn synthetic_output(count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count * 80);
    for i in 0..count {
        let architecture = match i % 30 {
            0..=4 => "all",
            5 => "i386",
            _ => "amd64",
        };
        let source = format!("source-package-{:04}", i / 3);
        let name = format!("lib{source}-{}", ["bin", "dev", "common"][i % 3]);
        let epoch = if i % 11 == 0 { "1:" } else { "" };
        let version = format!(
            "{epoch}{}.{}.{}-{}+deb13u{}",
            i % 7,
            i % 13,
            i % 29,
            1 + i % 5,
            i % 3
        );
        let line = format!("installed\t{name}\t{architecture}\t{version}\t{source}\n");
        out.extend_from_slice(line.as_bytes());
    }
    out
}

/// A dpkg `status` file with the packages of [`synthetic_output`], for the real `dpkg-query`.
pub(crate) fn synthetic_status(count: usize) -> Vec<u8> {
    let output = String::from_utf8(synthetic_output(count)).unwrap();
    let mut status = String::with_capacity(count * 400);
    for line in output.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let (name, architecture, version, source) = (fields[1], fields[2], fields[3], fields[4]);
        let multi_arch = if architecture == "all" {
            "foreign"
        } else {
            "same"
        };
        status.push_str(&format!(
            "Package: {name}\nStatus: install ok installed\nPriority: optional\nSection: libs\n\
             Installed-Size: 1024\nMaintainer: Example Maintainers <maintainers@example.lan>\n\
             Architecture: {architecture}\nMulti-Arch: {multi_arch}\nSource: {source}\n\
             Version: {version}\nDepends: libc6 (>= 2.38)\n\
             Description: synthetic package for the memory measurement\n \
             One of the packages of a large synthetic host.\n\n"
        ));
    }
    status.into_bytes()
}

#[test]
fn the_synthetic_listing_parses_without_warnings() {
    let listing = parse(&synthetic_output(3000));
    assert!(listing.warnings.is_empty(), "{:?}", listing.warnings);
    assert_eq!(listing.packages.len(), 3000);
}

/// What the real `dpkg-query` lists for [`synthetic_status`]: the agent's command against another
/// database directory.
pub(crate) struct SyntheticDpkg {
    admin: TempDir,
}

impl SyntheticDpkg {
    pub(crate) fn new(count: usize) -> Self {
        let admin = TempDir::new();
        std::fs::create_dir_all(admin.path("updates")).unwrap();
        std::fs::create_dir_all(admin.path("info")).unwrap();
        std::fs::write(admin.path("status"), synthetic_status(count)).unwrap();
        Self { admin }
    }
}

impl Host for SyntheticDpkg {
    fn stat(&self, path: &Path) -> io::Result<crate::facts::host::Stat> {
        RealHost::new().stat(&self.admin.path(path.file_name().unwrap().to_str().unwrap()))
    }

    fn read(&self, _: &Path, _: u64) -> io::Result<Vec<u8>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn list(&self, _: &Path, _: usize) -> io::Result<Vec<String>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn run(&self, command: &Command) -> Result<Vec<u8>, RunError> {
        let mut command = command.clone();
        command
            .args
            .insert(0, format!("--admindir={}", self.admin.root().display()));
        RealHost::new().run(&command)
    }
}

#[test]
fn the_real_dpkg_query_lists_a_large_synthetic_host_in_full() {
    if !Path::new(DPKG_QUERY[0]).exists() {
        return;
    }
    let host = SyntheticDpkg::new(3000);
    let Collected::Dpkg(listing) = collect(&host, None) else {
        panic!("not detected");
    };
    assert!(listing.warnings.is_empty(), "{:?}", listing.warnings);
    assert_eq!(listing.packages, parse(&synthetic_output(3000)).packages);
}
