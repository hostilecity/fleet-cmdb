//! Whole-collection tests: the readers together, over a fake host built from the Debian 13 fixtures
//! and the server's real manifest (`cmdb/config/fact_manifest.yml`), so a drift between the manifest
//! and the agent's readers fails here.

use std::io;
use std::time::Duration;

use serde_json::{Value, json};

use super::fake::{FakeHost, fixture, server_manifest, server_manifest_parsed};
use super::host::RunError;
use super::manifest::{self, FactType, Manifest};
use super::*;

fn collect_stock() -> (FakeHost, BTreeMap<String, Fact>) {
    let host = FakeHost::debian13();
    let facts = collect(&host, &server_manifest_parsed());
    (host, facts)
}

fn ok(facts: &BTreeMap<String, Fact>, key: &str) -> Value {
    let fact = &facts[key];
    assert_eq!(fact.state(), State::Ok, "{key}: {fact:?}");
    assert_eq!(fact.reason(), None, "{key}");
    fact.value().clone()
}

fn reason(facts: &BTreeMap<String, Fact>, key: &str, state: State) -> String {
    let fact = &facts[key];
    assert_eq!(fact.state(), state, "{key}: {fact:?}");
    assert_eq!(fact.value(), &Value::Null, "{key}");
    fact.reason().expect("a reason").to_owned()
}

fn manifest_of(facts: Value) -> Manifest {
    manifest::parse(&json!({"manifest_version": 1, "facts": facts})).unwrap()
}

#[test]
fn every_named_fact_of_the_server_manifest_has_a_reader_of_the_same_type() {
    // A fact the server adds before an agent release is `unsupported` (P2-A01), so a manifest key
    // without a reader is not a failure here. A reader whose key is gone from the manifest, or whose
    // type differs from the manifest's, is drift worth failing on.
    let known = known_keys();
    let manifest = server_manifest_parsed();
    let mut named = std::collections::BTreeSet::new();
    for fact in &manifest.facts {
        if fact.key.starts_with("file:") || fact.key.starts_with("service:") {
            continue;
        }
        named.insert(fact.key.as_str());
        if let Some(ty) = known.get(fact.key.as_str()) {
            assert_eq!(*ty, fact.ty, "{}", fact.key);
        }
    }
    for key in known.keys() {
        assert!(
            named.contains(key),
            "a reader answers `{key}`, which the manifest does not have"
        );
    }
}

#[test]
fn every_fact_of_the_manifest_is_in_the_result_and_none_is_unsupported() {
    // AC-2.5: nothing is silently absent. And for the manifest as published today, every fact has a
    // reader, so nothing is `unsupported` either.
    let (_, facts) = collect_stock();
    let manifest = server_manifest_parsed();
    assert_eq!(facts.len(), manifest.facts.len());
    let known = known_keys();
    for fact in &manifest.facts {
        assert!(facts.contains_key(&fact.key), "{} is missing", fact.key);
    }
    let unsupported: Vec<_> = facts
        .iter()
        .filter(|(_, f)| f.state() == State::Unsupported)
        .map(|(k, _)| k.as_str())
        .collect();
    // Only a named key with no reader may be unsupported (none today: the published manifest has 89
    // facts and every one has a reader).
    assert!(
        unsupported
            .iter()
            .all(|k| !k.contains(':') && !known.contains_key(k)),
        "{unsupported:?}"
    );
}

#[test]
fn a_stock_debian_13_host() {
    let (_, facts) = collect_stock();
    // SSH.
    assert_eq!(
        ok(&facts, "sshd.permitrootlogin"),
        json!("prohibit-password")
    );
    assert_eq!(ok(&facts, "sshd.maxauthtries"), json!(6));
    // Login and password policy. pwquality is installed but sets nothing but `retry`.
    assert_eq!(ok(&facts, "login_defs.pass_max_days"), json!(99999));
    assert_eq!(ok(&facts, "login_defs.umask"), json!("022"));
    assert_eq!(ok(&facts, "useradd.inactive"), json!(-1));
    assert_eq!(ok(&facts, "pwquality.retry"), json!(3));
    assert!(reason(&facts, "pwquality.minlen", State::Unreadable).contains("is not set"));
    // Updates and firewall.
    assert_eq!(ok(&facts, "auto_updates.installed"), json!(true));
    assert_eq!(ok(&facts, "auto_updates.enabled"), json!(true));
    assert_eq!(ok(&facts, "firewall.backend"), json!("none"));
    assert_eq!(ok(&facts, "firewall.enabled"), json!(false));
    // Services and users.
    assert!(
        ok(&facts, "services.running")
            .as_array()
            .unwrap()
            .contains(&json!("ssh.service"))
    );
    assert!(
        ok(&facts, "services.enabled")
            .as_array()
            .unwrap()
            .contains(&json!("unattended-upgrades.service"))
    );
    assert_eq!(ok(&facts, "users.uid0"), json!(["root"]));
    assert_eq!(ok(&facts, "users.login"), json!(["admin", "root"]));
    // File attributes: owner and group by name, mode in octal.
    assert_eq!(
        ok(&facts, "file:/etc/shadow"),
        json!({"mode": "0640", "owner": "root", "group": "shadow"})
    );
    assert_eq!(
        ok(&facts, "file:/etc/passwd"),
        json!({"mode": "0644", "owner": "root", "group": "root"})
    );
    assert_eq!(
        ok(&facts, "file:/etc/sudoers"),
        json!({"mode": "0440", "owner": "root", "group": "root"})
    );
    assert_eq!(
        ok(&facts, "file:/etc/cron.d"),
        json!({"mode": "0755", "owner": "root", "group": "root"})
    );
    // A file that is not there is null, not an error: this host has no grub.
    assert_eq!(ok(&facts, "file:/boot/grub/grub.cfg"), Value::Null);
    // Units: a state, `null` for a unit that is not installed.
    assert_eq!(
        ok(&facts, "service:ssh.service"),
        json!({"active": "active", "enabled": "enabled"})
    );
    assert_eq!(
        ok(&facts, "service:systemd-journald.service"),
        json!({"active": "active", "enabled": "static"})
    );
    assert_eq!(ok(&facts, "service:telnet.socket"), Value::Null);
    assert_eq!(ok(&facts, "service:rsyslog.service"), Value::Null);
}

#[test]
fn a_changed_setting_changes_the_reported_value() {
    // AC-2.1 on the fixtures: the operator sets PermitRootLogin no; the next report says so.
    let manifest = server_manifest_parsed();
    let before = collect(&FakeHost::debian13(), &manifest);
    let after_host = FakeHost::debian13().with_output("sshd -T", Ok(fixture("sshd-T.hardened")));
    let after = collect(&after_host, &manifest);
    assert_eq!(
        ok(&before, "sshd.permitrootlogin"),
        json!("prohibit-password")
    );
    assert_eq!(ok(&after, "sshd.permitrootlogin"), json!("no"));
    let changed: Vec<_> = after
        .iter()
        .filter(|(key, fact)| before[*key] != **fact)
        .map(|(key, _)| key.as_str())
        .collect();
    assert_eq!(
        changed,
        [
            "sshd.ciphers",
            "sshd.maxauthtries",
            "sshd.passwordauthentication",
            "sshd.permitrootlogin",
            "sshd.x11forwarding"
        ]
    );
}

#[test]
fn a_fact_with_no_reader_is_unsupported_not_absent() {
    // AC-2.5: a fact added to the manifest after this agent was built.
    let manifest = manifest_of(json!([
        {"key": "sshd.maxauthtries", "type": "integer"},
        {"key": "kernel.randomize_va_space", "type": "integer"},
        {"key": "sshd.futuresetting", "type": "string"},
        {"key": "sysctl.addresses", "type": "ip_address_list"}
    ]));
    let facts = collect(&FakeHost::debian13(), &manifest);
    assert_eq!(facts.len(), 4);
    assert_eq!(ok(&facts, "sshd.maxauthtries"), json!(6));
    for key in [
        "kernel.randomize_va_space",
        "sshd.futuresetting",
        "sysctl.addresses",
    ] {
        assert_eq!(
            reason(&facts, key, State::Unsupported),
            "this agent version has no reader for this fact"
        );
    }
}

#[test]
fn a_known_key_with_another_type_is_unsupported() {
    let manifest = manifest_of(json!([
        {"key": "sshd.maxauthtries", "type": "string"},
        {"key": "file:/etc/passwd", "type": "string"},
        {"key": "service:ssh.service", "type": "boolean"}
    ]));
    let host = FakeHost::debian13();
    let facts = collect(&host, &manifest);
    for key in [
        "sshd.maxauthtries",
        "file:/etc/passwd",
        "service:ssh.service",
    ] {
        assert!(
            reason(&facts, key, State::Unsupported)
                .contains("the manifest gives this fact the type")
        );
    }
    assert!(
        host.log().is_empty(),
        "nothing was read for them: {:?}",
        host.log()
    );
}

#[test]
fn sources_are_read_only_when_the_manifest_has_a_fact_for_them() {
    let host = FakeHost::debian13();
    let manifest = manifest_of(json!([{"key": "login_defs.umask", "type": "string"}]));
    collect(&host, &manifest);
    assert_eq!(host.log(), ["read /etc/login.defs"]);
}

#[test]
fn each_source_is_read_once_per_collection() {
    let host = FakeHost::debian13();
    collect(&host, &server_manifest_parsed());
    let log = host.log();
    for once in [
        "run /usr/sbin/sshd -T",
        "run /usr/bin/apt-config dump",
        "read /etc/login.defs",
        "read /etc/default/useradd",
        "read /etc/pam.d/common-password",
        "read /etc/security/pwquality.conf",
    ] {
        assert_eq!(
            log.iter().filter(|e| *e == once).count(),
            1,
            "{once}: {log:?}"
        );
    }
    // /etc/passwd is read for the accounts and again, once, for the owner names.
    assert_eq!(log.iter().filter(|e| *e == "read /etc/passwd").count(), 2);
}

#[test]
fn sensitive_files_are_only_ever_statted() {
    // P2-A03: the reader opens only `stat` on /etc/shadow and the files like it.
    let (host, facts) = collect_stock();
    let log = host.log();
    for path in [
        "/etc/shadow",
        "/etc/shadow-",
        "/etc/gshadow",
        "/etc/gshadow-",
        "/etc/sudoers",
    ] {
        let touching: Vec<&String> = log
            .iter()
            .filter(|e| e.ends_with(&format!(" {path}")))
            .collect();
        assert_eq!(touching, [&format!("stat {path}")], "{path}");
        assert_eq!(facts[&format!("file:{path}")].state(), State::Ok);
    }
    assert!(!log.iter().any(|e| e.starts_with("read ")
        && (e.contains("shadow") || e.contains("sudoers") || e.contains("_key"))));
}

#[test]
fn a_reader_cannot_read_a_secret_file_even_if_it_asks() {
    let host =
        FakeHost::debian13().with_file("/etc/shadow", b"root:$y$j9T$secret:19000:0:99999:7:::\n");
    let ctx = Ctx::new(&host, BUDGET);
    for path in [
        "/etc/shadow",
        "/etc/gshadow-",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/sudoers.d/x",
    ] {
        let error = ctx.read(path, 1024).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{path}");
    }
    assert!(
        host.log().is_empty(),
        "the host was never asked: {:?}",
        host.log()
    );
}

#[test]
fn no_secret_material_is_in_a_collected_result() {
    // P2-A02: nothing secret in any report. The fixture host holds a password hash and key paths; a
    // full collection serialised to JSON contains none of them.
    let host = FakeHost::debian13()
        .with_file(
            "/etc/shadow",
            b"root:$y$j9T$SECRETHASH:19000:0:99999:7:::\n",
        )
        .with_file("/etc/gshadow", b"root:*::\n")
        .with_file(
            "/etc/ssh/ssh_host_ed25519_key",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEY\n",
        );
    let facts = collect(&host, &server_manifest_parsed());
    let json = serde_json::to_string(&facts).unwrap();
    for secret in [
        "SECRETHASH",
        "SECRETKEY",
        "$y$",
        "PRIVATE KEY",
        "ssh_host_",
        "authorized_keys",
    ] {
        assert!(!json.contains(secret), "{secret} is in the result");
    }
}

#[test]
fn readers_run_only_their_own_fixed_commands() {
    let (host, _) = collect_stock();
    let runs: Vec<String> = host
        .log()
        .into_iter()
        .filter_map(|e| e.strip_prefix("run ").map(str::to_owned))
        .collect();
    let allowed_prefixes = [
        "/usr/sbin/sshd -T",
        "/usr/bin/apt-config dump",
        "/usr/bin/systemctl show --no-pager --property=LoadState,ActiveState,UnitFileState -- ",
        "/usr/bin/systemctl list-units --type=service --state=running --plain --no-legend --no-pager --full",
        "/usr/bin/systemctl list-unit-files --type=service --state=enabled --plain --no-legend --no-pager --full",
    ];
    assert!(!runs.is_empty());
    for run in &runs {
        assert!(
            allowed_prefixes
                .iter()
                .any(|p| run == p.trim_end() || run.starts_with(p)),
            "unexpected command: {run}"
        );
    }
    for expected in &allowed_prefixes[..2] {
        assert!(runs.iter().any(|r| r == expected), "{expected}");
    }
}

#[test]
fn a_hostile_manifest_never_gets_anything_run() {
    // The manifest names keys; hostile ones that look like options, escape a directory, or are not
    // canonical are refused, and none reaches a command line.
    let manifest = manifest_of(json!([
        {"key": "service:--help", "type": "service_state"},
        {"key": "service:-H", "type": "service_state"},
        {"key": "service:--host", "type": "service_state"},
        {"key": "service:ssh", "type": "service_state"},
        {"key": "service:.hidden.service", "type": "service_state"},
        {"key": "service:ssh.service", "type": "service_state"},
        {"key": "file:/etc/../etc/shadow", "type": "file_attributes"},
        {"key": "file:/etc//passwd", "type": "file_attributes"},
        {"key": "file:/etc/", "type": "file_attributes"},
        {"key": "file:/etc/passwd", "type": "file_attributes"},
        {"key": "sshd.maxauthtries", "type": "integer"}
    ]));
    let host = FakeHost::debian13();
    let facts = collect(&host, &manifest);
    for key in [
        "service:--help",
        "service:-H",
        "service:--host",
        "service:ssh",
        "service:.hidden.service",
        "file:/etc/../etc/shadow",
        "file:/etc//passwd",
        "file:/etc/",
    ] {
        assert_eq!(facts[key].state(), State::Unsupported, "{key}");
    }
    assert_eq!(facts["service:ssh.service"].state(), State::Ok);
    assert_eq!(facts["file:/etc/passwd"].state(), State::Ok);
    assert_eq!(facts.len(), 11);
    for entry in host.log() {
        assert!(
            !entry
                .split(' ')
                .any(|word| matches!(word, "--help" | "-H" | "--host" | "ssh" | ".hidden.service")),
            "{entry}"
        );
    }
}

#[test]
fn a_huge_manifest_is_bounded() {
    // 1500 files and 1500 units: only the first MAX_* of each are looked at; the rest are reported.
    let mut facts: Vec<Value> = (0..1500)
        .map(|i| json!({"key": format!("file:/etc/f{i:04}"), "type": "file_attributes"}))
        .collect();
    facts.extend(
        (0..1500)
            .map(|i| json!({"key": format!("service:u{i:04}.service"), "type": "service_state"})),
    );
    let manifest = manifest_of(json!(facts));
    assert_eq!(
        manifest.facts.len(),
        2000,
        "the manifest itself is cut at 2000 facts"
    );
    let host = FakeHost::debian13();
    let collected = collect(&host, &manifest);
    assert_eq!(collected.len(), 2000);
    let stats = host.log().iter().filter(|e| e.starts_with("stat ")).count();
    assert_eq!(stats, MAX_FILE_FACTS);
    let over = collected
        .values()
        .filter(|f| f.state() == State::Unsupported)
        .count();
    assert_eq!(
        over,
        (1500 - MAX_FILE_FACTS) + (500 - MAX_UNIT_FACTS.min(500))
    );
    let showed: usize = host
        .log()
        .iter()
        .filter(|e| e.starts_with("run /usr/bin/systemctl show"))
        .map(|e| e.split(" -- ").nth(1).unwrap().split(' ').count())
        .sum();
    assert_eq!(showed, 500);
}

#[test]
fn every_failure_mode_gives_a_reason_not_a_crash() {
    let manifest = server_manifest_parsed();

    // sshd absent (AC: "when sshd is absent, the facts are unreadable with a reason").
    let facts = collect(&FakeHost::debian13().without_output("sshd -T"), &manifest);
    for (key, fact) in facts.iter().filter(|(k, _)| k.starts_with("sshd.")) {
        assert_eq!(fact.state(), State::Unreadable, "{key}");
        assert!(
            fact.reason().unwrap().contains("sshd -T is not installed"),
            "{key}"
        );
    }
    // Everything else is unaffected.
    assert_eq!(ok(&facts, "login_defs.umask"), json!("022"));

    // Permission denied, a timeout, and a failure of the program.
    for (error, needle) in [
        (
            RunError::PermissionDenied("/usr/sbin/sshd".into()),
            "permission denied running /usr/sbin/sshd",
        ),
        (
            RunError::TimedOut(Duration::from_secs(10)),
            "sshd -T did not finish within 10 seconds",
        ),
        (
            RunError::Failed {
                status: "exit status 255".into(),
                stderr: "no hostkeys available -- exiting.".into(),
            },
            "sshd -T failed (exit status 255): no hostkeys available",
        ),
        (
            RunError::TooMuchOutput(1_048_576),
            "printed more than 1048576 bytes",
        ),
    ] {
        let facts = collect(
            &FakeHost::debian13().with_output("sshd -T", Err(error)),
            &manifest,
        );
        assert!(
            reason(&facts, "sshd.permitrootlogin", State::Unreadable).contains(needle),
            "{needle}"
        );
    }

    // Files: permission denied and a read that hangs.
    let host = FakeHost::debian13()
        .denying("/etc/login.defs")
        .breaking("/etc/passwd", io::ErrorKind::TimedOut);
    let facts = collect(&host, &manifest);
    assert_eq!(
        reason(&facts, "login_defs.pass_max_days", State::Unreadable),
        "permission denied reading /etc/login.defs"
    );
    assert!(reason(&facts, "users.accounts", State::Unreadable).contains("timed out"));
    assert_eq!(ok(&facts, "sshd.maxauthtries"), json!(6));

    // A file the agent may not stat is unreadable; one that is missing is null.
    let host = FakeHost::debian13()
        .denying("/etc/crontab")
        .without_file("/etc/motd");
    let facts = collect(&host, &manifest);
    assert_eq!(
        reason(&facts, "file:/etc/crontab", State::Unreadable),
        "permission denied reading /etc/crontab"
    );
    assert_eq!(ok(&facts, "file:/etc/motd"), Value::Null);

    // systemctl missing: every fact that needs it says why, and the rest is unaffected.
    let host = FakeHost::debian13().with_output(
        "systemctl show",
        Err(RunError::NotInstalled(
            "/usr/bin/systemctl or /bin/systemctl".into(),
        )),
    );
    let facts = collect(&host, &manifest);
    assert!(
        reason(&facts, "service:ssh.service", State::Unreadable)
            .contains("systemctl show is not installed")
    );
    assert!(reason(&facts, "firewall.backend", State::Unreadable).contains("not installed"));
    assert!(reason(&facts, "auto_updates.enabled", State::Unreadable).contains("not installed"));
    assert_eq!(ok(&facts, "auto_updates.installed"), json!(true));
    assert_eq!(ok(&facts, "users.uid0"), json!(["root"]));
}

#[test]
fn the_time_budget_stops_commands_and_filesystem_calls_from_starting() {
    let host = FakeHost::debian13();
    let facts = collect_within(&host, &server_manifest_parsed(), Duration::ZERO, None);
    assert!(reason(&facts, "sshd.permitrootlogin", State::Unreadable).contains("time budget"));
    assert!(reason(&facts, "service:ssh.service", State::Unreadable).contains("time budget"));
    // Review of #114: filesystem calls share the budget, so a manifest of paths on a dead mount
    // cannot hold a collection (and shutdown) for 512 times the per-call timeout.
    assert!(reason(&facts, "login_defs.pass_min_days", State::Unreadable).contains("time budget"));
    assert!(reason(&facts, "file:/etc/passwd", State::Unreadable).contains("time budget"));
    assert!(host.log().is_empty(), "{:?}", host.log());
    assert_eq!(facts.len(), server_manifest_parsed().facts.len());
}

#[test]
fn a_value_outside_the_manifests_limits_is_unreadable_not_cut() {
    let long_home = "h".repeat(300);
    let passwd = format!("root:x:0:0:root:/root:/bin/bash\nsvc:x:5:5::/{long_home}:/bin/sh\n");
    let host = FakeHost::debian13().with_file("/etc/passwd", passwd.as_bytes());
    let facts = collect(&host, &server_manifest_parsed());
    assert!(reason(&facts, "users.accounts", State::Unreadable).contains("entry"));
    assert_eq!(ok(&facts, "users.uid0"), json!(["root"]));

    // More entries than the manifest allows: all or nothing.
    let manifest =
        manifest_of(json!([{"key": "users.login", "type": "string_list", "max_items": 1}]));
    let facts = collect(&FakeHost::debian13(), &manifest);
    assert!(
        reason(&facts, "users.login", State::Unreadable)
            .contains("2 entries, and the manifest allows at most 1")
    );

    // A number outside the range, and a string that is too long.
    let manifest = manifest_of(json!([
        {"key": "sshd.maxauthtries", "type": "integer", "minimum": 0, "maximum": 3},
        {"key": "sshd.loglevel", "type": "string", "max_length": 2}
    ]));
    let facts = collect(&FakeHost::debian13(), &manifest);
    assert!(reason(&facts, "sshd.maxauthtries", State::Unreadable).contains("6 is outside 0 to 3"));
    assert!(
        reason(&facts, "sshd.loglevel", State::Unreadable).contains("longer than 2 characters")
    );
}

#[test]
fn a_value_with_a_control_character_is_unreadable() {
    let facts = collect(
        &FakeHost::debian13().with_output("sshd -T", Ok(b"loglevel IN\x07FO\n".to_vec())),
        &manifest_of(json!([{"key": "sshd.loglevel", "type": "string"}])),
    );
    assert!(reason(&facts, "sshd.loglevel", State::Unreadable).contains("control character"));
}

#[test]
fn reasons_are_safe_and_within_the_contract() {
    assert_eq!(clip_reason("a\nb\u{0}c"), "a b c");
    assert_eq!(clip_reason(""), "no reason was given");
    assert_eq!(clip_reason("  \n "), "no reason was given");
    assert_eq!(
        clip_reason(&"x".repeat(2000)).chars().count(),
        MAX_REASON_CHARS
    );
    // Every reason in a degraded collection is non-empty and at most 512 characters.
    let host = FakeHost::debian13().with_output(
        "sshd -T",
        Err(RunError::Failed {
            status: "exit status 1".into(),
            stderr: "x".repeat(5000),
        }),
    );
    for (key, fact) in collect(&host, &server_manifest_parsed()) {
        if let Some(reason) = fact.reason() {
            assert!(
                (1..=MAX_REASON_CHARS).contains(&reason.chars().count()),
                "{key}"
            );
            assert!(!reason.chars().any(char::is_control), "{key}");
        }
    }
}

#[test]
fn check_enforces_each_types_limits() {
    let fact = |ty: FactType| manifest::ManifestFact {
        key: "x.y".into(),
        ty,
        limits: manifest::Limits {
            max_length: 4,
            minimum: -1,
            maximum: 10,
            max_items: 2,
            item_max_length: 3,
        },
    };
    let string = fact(FactType::String);
    assert!(check(&string, &json!("abcd")).is_ok());
    assert!(check(&string, &json!("abcde")).is_err());
    assert!(check(&string, &json!(5)).is_err());
    assert!(check(&string, &json!("a\u{0}")).is_err());
    let int = fact(FactType::Integer);
    assert!(check(&int, &json!(-1)).is_ok());
    assert!(check(&int, &json!(10)).is_ok());
    assert!(check(&int, &json!(11)).is_err());
    assert!(check(&int, &json!(1.5)).is_err());
    assert!(check(&int, &json!("1")).is_err());
    let boolean = fact(FactType::Boolean);
    assert!(check(&boolean, &json!(false)).is_ok());
    assert!(check(&boolean, &json!("yes")).is_err());
    let list = fact(FactType::StringList);
    assert!(check(&list, &json!(["abc", "d"])).is_ok());
    assert!(check(&list, &json!([])).is_ok());
    assert!(check(&list, &json!(["a", "b", "c"])).is_err());
    assert!(check(&list, &json!(["abcd"])).is_err());
    assert!(check(&list, &json!([1])).is_err());
    let file = fact(FactType::FileAttributes);
    assert!(check(&file, &Value::Null).is_ok());
    assert!(
        check(
            &file,
            &json!({"mode": "0640", "owner": "root", "group": "root"})
        )
        .is_ok()
    );
    assert!(check(&file, &json!({"mode": "640", "owner": "0", "group": "0"})).is_ok());
    for bad in [
        json!({"mode": "0680", "owner": "root", "group": "root"}),
        json!({"mode": "06400", "owner": "root", "group": "root"}),
        json!({"mode": "0640", "owner": "", "group": "root"}),
        json!({"mode": "0640", "owner": "root"}),
        json!({"mode": "0640", "owner": "x".repeat(65), "group": "root"}),
        json!("0640"),
    ] {
        assert!(check(&file, &bad).is_err(), "{bad}");
    }
    let unit = fact(FactType::ServiceState);
    assert!(check(&unit, &Value::Null).is_ok());
    assert!(
        check(
            &unit,
            &json!({"active": "active", "enabled": "enabled-runtime"})
        )
        .is_ok()
    );
    for bad in [
        json!({"active": "Active", "enabled": "enabled"}),
        json!({"active": "active", "enabled": ""}),
        json!({"active": "active"}),
        json!({"active": "a".repeat(33), "enabled": "enabled"}),
        json!({"active": "1active", "enabled": "enabled"}),
    ] {
        assert!(check(&unit, &bad).is_err(), "{bad}");
    }
    assert!(check(&fact(FactType::Unknown("ip".into())), &json!("x")).is_err());
}

#[test]
fn the_published_manifest_example_can_be_collected() {
    let path = crate::collect::contract::root()
        .join("examples/v1/config-manifest.response/valid/all-types.json");
    let body: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let manifest = manifest::parse(&body).unwrap();
    let facts = collect(&FakeHost::debian13(), &manifest);
    assert_eq!(facts.len(), manifest.facts.len());
}

#[test]
fn the_server_manifest_reader_agrees_with_the_manifest_file() {
    // The test helper reads the YAML line by line; check it against what the file plainly says.
    let manifest = server_manifest();
    // Not pinned to today's version or count: the server may add facts without touching the agent.
    assert!(manifest["manifest_version"].as_u64().unwrap() >= 1);
    let facts = manifest["facts"].as_array().unwrap();
    assert!(facts.len() >= 89, "{}", facts.len());
    let find = |key: &str| facts.iter().find(|f| f["key"] == key).unwrap();
    assert_eq!(find("sshd.maxauthtries")["maximum"], json!(1000));
    assert_eq!(find("sshd.ciphers")["ordered"], json!(true));
    assert_eq!(find("services.running")["max_items"], json!(1000));
    assert_eq!(find("services.running")["ordered"], json!(false));
    assert_eq!(find("users.uid0")["max_items"], json!(100));
    assert_eq!(find("file:/etc/shadow")["type"], json!("file_attributes"));
    assert_eq!(
        find("service:telnet.socket")["type"],
        json!("service_state")
    );
}

#[test]
fn nothing_starts_once_the_agent_is_stopping() {
    // Rust practice review of #114: a stop request ends the collection at the call in flight.
    let host = FakeHost::debian13();
    let stop = crate::shutdown::Shutdown::default();
    stop.request();
    let facts = collect_until(&host, &server_manifest_parsed(), &stop);
    assert!(host.log().is_empty(), "{:?}", host.log());
    assert_eq!(facts.len(), server_manifest_parsed().facts.len());
    assert!(reason(&facts, "sshd.permitrootlogin", State::Unreadable).contains("stopping"));
    assert!(reason(&facts, "file:/etc/passwd", State::Unreadable).contains("stopping"));
    // Without a stop request the same call reads normally.
    let facts = collect_until(&host, &server_manifest_parsed(), &Default::default());
    assert_eq!(ok(&facts, "sshd.maxauthtries"), json!(6));
}

#[test]
fn a_fact_serializes_as_state_value_and_reason() {
    // The enum keeps the contract's wire form (Rust practice review of #114).
    assert_eq!(
        serde_json::to_value(Fact::Ok(json!(22))).unwrap(),
        json!({"state": "ok", "value": 22, "reason": null})
    );
    assert_eq!(
        serde_json::to_value(Fact::Ok(Value::Null)).unwrap(),
        json!({"state": "ok", "value": null, "reason": null})
    );
    assert_eq!(
        serde_json::to_value(Fact::unreadable("no\u{0}sshd")).unwrap(),
        json!({"state": "unreadable", "value": null, "reason": "no sshd"})
    );
    assert_eq!(
        serde_json::to_value(Fact::unsupported("")).unwrap(),
        json!({"state": "unsupported", "value": null, "reason": "no reason was given"})
    );
}
