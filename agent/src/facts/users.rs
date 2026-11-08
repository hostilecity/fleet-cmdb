//! Local accounts (P2-A03): `users.accounts`, `users.login`, and `users.uid0`, from `/etc/passwd`.
//!
//! Only `/etc/passwd` is read: name, uid, home directory, and login shell. `/etc/shadow` is never
//! opened (the file facts only `stat` it, and [`crate::facts::host::read_file`] refuses it), so no
//! password hash can reach a report.
//!
//! - `users.accounts`: each account as `name:uid:home:shell`, sorted. An empty shell stays empty (the
//!   system default, `/bin/sh`, applies).
//! - `users.login`: the accounts whose shell allows a login. An account cannot log in when its shell
//!   is `nologin`, `false`, `sync`, `shutdown`, or `halt` (the shells Debian's `base-passwd` gives
//!   service accounts, by file name, wherever they are installed); every other shell, including an
//!   empty one, can. The check is on the shell field, not on the password: a locked password does not
//!   stop an SSH key login, and the password hash is not read.
//! - `users.uid0`: the accounts with user id 0.
//!
//! A line that cannot be read (too few fields, a user id that is not a number, bytes that are not
//! UTF-8) makes all three facts `unreadable`, with the line number: leaving the line out would hide an
//! account. NIS markers (`+`, `-` at the start of a line) and `#` comments are skipped.
//!
//! The same parser provides the names the file facts use for owners ([`parse_names`]).

use std::collections::HashMap;

use serde_json::json;

use super::manifest::FactType;
use super::{Ctx, Outcome, io_reason};

const PASSWD: &str = "/etc/passwd";
const GROUP: &str = "/etc/group";
/// Largest passwd or group file read (about 40,000 accounts at 100 bytes).
const MAX_BYTES: u64 = 4 * 1024 * 1024;

pub const KEYS: &[(&str, FactType)] = &[
    ("users.accounts", FactType::StringList),
    ("users.login", FactType::StringList),
    ("users.uid0", FactType::StringList),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub home: String,
    pub shell: String,
}

impl Account {
    /// Whether the shell field allows a login. See the module documentation.
    pub fn can_login(&self) -> bool {
        let shell = self.shell.rsplit('/').next().unwrap_or("");
        !matches!(shell, "nologin" | "false" | "sync" | "shutdown" | "halt")
    }

    fn entry(&self) -> String {
        format!("{}:{}:{}:{}", self.name, self.uid, self.home, self.shell)
    }
}

pub fn read(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    let outcome = match ctx.read(PASSWD, MAX_BYTES) {
        Err(e) => Err(io_reason(PASSWD, &e)),
        Ok(bytes) => {
            parse_passwd(&bytes).map_err(|problem| format!("cannot read {PASSWD}: {problem}"))
        }
    };
    match outcome {
        Err(reason) => KEYS
            .iter()
            .map(|(key, _)| (*key, Outcome::Unreadable(reason.clone())))
            .collect(),
        Ok(accounts) => facts(&accounts),
    }
}

/// The three facts for a list of accounts.
pub fn facts(accounts: &[Account]) -> HashMap<&'static str, Outcome> {
    let sorted = |mut names: Vec<String>| {
        names.sort();
        names.dedup();
        Outcome::Ok(json!(names))
    };
    let mut entries: Vec<String> = accounts.iter().map(Account::entry).collect();
    entries.sort();
    HashMap::from([
        ("users.accounts", Outcome::Ok(json!(entries))),
        (
            "users.login",
            sorted(
                accounts
                    .iter()
                    .filter(|a| a.can_login())
                    .map(|a| a.name.clone())
                    .collect(),
            ),
        ),
        (
            "users.uid0",
            sorted(
                accounts
                    .iter()
                    .filter(|a| a.uid == 0)
                    .map(|a| a.name.clone())
                    .collect(),
            ),
        ),
    ])
}

/// The accounts in a passwd file, in file order.
pub fn parse_passwd(bytes: &[u8]) -> Result<Vec<Account>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "the file is not valid UTF-8")?;
    let mut accounts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim().is_empty() || line.starts_with(['#', '+', '-']) {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(format!("line {number} does not have 7 fields"));
        }
        if fields[0].is_empty() {
            return Err(format!("line {number} has no user name"));
        }
        let uid = fields[2]
            .parse::<u32>()
            .map_err(|_| format!("line {number} has a user id that is not a number"))?;
        accounts.push(Account {
            name: fields[0].to_owned(),
            uid,
            home: fields[5].to_owned(),
            shell: fields[6].to_owned(),
        });
    }
    Ok(accounts)
}

/// Names for numeric ids, for the owner and group of the file facts. The first entry for an id wins,
/// as `getpwuid(3)` and `getgrgid(3)` do. A line that cannot be read is skipped: a missing name only
/// means the numeric id is reported instead, which the contract allows.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Names {
    pub users: HashMap<u32, String>,
    pub groups: HashMap<u32, String>,
}

impl Names {
    pub fn load(ctx: &Ctx) -> Self {
        Self {
            users: ctx
                .read(PASSWD, MAX_BYTES)
                .map(|bytes| parse_names(&bytes, 2))
                .unwrap_or_default(),
            groups: ctx
                .read(GROUP, MAX_BYTES)
                .map(|bytes| parse_names(&bytes, 2))
                .unwrap_or_default(),
        }
    }
}

/// `name:x:id:...` lines to a map from id to name. `id_field` is the index of the numeric id (2 in
/// both `passwd` and `group`).
pub fn parse_names(bytes: &[u8], id_field: usize) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for line in String::from_utf8_lossy(bytes).lines() {
        if line.starts_with(['#', '+', '-']) {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(name), Some(id)) = (fields.next(), fields.nth(id_field - 1)) else {
            continue;
        };
        if let Ok(id) = id.parse::<u32>()
            && !name.is_empty()
        {
            names.entry(id).or_insert_with(|| name.to_owned());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const PASSWD_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/passwd");
    const GROUP_FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/group");

    fn list(outcomes: &HashMap<&'static str, Outcome>, key: &str) -> Vec<String> {
        match &outcomes[key] {
            Outcome::Ok(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect(),
            other => panic!("{key}: {other:?}"),
        }
    }

    #[test]
    fn debian_13_accounts() {
        let accounts = parse_passwd(PASSWD_FIXTURE).unwrap();
        let facts = facts(&accounts);
        let all = list(&facts, "users.accounts");
        assert!(all.windows(2).all(|w| w[0] <= w[1]), "sorted");
        assert!(all.contains(&"root:0:/root:/bin/bash".to_owned()));
        assert!(all.contains(&"daemon:1:/usr/sbin:/usr/sbin/nologin".to_owned()));
        assert!(all.contains(&"nobody:65534:/nonexistent:/usr/sbin/nologin".to_owned()));
        assert_eq!(list(&facts, "users.uid0"), ["root"]);
        // root, the operator's account, and sync is not a login (its shell is /bin/sync).
        assert_eq!(list(&facts, "users.login"), ["admin", "root"]);
    }

    #[test]
    fn a_second_account_with_uid_0_is_listed() {
        let accounts = parse_passwd(b"root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nbob:x:1000:1000::/home/bob:/bin/bash\n").unwrap();
        let facts = facts(&accounts);
        assert_eq!(list(&facts, "users.uid0"), ["root", "toor"]);
        assert_eq!(list(&facts, "users.login"), ["bob", "root", "toor"]);
    }

    #[test]
    fn which_shells_can_log_in() {
        let account = |shell: &str| Account {
            name: "x".into(),
            uid: 1,
            home: "/".into(),
            shell: shell.into(),
        };
        for shell in [
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/zsh",
            "",
            "/usr/local/bin/menu",
            "/bin/rbash",
        ] {
            assert!(account(shell).can_login(), "{shell:?}");
        }
        for shell in [
            "/usr/sbin/nologin",
            "/sbin/nologin",
            "/bin/false",
            "/usr/bin/false",
            "/bin/sync",
            "/sbin/shutdown",
            "/sbin/halt",
            "nologin",
        ] {
            assert!(!account(shell).can_login(), "{shell:?}");
        }
    }

    #[test]
    fn an_empty_shell_stays_empty_in_the_entry() {
        let accounts = parse_passwd(b"svc:x:200:200::/var/lib/svc:\n").unwrap();
        assert_eq!(
            list(&facts(&accounts), "users.accounts"),
            ["svc:200:/var/lib/svc:"]
        );
    }

    #[test]
    fn comments_nis_markers_and_blank_lines_are_skipped() {
        let accounts =
            parse_passwd(b"# comment\n\n+::::::\n-bad:::::\nroot:x:0:0:root:/root:/bin/bash\n")
                .unwrap();
        assert_eq!(accounts.len(), 1);
    }

    #[test]
    fn a_malformed_line_makes_every_fact_unreadable_with_its_line_number() {
        for (text, needle) in [
            (
                &b"root:x:0:0:root:/root:/bin/bash\nbroken:x:1\n"[..],
                "line 2 does not have 7 fields",
            ),
            (
                b"root:x:zero:0:root:/root:/bin/bash\n",
                "line 1 has a user id that is not a number",
            ),
            (
                b"root:x:-1:0:root:/root:/bin/bash\n",
                "line 1 has a user id",
            ),
            (b":x:0:0:root:/root:/bin/bash\n", "line 1 has no user name"),
            (
                b"root:x:0:0:root:/root:/bin/bash:extra\n",
                "line 1 does not have 7 fields",
            ),
            (b"root:x:0:0:r\xffoot:/root:/bin/bash\n", "not valid UTF-8"),
        ] {
            let error = parse_passwd(text).unwrap_err();
            assert!(error.contains(needle), "{error}");
        }
    }

    #[test]
    fn names_for_ids_take_the_first_entry() {
        let users = parse_names(PASSWD_FIXTURE, 2);
        assert_eq!(users[&0], "root");
        assert_eq!(users[&65534], "nobody");
        let groups = parse_names(GROUP_FIXTURE, 2);
        assert_eq!(groups[&0], "root");
        assert_eq!(groups[&42], "shadow");
        let dup = parse_names(
            b"first:x:7:\nsecond:x:7:\nbroken\n:x:8:\nx:x:notnumber:\n",
            2,
        );
        assert_eq!(dup.len(), 1);
        assert_eq!(dup[&7], "first");
    }
}
