//! The programs started on demand, which the library scan never calls idle (owner decisions 2026-11-21,
//! third review S3, focused review S1, S2): what cron, anacron, systemd timers (system and user), and
//! D-Bus activation start. Read from the files themselves, the way their readers do: no command is run
//! (no `systemctl show`), so the scan gains no new program.
//!
//! Wherever reading is ambiguous the answer errs toward "started": every absolute path in a command
//! counts, arguments included; every bare word is looked up in the standard executable directories (and
//! any `PATH=` the file sets); every `Exec*=` value of a unit's main file and of all its drop-ins counts,
//! an empty `ExecStart=` reset notwithstanding; a symlink (`/etc/alternatives`) counts as itself and as
//! its target. Only paths that are regular files count, so a directory argument (`find /usr/lib`) does
//! not mark every package that lists that directory.
//!
//! A file that cannot be read fails the scan, except a user's crontab, which is private to that user
//! (mode 0600): the scan has no `CAP_DAC_READ_SEARCH` and skips those, a stated limit. A masked unit (a
//! symlink to `/dev/null`) starts nothing. Limits: [`MAX_FILES`] files read (unit directories are
//! listed once, so a unit missing from one costs no call), of at most [`MAX_BYTES`] each,
//! [`MAX_CRONTABS`] users' crontabs, and [`MAX_PATHS`] distinct candidate paths; past any of them the
//! scan fails rather than guess.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::facts::Ctx;
use crate::facts::host::Inspect;

/// systemd's system unit directories, in its order of precedence (`systemd.unit(5)`).
pub const SYSTEM_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
];
/// systemd's user unit directories that are not in a home. `~/.config/systemd/user` is tried for each
/// home too, but the scan runs with `ProtectHome=yes`, so it sees none: a stated limit.
pub const USER_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/user",
    "/run/systemd/user",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
];
/// libdbus's activation directories: system bus, then session bus.
pub const DBUS_SYSTEM_DIRS: &[&str] = &[
    "/usr/local/share/dbus-1/system-services",
    "/usr/share/dbus-1/system-services",
    "/lib/dbus-1/system-services",
    "/etc/dbus-1/system-services",
];
pub const DBUS_SESSION_DIRS: &[&str] = &[
    "/usr/local/share/dbus-1/services",
    "/usr/share/dbus-1/services",
];
/// Cron and anacron.
pub const CRON_FILES: &[&str] = &["/etc/crontab", "/etc/anacrontab"];
pub const CRON_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/cron.yearly",
];
pub const USER_CRONTABS: &str = "/var/spool/cron/crontabs";
/// Where a bare command name is looked up: systemd's fixed search path, which includes cron's default
/// `/usr/bin:/bin`.
pub const BIN_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

pub const MAX_FILES: usize = 20_000;
pub const MAX_BYTES: u64 = 1024 * 1024;
pub const MAX_CRONTABS: usize = 100_000;
pub const MAX_PATHS: usize = 100_000;

enum Found {
    Text(String),
    Missing,
    Masked,
}

struct Reader<'a> {
    ctx: &'a Ctx<'a>,
    files: usize,
    /// Absolute paths and bare words named by commands, before they are checked.
    paths: BTreeSet<String>,
    words: BTreeSet<String>,
    /// More directories to look bare words up in (`PATH=` lines).
    extra_dirs: BTreeSet<String>,
    /// Unit directories' entries, each listed once.
    listed: HashMap<String, HashSet<String>>,
}

impl Reader<'_> {
    /// A file's text. A file that cannot be read is an error unless `private` (a user's crontab, then
    /// [`Found::Missing`]); one refused as secret-looking is an error too (focused review N2).
    fn read(&mut self, path: &str, private: bool) -> Result<Found, String> {
        let denied =
            |e: &std::io::Error| private && e.kind() == std::io::ErrorKind::PermissionDenied;
        // A masked unit is a link to /dev/null, told by its target (focused review N4).
        match self.ctx.resolve(path) {
            Ok(target) if target == "/dev/null" => return Ok(Found::Masked),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Found::Missing),
            Err(e) if denied(&e) => return Ok(Found::Missing),
            Err(e) => return Err(crate::facts::io_reason(path, &e)),
        }
        self.files += 1;
        if self.files > MAX_FILES {
            return Err(format!(
                "more than {MAX_FILES} cron, timer, and D-Bus files"
            ));
        }
        match self.ctx.read(path, MAX_BYTES) {
            Ok(bytes) => Ok(Found::Text(String::from_utf8_lossy(&bytes).into_owned())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Found::Missing),
            Err(e) if denied(&e) => Ok(Found::Missing),
            Err(e) => Err(crate::facts::io_reason(path, &e)),
        }
    }

    /// Whether `dir` (a unit directory, listed once) has an entry `name`, so a unit is looked for
    /// without a failed call per directory.
    fn has(&mut self, dir: &str, name: &str) -> Result<bool, String> {
        if !self.listed.contains_key(dir) {
            let names = self.list(dir, MAX_FILES)?.into_iter().collect();
            self.listed.insert(dir.to_owned(), names);
        }
        Ok(self.listed[dir].contains(name))
    }

    fn list(&self, dir: &str, max: usize) -> Result<Vec<String>, String> {
        match self.ctx.list(dir, max) {
            Ok(names) => Ok(names),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(crate::facts::io_reason(dir, &e)),
        }
    }

    /// The paths and bare words of a command (or a script's text).
    fn command(&mut self, text: &str) -> Result<(), String> {
        for token in text.split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    ';' | '&'
                        | '|'
                        | '"'
                        | '\''
                        | '('
                        | ')'
                        | '='
                        | '`'
                        | '$'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                )
        }) {
            let token = token.trim_start_matches(['-', '@', ':', '+', '!']);
            if token.starts_with('/') && token.len() > 1 {
                self.paths.insert(token.to_owned());
            } else if !token.is_empty()
                && token.len() <= 255
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
                && !token.starts_with('.')
            {
                self.words.insert(token.to_owned());
            }
            // The paths to look at, once each bare word is placed in every directory.
            if self.paths.len() + self.words.len() * (BIN_DIRS.len() + self.extra_dirs.len())
                > MAX_PATHS
            {
                return Err(format!(
                    "cron, timer, and D-Bus files name more than {MAX_PATHS} paths"
                ));
            }
        }
        Ok(())
    }

    /// A cron table: each line that is not a comment is a command; `PATH=` adds directories.
    fn crontab(&mut self, text: &str) -> Result<(), String> {
        for line in logical_lines(text) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(path) = line.strip_prefix("PATH").map(str::trim_start)
                && let Some(value) = path.strip_prefix('=')
            {
                for dir in value.trim().trim_matches('"').split(':') {
                    if dir.starts_with('/') {
                        self.extra_dirs.insert(dir.trim_end_matches('/').to_owned());
                    }
                }
            }
            self.command(line)?;
        }
        Ok(())
    }

    /// Every `Exec*=` value of a unit, from its main file in the first directory that has it and
    /// from every drop-in in every directory: `<unit>.d/*.conf`, the template's for an instance, and the
    /// type's (`service.d/`). An instance with no file of its own falls back to its template's. A
    /// `Unit=` value (a timer's) is returned.
    fn unit(&mut self, name: &str, dirs: &[&str]) -> Result<Option<Vec<String>>, String> {
        let template = template_of(name);
        let kind = name.rsplit('.').next().unwrap_or("");
        let mut texts = Vec::new();
        'lookup: for candidate in [Some(name.to_owned()), template.clone()]
            .into_iter()
            .flatten()
        {
            for dir in dirs {
                if !self.has(dir, &candidate)? {
                    continue;
                }
                match self.read(&format!("{dir}/{candidate}"), false)? {
                    Found::Text(text) => {
                        texts.push(text);
                        break 'lookup;
                    }
                    // Masked where it is first found: the unit starts nothing.
                    Found::Masked => return Ok(None),
                    Found::Missing => {}
                }
            }
        }
        let mut dropin_dirs = vec![format!("{name}.d")];
        if let Some(template) = &template {
            dropin_dirs.push(format!("{template}.d"));
        }
        dropin_dirs.push(format!("{kind}.d"));
        for dir in dirs {
            for dropin_dir in &dropin_dirs {
                if !self.has(dir, dropin_dir)? {
                    continue;
                }
                let path = format!("{dir}/{dropin_dir}");
                for file in self.list(&path, MAX_FILES)? {
                    if file.ends_with(".conf")
                        && let Found::Text(text) = self.read(&format!("{path}/{file}"), false)?
                    {
                        texts.push(text);
                    }
                }
            }
        }
        let mut units = Vec::new();
        for text in texts {
            for line in logical_lines(&text) {
                let line = line.trim();
                // A comment's key (`#ExecStart`) is no Exec*= or Unit= key.
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                if key.starts_with("Exec") {
                    self.command(value)?;
                } else if key == "Unit" {
                    units.push(value.trim().to_owned());
                }
            }
        }
        Ok(Some(units))
    }

    /// Every timer in `dirs` (and the instances enabled through `*.wants/` links), and the programs the
    /// services they start run.
    fn timers(&mut self, dirs: &[&str]) -> Result<(), String> {
        let mut timers = BTreeSet::new();
        for dir in dirs {
            self.has(dir, "")?;
            let names: Vec<String> = self.listed[*dir].iter().cloned().collect();
            for name in names {
                if name.ends_with(".timer") {
                    timers.insert(name);
                } else if name.ends_with(".wants")
                    || name.ends_with(".requires")
                    || name.ends_with(".upholds")
                {
                    for link in self.list(&format!("{dir}/{name}"), MAX_FILES)? {
                        if link.ends_with(".timer") {
                            timers.insert(link);
                        }
                    }
                }
            }
        }
        for timer in timers {
            if !unit_name(&timer) {
                return Err(format!("a timer's name cannot be read: {timer:?}"));
            }
            let Some(named) = self.unit(&timer, dirs)? else {
                continue;
            };
            let services = if named.is_empty() {
                vec![format!("{}.service", timer.trim_end_matches(".timer"))]
            } else {
                named
            };
            for service in services {
                if !unit_name(&service) {
                    return Err(format!(
                        "a timer names a unit that cannot be read: {service:?}"
                    ));
                }
                self.unit(&service, dirs)?;
            }
        }
        Ok(())
    }

    /// D-Bus activation files: their `Exec=` and the unit their `SystemdService=` names.
    fn dbus(&mut self, dirs: &[&str], units: &[&str]) -> Result<(), String> {
        for dir in dirs {
            for name in self.list(dir, MAX_FILES)? {
                if !name.ends_with(".service") {
                    continue;
                }
                let Found::Text(text) = self.read(&format!("{dir}/{name}"), false)? else {
                    continue;
                };
                for line in logical_lines(&text) {
                    let Some((key, value)) = line.trim().split_once('=') else {
                        continue;
                    };
                    match key.trim() {
                        "Exec" => self.command(value)?,
                        "SystemdService" => {
                            let unit = value.trim();
                            if !unit_name(unit) {
                                return Err(format!(
                                    "{dir}/{name} names a unit that cannot be read: {unit:?}"
                                ));
                            }
                            self.unit(unit, units)?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    fn cron(&mut self) -> Result<(), String> {
        for file in CRON_FILES {
            if let Found::Text(text) = self.read(file, false)? {
                self.crontab(&text)?;
            }
        }
        // Package scripts in /etc/cron.* already make their packages not native; an admin's script names
        // the programs it runs, so its text is read as commands too (focused review S2).
        for dir in CRON_DIRS {
            for name in self.list(dir, MAX_FILES)? {
                let path = format!("{dir}/{name}");
                if let Ok(Inspect::Directory) = self.ctx.inspect(&path) {
                    continue;
                }
                if let Found::Text(text) = self.read(&path, false)? {
                    self.crontab(&text)?;
                }
            }
        }
        let crontabs = self.list(USER_CRONTABS, MAX_CRONTABS + 1)?;
        if crontabs.len() > MAX_CRONTABS {
            return Err(format!(
                "more than {MAX_CRONTABS} users' crontabs, more than the scan reads"
            ));
        }
        for name in crontabs {
            // Not counted toward MAX_FILES: MAX_CRONTABS bounds them.
            let files = self.files;
            let found = self.read(&format!("{USER_CRONTABS}/{name}"), true)?;
            self.files = files;
            if let Found::Text(text) = found {
                self.crontab(&text)?;
            }
        }
        Ok(())
    }

    /// The named paths that are regular files (or lead to one), each with its real path too.
    fn checked(mut self) -> Result<BTreeSet<String>, String> {
        let mut dirs: Vec<String> = BIN_DIRS.iter().map(|d| (*d).to_owned()).collect();
        dirs.extend(std::mem::take(&mut self.extra_dirs));
        let words = std::mem::take(&mut self.words);
        for word in words {
            for dir in &dirs {
                self.paths.insert(format!("{dir}/{word}"));
            }
        }
        // At most MAX_PATHS: command() checks as it collects.
        let mut found = BTreeSet::new();
        for path in std::mem::take(&mut self.paths) {
            match self.ctx.inspect(&path) {
                Ok(Inspect::File(_)) => {
                    if let Ok(real) = self.ctx.resolve(&path) {
                        found.insert(real);
                    }
                    found.insert(path);
                }
                Ok(Inspect::Symlink) => match self.ctx.resolve(&path) {
                    Ok(real) => {
                        if matches!(self.ctx.inspect(&real), Ok(Inspect::File(_))) {
                            found.insert(real);
                            found.insert(path);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    // Cannot tell where it leads: counted, which can only make more not native.
                    Err(_) if self.ctx.out_of_time() => return Err(out_of_time()),
                    Err(_) => {
                        found.insert(path);
                    }
                },
                Ok(Inspect::Directory | Inspect::Other) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) if self.ctx.out_of_time() => return Err(out_of_time()),
                // A path the scan cannot look at (a directory it may not search): counted.
                Err(_) => {
                    found.insert(path);
                }
            }
        }
        Ok(found)
    }
}

fn out_of_time() -> String {
    "the scan ran out of its budget while reading what is started on demand".into()
}

/// A file's lines with backslash continuations joined, as systemd and shells read them.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(head) = line.strip_suffix('\\') {
            current.push_str(head);
            current.push(' ');
        } else {
            current.push_str(line);
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// `foo@.service` for `foo@x.service`; `None` for anything else.
fn template_of(name: &str) -> Option<String> {
    let (stem, rest) = name.split_once('@')?;
    let (instance, kind) = rest.rsplit_once('.')?;
    (!instance.is_empty()).then(|| format!("{stem}@.{kind}"))
}

/// A unit name the scan reads a file for: the unit name alphabet plus `\` and `@`, with a type.
fn unit_name(name: &str) -> bool {
    (3..=256).contains(&name.len())
        && !name.starts_with(['-', '.'])
        && !name.contains('/')
        && name.contains('.')
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-' | b'\\' | b':')
        })
}

/// The programs started on demand, as absolute paths (module documentation).
pub fn started_on_demand(ctx: &Ctx) -> Result<BTreeSet<String>, String> {
    let mut reader = Reader {
        ctx,
        files: 0,
        paths: BTreeSet::new(),
        words: BTreeSet::new(),
        extra_dirs: BTreeSet::new(),
        listed: HashMap::new(),
    };
    reader.cron()?;
    reader.timers(SYSTEM_UNIT_DIRS)?;
    let mut user_dirs: Vec<String> = USER_UNIT_DIRS.iter().map(|d| (*d).to_owned()).collect();
    // Homes where readable: under the scan's ProtectHome=yes, none is (a stated limit).
    let homes = ctx.list("/home", MAX_FILES).unwrap_or_default();
    for dir in homes
        .iter()
        .map(|home| format!("/home/{home}/.config/systemd/user"))
        .chain(std::iter::once("/root/.config/systemd/user".to_owned()))
    {
        if ctx.list(&dir, MAX_FILES).is_ok() {
            user_dirs.push(dir);
        }
    }
    let user_dirs: Vec<&str> = user_dirs.iter().map(String::as_str).collect();
    reader.timers(&user_dirs)?;
    reader.dbus(DBUS_SYSTEM_DIRS, SYSTEM_UNIT_DIRS)?;
    reader.dbus(DBUS_SESSION_DIRS, &user_dirs)?;
    reader.checked()
}
