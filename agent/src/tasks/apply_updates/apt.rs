//! Debian's package manager, apt and dpkg, for `apply_package_updates` (DEC-16, DEC-01).
//!
//! Every program here is a fixed vector written in this file: no task parameter, no package name, and
//! no option reaches it. The options are DEC-16's policy, one by one:
//!
//! | Option | Why |
//! |---|---|
//! | `-q` | No progress bars in the captured output |
//! | `--error-on=any` (update) | A source that cannot be fetched fails the task, instead of an upgrade from stale lists that reports success |
//! | `-y` | Non-interactive (with `DEBIAN_FRONTEND=noninteractive` in the fixed environment) |
//! | `-o DPkg::Lock::Timeout=300` | Waits up to 5 minutes for the dpkg lock, then fails with a lock message (D3) |
//! | `-o Dpkg::Options::=--force-confdef`, `--force-confold` | Keeps local configuration files |
//! | `--no-remove` | apt-get aborts rather than remove a package (`upgrade` never removes; this makes it certain) |
//! | `-o APT::Get::Upgrade-Allow-New=false` | Installs no new package (`apt-get upgrade`'s default, stated) |
//! | no `--allow-change-held-packages`, `--allow-downgrades`, `--with-new-pkgs` | Holds are respected; nothing is downgraded |
//! | `upgrade`, never `dist-upgrade` or `full-upgrade` | DEC-16 |
//!
//! Held back packages are found afterwards with a simulation that changes nothing (`--simulate`), with
//! holds ignored and new packages allowed, so it lists every package `upgrade` left behind and why
//! would not matter: its `Inst name [installed] (candidate ...)` lines, a format apt has printed
//! unchanged for many releases and that scripts rely on. `needrestart`, when the VM has it, lists the
//! services still running old code and whether the running kernel is older than the installed one
//! (batch mode, list only: `-r l`; `NEEDRESTART_MODE=l` in the fixed environment keeps its apt hook to
//! listing too, threat model D7).
//!
//! Another package manager (issue #163) is another [`super::Manager`]; nothing outside this file knows
//! apt's paths, options, or messages.

use super::{Manager, RestartCheck, System};
use crate::tasks::catalog::Privilege;
use crate::tasks::executor::Program;

const APT_GET: &str = "/usr/bin/apt-get";
/// The optional restart checker (Debian package `needrestart`).
pub const NEEDRESTART: &str = "/usr/sbin/needrestart";
/// dpkg's database, which must exist for apt to be this host's manager.
const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// The locks apt and dpkg take, as `fcntl` record locks: the frontend lock (apt, unattended-upgrades),
/// dpkg's own, the package lists' (`apt-get update`, apt-daily), and the download cache's.
pub const LOCKS: &[&str] = &[
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/lib/apt/lists/lock",
    "/var/cache/apt/archives/lock",
];

/// Debian's and Ubuntu's flag file, written by packages (a kernel's hooks, for example) whose upgrade
/// needs a reboot to take effect.
pub const REBOOT_FLAG: &str = "/run/reboot-required";

const UPDATE_ARGS: &[&str] = &[
    "-q",
    "--error-on=any",
    "-o",
    "DPkg::Lock::Timeout=300",
    "update",
];

const UPGRADE_ARGS: &[&str] = &[
    "-q",
    "-y",
    "-o",
    "DPkg::Lock::Timeout=300",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
    "-o",
    "APT::Get::Upgrade-Allow-New=false",
    "--no-remove",
    "upgrade",
];

const PENDING_ARGS: &[&str] = &[
    "-q",
    "--simulate",
    "-o",
    "APT::Ignore-Hold=true",
    "-o",
    "APT::Get::Upgrade-Allow-New=true",
    "upgrade",
];

const NEEDRESTART_ARGS: &[&str] = &["-b", "-r", "l"];

/// apt on Debian.
pub struct Apt;

impl Manager for Apt {
    fn present(&self, system: &dyn System) -> bool {
        system.exists(APT_GET) && system.exists(DPKG_STATUS)
    }

    fn locks(&self) -> &'static [&'static str] {
        LOCKS
    }

    fn refresh(&self) -> Program {
        package_manager(APT_GET, UPDATE_ARGS)
    }

    fn upgrade(&self) -> Program {
        package_manager(APT_GET, UPGRADE_ARGS)
    }

    fn pending(&self) -> Program {
        package_manager(APT_GET, PENDING_ARGS)
    }

    fn read_pending(&self, output: &str) -> Vec<String> {
        read_pending(output)
    }

    fn restart_check(&self, system: &dyn System) -> Option<Program> {
        // It reads every process's memory maps, so it needs what the agent's sandbox does not give.
        system
            .exists(NEEDRESTART)
            .then(|| package_manager(NEEDRESTART, NEEDRESTART_ARGS))
    }

    fn read_restart_check(&self, output: &str) -> RestartCheck {
        read_needrestart(output)
    }

    fn lock_failure(&self, output: &str) -> bool {
        lock_failure(output)
    }

    fn needs_repair(&self, output: &str) -> bool {
        output.contains("dpkg was interrupted")
    }

    fn repair(&self) -> &'static str {
        "dpkg --configure -a"
    }

    fn reboot_flag(&self) -> &'static str {
        REBOOT_FLAG
    }

    fn is_kernel(&self, package: &str) -> bool {
        package.starts_with("linux-image-")
    }
}

fn package_manager(path: &'static str, args: &'static [&'static str]) -> Program {
    Program {
        path,
        args,
        operand: None,
        privilege: Privilege::PackageManager,
    }
}

/// The packages a simulated upgrade would still upgrade: `Inst name [installed] (candidate ...)`.
/// A line without `[installed]` is a new package, not an upgrade. Sorted, each once, only names a
/// package name can be.
pub fn read_pending(output: &str) -> Vec<String> {
    let mut names: Vec<String> = output
        .lines()
        .filter_map(|line| line.strip_prefix("Inst "))
        .filter_map(|rest| {
            let (name, rest) = rest.split_once(' ')?;
            rest.starts_with('[').then_some(name)
        })
        .filter(|name| is_package_name(name))
        .map(str::to_owned)
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// needrestart's batch output: `NEEDRESTART-SVC: <unit>` per service, `NEEDRESTART-KSTA: <n>` for
/// the kernel (0 unknown, 1 current, 2 an ABI-compatible upgrade pending, 3 a newer version pending).
pub fn read_needrestart(output: &str) -> RestartCheck {
    let mut check = RestartCheck::default();
    for line in output.lines() {
        if let Some(unit) = line.strip_prefix("NEEDRESTART-SVC:") {
            let unit = unit.trim();
            if crate::tasks::executor::spawn::ValidatedArg::service_unit(unit).is_some() {
                check.services.push(unit.to_owned());
            }
        } else if let Some(status) = line.strip_prefix("NEEDRESTART-KSTA:") {
            check.kernel_pending = match status.trim() {
                "1" => Some(false),
                "2" | "3" => Some(true),
                _ => None,
            };
        }
    }
    check.services.sort_unstable();
    check.services.dedup();
    check
}

/// Whether apt or dpkg failed because another program held a lock.
pub fn lock_failure(output: &str) -> bool {
    [
        "Could not get lock",
        "Unable to acquire the dpkg frontend lock",
        "Unable to lock directory",
        "Unable to lock the administration directory",
    ]
    .iter()
    .any(|message| output.contains(message))
}

/// A Debian package name (policy 5.6.1), optionally with `:architecture`, at most 128 characters.
pub fn is_package_name(name: &str) -> bool {
    let (package, arch) = match name.split_once(':') {
        Some((package, arch)) => (package, Some(arch)),
        None => (name, None),
    };
    let mut chars = package.chars();
    name.len() <= 128
        && package.len() >= 2
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+.-".contains(c))
        && arch.is_none_or(|a| {
            !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_program_is_fixed_and_follows_the_policy() {
        let apt = Apt;
        for program in [apt.refresh(), apt.upgrade(), apt.pending()] {
            assert_eq!(program.path, "/usr/bin/apt-get");
            assert!(program.operand.is_none());
            assert_eq!(program.privilege, Privilege::PackageManager);
            for word in [
                "dist-upgrade",
                "full-upgrade",
                "--allow-change-held-packages",
                "--allow-downgrades",
                "--allow-remove-essential",
                "--purge",
                "autoremove",
                "install",
                "remove",
            ] {
                assert!(
                    !program.args.contains(&word),
                    "{word} in {:?}",
                    program.args
                );
            }
        }
        let upgrade = apt.upgrade();
        assert_eq!(upgrade.args.last(), Some(&"upgrade"));
        for needed in [
            "-y",
            "--no-remove",
            "Dpkg::Options::=--force-confdef",
            "Dpkg::Options::=--force-confold",
            "DPkg::Lock::Timeout=300",
            "APT::Get::Upgrade-Allow-New=false",
        ] {
            assert!(upgrade.args.contains(&needed), "{needed}");
        }
        assert_eq!(apt.refresh().args.last(), Some(&"update"));
        assert!(apt.refresh().args.contains(&"--error-on=any"));
        // The held-back check changes nothing.
        assert!(apt.pending().args.contains(&"--simulate"));
        assert!(!apt.pending().args.contains(&"-y"));
    }

    #[test]
    fn held_back_packages_are_read_from_a_simulation() {
        let output = "\
Reading package lists...
Building dependency tree...
The following NEW packages will be installed:
  linux-image-6.12.0-10-amd64
The following packages will be upgraded:
  acme-daemon linux-image-amd64
Inst linux-image-6.12.0-10-amd64 (6.12.38-1 Debian-Security:13/stable-security [amd64])
Inst linux-image-amd64 [6.12.37-1] (6.12.38-1 Debian-Security:13/stable-security [amd64])
Inst acme-daemon [1.0-1] (1.1-1 example.lan [amd64])
Inst libfoo1:i386 [2.0] (2.1 example.lan [i386])
Inst acme-daemon [1.0-1] (1.1-1 example.lan [amd64])
Inst Bad_Name [1] (2 x [amd64])
Conf linux-image-amd64 (6.12.38-1 Debian-Security:13/stable-security [amd64])
";
        assert_eq!(
            read_pending(output),
            ["acme-daemon", "libfoo1:i386", "linux-image-amd64"]
        );
        assert!(
            read_pending("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
                .is_empty()
        );
    }

    #[test]
    fn needrestart_batch_output_is_read() {
        let check = read_needrestart(
            "NEEDRESTART-VER: 3.8\nNEEDRESTART-KCUR: 6.12.37-amd64\nNEEDRESTART-KEXP: 6.12.38-amd64\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: cron.service\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: $(evil).service\nNEEDRESTART-CONT: x\n",
        );
        assert_eq!(check.services, ["cron.service", "nginx.service"]);
        assert_eq!(check.kernel_pending, Some(true));
        assert_eq!(
            read_needrestart("NEEDRESTART-KSTA: 1\n").kernel_pending,
            Some(false)
        );
        assert_eq!(
            read_needrestart("NEEDRESTART-KSTA: 0\n").kernel_pending,
            None
        );
        assert_eq!(read_needrestart("").kernel_pending, None);
    }

    #[test]
    fn lock_messages_of_apt_and_dpkg_are_recognised() {
        for message in [
            "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)",
            "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?",
            "E: Unable to lock directory /var/lib/apt/lists/",
            "E: Unable to lock the administration directory (/var/lib/dpkg/), is another process using it?",
        ] {
            assert!(lock_failure(message), "{message}");
        }
        assert!(!lock_failure(
            "E: Failed to fetch http://deb.example.lan/debian/dists/trixie/InRelease"
        ));
        assert!(Apt.needs_repair(
            "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem."
        ));
    }

    #[test]
    fn package_names_follow_debian_policy() {
        for good in [
            "libc6",
            "g++",
            "linux-image-6.12.0-9-amd64",
            "libfoo1:i386",
            "0ad",
        ] {
            assert!(is_package_name(good), "{good}");
        }
        for bad in [
            "",
            "a",
            "Libc6",
            "-x",
            "a b",
            "a;b",
            "x:",
            "x:I386",
            &"a".repeat(129),
        ] {
            assert!(!is_package_name(bad), "{bad:?}");
        }
    }
}
