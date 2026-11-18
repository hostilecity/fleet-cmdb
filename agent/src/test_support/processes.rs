//! Other processes for the lock tests (#242): a child forked and caught before it execs, and a real
//! second process that takes a lock the way the agent does.

use std::io::Read;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A child forked from this process that does nothing until it is killed. It holds a copy of every
/// descriptor open when it was forked, as a program another thread starts does between `fork` and
/// `exec`, for as long as the test needs: the moment that made the ledger's own released lock look
/// held by another process (#242). Killed and reaped on drop.
pub struct Forked(libc::pid_t);

impl Forked {
    ///
    /// The child also holds, for its short life, copies of other concurrent tests' pipe ends, so it
    /// can delay their end of file by the few milliseconds it lives. It dies with this process, even
    /// one killed outright (a timeout, the OOM killer), so it never keeps those pipes open for good.
    pub fn idle() -> Self {
        // SAFETY: getpid(2) has no preconditions.
        let parent = unsafe { libc::getpid() };
        // SAFETY: after fork the child calls only prctl(2), getppid(2), _exit(2) and pause(2), all
        // async-signal-safe, so it never touches a lock or allocator another thread of this process
        // held at the fork. It never returns or unwinds; the parent kills it, or its death does.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: see above.
            unsafe {
                // Killed when the parent dies; and if it already died before this took effect, the
                // child was re-parented, so it leaves now.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if libc::getppid() != parent {
                    libc::_exit(0);
                }
                loop {
                    libc::pause();
                }
            }
        }
        Self(pid)
    }
}

impl Drop for Forked {
    fn drop(&mut self) {
        // SAFETY: the pid is this process's own unreaped child, so it cannot have been reused.
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            libc::waitpid(self.0, std::ptr::null_mut(), 0);
        }
    }
}

/// What the other process is to take: `Lock::file` on a path, or `Ledger::open` on a directory.
#[derive(Debug, Clone, Copy)]
pub enum Hold {
    Lock,
    Ledger,
}

/// The variable that tells [`held_for_another_test`] what to take.
const HOLD_VAR: &str = "FLEET_AGENT_TEST_HOLD";
/// That test's full name, as the test binary is asked to run it.
const HOLD_TEST: &str = "test_support::processes::held_for_another_test";

/// A real second process, the unit-test binary run again, that took `what` on `path` with the
/// agent's own code and holds it until dropped. `None` if it could not take it (held here).
pub struct Holder {
    child: Child,
    stdin: Option<ChildStdin>,
    /// The rest of its output, read to the end on drop so libtest's last lines reach it and its
    /// exit status means something.
    stdout: Option<BufReader<ChildStdout>>,
}

impl Holder {
    pub fn start(what: Hold, path: &Path) -> Option<Self> {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", HOLD_TEST, "--ignored", "--nocapture"])
            .arg("--test-threads=1")
            .env(HOLD_VAR, format!("{what:?}:{}", path.display()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = Some(BufReader::new(child.stdout.take().unwrap()));
        // From here on its Drop reaps the child, on every path, panics included.
        let mut holder = Self {
            child,
            stdin,
            stdout,
        };
        let mut line = String::new();
        loop {
            line.clear();
            let reader = holder.stdout.as_mut().unwrap();
            if reader.read_line(&mut line).unwrap() == 0 {
                panic!("the holder exited without answering");
            }
            // libtest prints the test's name first, on the same line.
            let answer = line.trim_end();
            if answer.ends_with("fleet-agent-test: held") {
                return Some(holder);
            }
            if answer.ends_with("fleet-agent-test: refused") {
                return None;
            }
        }
    }

    /// The other process's id.
    pub fn id(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        // End of input tells it to let go and exit; its output is read to the end and it is reaped
        // before the test goes on. It must have passed: a failure after it answered shows here.
        drop(self.stdin.take());
        let mut rest = String::new();
        if let Some(mut stdout) = self.stdout.take() {
            let _ = stdout.read_to_string(&mut rest);
        }
        let status = self.child.wait();
        if !std::thread::panicking() {
            let status = status.unwrap();
            assert!(
                status.success(),
                "the holder process failed ({status}): {rest}"
            );
        }
    }
}

/// Not a test of its own: the body of [`Holder`]'s process. Without the variable it does nothing,
/// so a run of every ignored test passes it.
#[test]
#[ignore = "run by Holder in a second process"]
fn held_for_another_test() {
    let Ok(spec) = std::env::var(HOLD_VAR) else {
        return;
    };
    let (what, path) = spec.split_once(':').unwrap();
    let path = Path::new(path);
    let held: Option<Box<dyn std::any::Any>> = match what {
        "Lock" => crate::fsx::Lock::file(path)
            .unwrap()
            .map(|l| Box::new(l) as _),
        "Ledger" => match crate::tasks::ledger::Ledger::open(path, std::time::SystemTime::now()) {
            Ok((ledger, _)) => Some(Box::new(ledger)),
            Err(crate::tasks::ledger::LedgerError::Locked) => None,
            Err(e) => panic!("{e}"),
        },
        other => panic!("unknown hold {other}"),
    };
    println!(
        "fleet-agent-test: {}",
        if held.is_some() { "held" } else { "refused" }
    );
    // Hold it until the parent closes our input (or dies).
    let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut Vec::new());
    drop(held);
}
