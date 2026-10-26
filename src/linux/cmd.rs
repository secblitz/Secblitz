//! The one way Linux code runs programs and touches files. Backends take a [`Sys`] so tests can use a fake.

use anyhow::Result;
use std::path::Path;

/// What a finished program left behind. `status` is -1 when a signal stopped it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// The only session bus address a person-scope program is given.
pub fn session_bus_address(uid: u32) -> String {
    format!("unix:path=/run/user/{uid}/bus")
}

pub trait Sys {
    /// Runs `program` (an absolute path) with fixed arguments and no shell.
    fn run(&self, program: &'static str, args: &[&str]) -> Result<Output>;
    /// The file's bytes, or `None` when it does not exist. A symbolic link is refused.
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>>;
    /// Replaces `path` in one step: a temporary file in the same folder, flushed to disk, then renamed.
    fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()>;
    /// Removes the file; a missing file is not an error.
    fn remove(&self, path: &Path) -> Result<()>;
    /// Like [`run`](Sys::run) for a job that can take minutes, such as removing software.
    fn run_long(&self, program: &'static str, args: &[&str]) -> Result<Output> {
        self.run(program, args)
    }
    /// Runs `program` with `answer` typed into it, for a program that asks before it changes anything and has no way to say no on the command line.
    fn run_answering(
        &self,
        _program: &'static str,
        _args: &[&str],
        _answer: &str,
    ) -> Result<Output> {
        anyhow::bail!("This program cannot be given an answer")
    }
}

#[cfg(target_os = "linux")]
pub use real::{RealSys, SessionSys};

#[cfg(target_os = "linux")]
mod real {
    use super::{Output, Sys};
    use anyhow::{bail, ensure, Context, Result};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
    const OUTPUT_CAP: u64 = 1 << 20;
    const READ_CAP: u64 = 4 << 20;
    const TIME_LIMIT: Duration = Duration::from_secs(60);
    const LONG_TIME_LIMIT: Duration = Duration::from_secs(20 * 60);
    const OUTPUT_GRACE: Duration = Duration::from_secs(2);

    pub struct RealSys;

    type Captured = (std::thread::JoinHandle<()>, Arc<Mutex<Vec<u8>>>);

    fn capture(mut pipe: impl Read + Send + 'static) -> Captured {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&kept);
        let handle = std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            while let Ok(n) = pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                // The program must never block on a full pipe, so what is over the cap is read and dropped.
                let Ok(mut held) = sink.lock() else { break };
                let room = (OUTPUT_CAP as usize).saturating_sub(held.len());
                held.extend_from_slice(&chunk[..n.min(room)]);
            }
        });
        (handle, kept)
    }

    /// A program that left a background process holding its output open must not hold this call up with it.
    fn collected((handle, kept): Captured, until: Instant) -> String {
        while !handle.is_finished() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        let bytes = kept.lock().map(|b| b.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn unreadable(path: &Path) -> String {
        format!("Could not read {}", path.display())
    }

    fn run_program(
        program: &'static str,
        args: &[&str],
        session_bus: Option<&str>,
        limit: Duration,
        answer: Option<&str>,
    ) -> Result<Output> {
        ensure!(
            program.starts_with('/'),
            "Programs are run by absolute path"
        );
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("PATH", PATH)
            .env("LC_ALL", "C");
        if let Some(bus) = session_bus {
            command.env("DBUS_SESSION_BUS_ADDRESS", bus);
        }
        let mut child = command
            .stdin(if answer.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Could not start {program}"))?;
        if let (Some(answer), Some(mut stdin)) = (answer, child.stdin.take()) {
            // A program that exits before reading its question closes the pipe, which is not a failure here.
            let _ = stdin.write_all(answer.as_bytes());
        }
        let out = capture(child.stdout.take().context("No output pipe")?);
        let err = capture(child.stderr.take().context("No error pipe")?);
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                bail!("{program} took too long and was stopped");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let until = Instant::now() + OUTPUT_GRACE;
        Ok(Output {
            status: status.code().unwrap_or(-1),
            stdout: collected(out, until),
            stderr: collected(err, until),
        })
    }

    impl Sys for RealSys {
        fn run(&self, program: &'static str, args: &[&str]) -> Result<Output> {
            run_program(program, args, None, TIME_LIMIT, None)
        }

        fn run_long(&self, program: &'static str, args: &[&str]) -> Result<Output> {
            run_program(program, args, None, LONG_TIME_LIMIT, None)
        }

        fn run_answering(
            &self,
            program: &'static str,
            args: &[&str],
            answer: &str,
        ) -> Result<Output> {
            run_program(program, args, None, TIME_LIMIT, Some(answer))
        }

        fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
            match fs::symlink_metadata(path) {
                Ok(m) => ensure!(
                    !m.file_type().is_symlink(),
                    "{} is a link and is not read",
                    path.display()
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e).with_context(|| unreadable(path)),
            }
            let file = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e).with_context(|| unreadable(path)),
            };
            ensure!(
                file.metadata()?.is_file(),
                "{} is not a regular file",
                path.display()
            );
            let mut bytes = Vec::new();
            file.take(READ_CAP + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= READ_CAP,
                "{} is too large",
                path.display()
            );
            Ok(Some(bytes))
        }

        fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
            let dir = path.parent().context("The file has no folder")?;
            let name = path.file_name().context("The file has no name")?;
            let dir_meta = fs::symlink_metadata(dir)
                .with_context(|| format!("Could not open {}", dir.display()))?;
            ensure!(dir_meta.is_dir(), "{} is not a plain folder", dir.display());
            if let Ok(existing) = fs::symlink_metadata(path) {
                ensure!(
                    existing.is_file(),
                    "{} is not a regular file",
                    path.display()
                );
            }
            let mut temp_name = std::ffi::OsString::from(".secblitz-");
            temp_name.push(name);
            temp_name.push(format!(".{}.tmp", std::process::id()));
            let temp = dir.join(temp_name);
            let _ = fs::remove_file(&temp);
            let written = (|| -> Result<()> {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&temp)?;
                file.write_all(bytes)?;
                let fd = file.as_raw_fd();
                // SAFETY: `fd` stays open for the life of `file`.
                unsafe {
                    if libc::geteuid() == 0 {
                        ensure!(libc::fchown(fd, 0, 0) == 0, "Could not set the owner");
                    }
                    // The process umask must not narrow the requested mode.
                    ensure!(
                        libc::fchmod(fd, mode as libc::mode_t) == 0,
                        "Could not set the permissions"
                    );
                }
                file.sync_all()?;
                fs::rename(&temp, path)?;
                File::open(dir)?.sync_all()?;
                Ok(())
            })();
            if written.is_err() {
                let _ = fs::remove_file(&temp);
            }
            written.with_context(|| format!("Could not write {}", path.display()))
        }

        fn remove(&self, path: &Path) -> Result<()> {
            let removing = || format!("Could not remove {}", path.display());
            match fs::symlink_metadata(path) {
                Ok(m) => ensure!(
                    !m.is_dir(),
                    "{} is a folder and is not removed",
                    path.display()
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e).with_context(removing),
            }
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e).with_context(removing),
            }
            if let Some(dir) = path.parent() {
                File::open(dir)?.sync_all()?;
            }
            Ok(())
        }
    }

    /// Runs programs as the signed-in person with their desktop's message bus, the one variable `gsettings` needs.
    /// Files are handled exactly as [`RealSys`] does.
    pub struct SessionSys {
        bus: String,
    }

    impl SessionSys {
        /// `address` must be exactly the person's own bus socket, `unix:path=/run/user/<uid>/bus`.
        pub fn new(address: &str, uid: u32) -> Result<Self> {
            ensure!(
                address == super::session_bus_address(uid),
                "The desktop session bus address is not the usual one"
            );
            Ok(Self {
                bus: address.to_owned(),
            })
        }
    }

    impl Sys for SessionSys {
        fn run(&self, program: &'static str, args: &[&str]) -> Result<Output> {
            run_program(program, args, Some(&self.bus), TIME_LIMIT, None)
        }

        fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
            RealSys.read(path)
        }

        fn write_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
            RealSys.write_atomic(path, bytes, mode)
        }

        fn remove(&self, path: &Path) -> Result<()> {
            RealSys.remove(path)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        #[test]
        fn a_program_runs_with_a_clean_environment_and_its_output_is_captured() {
            std::env::set_var("SECBLITZ_LEAK_PROBE", "leaked");
            let out = RealSys.run("/usr/bin/env", &[]).unwrap();
            assert!(out.success());
            assert!(out.stdout.contains("PATH=/usr/sbin:/usr/bin:/sbin:/bin"));
            assert!(out.stdout.contains("LC_ALL=C"));
            assert!(!out.stdout.contains("SECBLITZ_LEAK_PROBE"));
        }

        #[test]
        fn a_session_program_gets_exactly_the_bus_variable() {
            // SAFETY: geteuid has no preconditions and cannot fail.
            let uid = unsafe { libc::geteuid() };
            let address = super::super::session_bus_address(uid);
            let sys = SessionSys::new(&address, uid).unwrap();
            let out = sys.run("/usr/bin/env", &[]).unwrap();
            assert!(out
                .stdout
                .contains(&format!("DBUS_SESSION_BUS_ADDRESS={address}")));
            assert_eq!(out.stdout.lines().count(), 3);
        }

        #[test]
        fn only_the_persons_own_bus_socket_is_accepted() {
            for bad in [
                "unix:path=/run/user/1001/bus",
                "unix:path=/run/user/1000/bus,guid=1",
                "unix:abstract=/tmp/dbus-x",
                "tcp:host=localhost,port=1",
                "unix:path=/run/user/1000/../bus",
                "",
            ] {
                assert!(SessionSys::new(bad, 1000).is_err(), "{bad}");
            }
            SessionSys::new("unix:path=/run/user/1000/bus", 1000).unwrap();
        }

        #[test]
        fn a_failing_program_reports_its_status_and_error_text() {
            let out = RealSys
                .run("/bin/sh", &["-c", "echo no >&2; exit 3"])
                .unwrap();
            assert_eq!(out.status, 3);
            assert_eq!(out.stderr, "no\n");
        }

        #[test]
        fn a_relative_or_missing_program_is_an_error() {
            assert!(RealSys.run("sh", &[]).is_err());
            assert!(RealSys.run("/nonexistent/program", &[]).is_err());
        }

        #[test]
        fn standard_input_is_closed() {
            let out = RealSys.run("/bin/sh", &["-c", "cat; echo done"]).unwrap();
            assert_eq!(out.stdout, "done\n");
        }

        #[test]
        fn a_program_that_leaves_a_background_process_does_not_hold_the_call_up() {
            let started = Instant::now();
            let out = RealSys
                .run("/bin/sh", &["-c", "sleep 20 & echo hi"])
                .unwrap();
            assert_eq!(out.stdout, "hi\n");
            assert!(started.elapsed() < Duration::from_secs(10));
        }

        #[test]
        fn output_is_capped_without_stalling_the_program() {
            let out = RealSys
                .run("/bin/sh", &["-c", "head -c 5000000 /dev/zero | tr '\\0' a"])
                .unwrap();
            assert!(out.success());
            assert_eq!(out.stdout.len() as u64, OUTPUT_CAP);
        }

        #[test]
        fn read_returns_none_for_a_missing_file_and_refuses_a_link() {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("a");
            assert_eq!(RealSys.read(&file).unwrap(), None);
            fs::write(&file, b"x").unwrap();
            assert_eq!(RealSys.read(&file).unwrap(), Some(b"x".to_vec()));
            let link = dir.path().join("l");
            symlink(&file, &link).unwrap();
            assert!(RealSys.read(&link).is_err());
            let dangling = dir.path().join("d");
            symlink(dir.path().join("none"), &dangling).unwrap();
            assert!(RealSys.read(&dangling).is_err());
        }

        #[test]
        fn read_refuses_a_folder_and_a_huge_file() {
            let dir = tempfile::tempdir().unwrap();
            assert!(RealSys.read(dir.path()).is_err());
            let big = dir.path().join("big");
            fs::write(&big, vec![0u8; READ_CAP as usize + 1]).unwrap();
            assert!(RealSys.read(&big).is_err());
        }

        #[test]
        fn write_atomic_replaces_the_file_with_the_mode_and_leaves_no_temporary() {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("conf");
            fs::write(&file, b"old").unwrap();
            RealSys.write_atomic(&file, b"new", 0o640).unwrap();
            assert_eq!(fs::read(&file).unwrap(), b"new");
            let meta = fs::metadata(&file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o640);
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }

        #[test]
        fn write_atomic_refuses_a_link_target_and_a_link_folder() {
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("real");
            fs::write(&real, b"keep").unwrap();
            let link = dir.path().join("link");
            symlink(&real, &link).unwrap();
            assert!(RealSys.write_atomic(&link, b"x", 0o600).is_err());
            assert_eq!(fs::read(&real).unwrap(), b"keep");

            let folder = dir.path().join("folder");
            fs::create_dir(&folder).unwrap();
            let folder_link = dir.path().join("folder-link");
            symlink(&folder, &folder_link).unwrap();
            assert!(RealSys
                .write_atomic(&folder_link.join("f"), b"x", 0o600)
                .is_err());
            assert_eq!(fs::read_dir(&folder).unwrap().count(), 0);
        }

        #[test]
        fn remove_ignores_a_missing_file_and_refuses_a_folder() {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("f");
            RealSys.remove(&file).unwrap();
            fs::write(&file, b"x").unwrap();
            RealSys.remove(&file).unwrap();
            assert!(!file.exists());
            let sub = dir.path().join("sub");
            fs::create_dir(&sub).unwrap();
            assert!(RealSys.remove(&sub).is_err());
        }
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::{Output, Sys};
    use anyhow::{bail, Result};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// Files and program replies held in memory. A program with no recorded reply is an error, so a test never runs
    /// something it did not expect.
    #[derive(Default)]
    pub struct FakeSys {
        pub files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
        pub replies: RefCell<BTreeMap<String, Output>>,
        pub calls: RefCell<Vec<String>>,
        pub answers: RefCell<Vec<String>>,
    }

    fn key(program: &str, args: &[&str]) -> String {
        std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ")
    }

    impl FakeSys {
        pub fn reply(&self, program: &str, args: &[&str], status: i32, stdout: &str) {
            self.replies.borrow_mut().insert(
                key(program, args),
                Output {
                    status,
                    stdout: stdout.into(),
                    stderr: String::new(),
                },
            );
        }

        pub fn file(&self, path: &str, bytes: &[u8]) {
            self.files.borrow_mut().insert(path.into(), bytes.to_vec());
        }
    }

    impl Sys for FakeSys {
        fn run(&self, program: &'static str, args: &[&str]) -> Result<Output> {
            let k = key(program, args);
            self.calls.borrow_mut().push(k.clone());
            match self.replies.borrow().get(&k) {
                Some(out) => Ok(out.clone()),
                None => bail!("Unexpected program: {k}"),
            }
        }

        fn run_answering(
            &self,
            program: &'static str,
            args: &[&str],
            answer: &str,
        ) -> Result<Output> {
            self.answers.borrow_mut().push(answer.to_owned());
            self.run(program, args)
        }

        fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
            Ok(self.files.borrow().get(path).cloned())
        }

        fn write_atomic(&self, path: &Path, bytes: &[u8], _mode: u32) -> Result<()> {
            self.files.borrow_mut().insert(path.into(), bytes.to_vec());
            Ok(())
        }

        fn remove(&self, path: &Path) -> Result<()> {
            self.files.borrow_mut().remove(path);
            Ok(())
        }
    }

    #[test]
    fn the_fake_answers_only_what_it_was_told() {
        let sys = FakeSys::default();
        sys.reply("/usr/bin/true", &["a"], 0, "ok");
        assert_eq!(sys.run("/usr/bin/true", &["a"]).unwrap().stdout, "ok");
        assert!(sys.run("/usr/bin/true", &["b"]).is_err());
        sys.file("/etc/x", b"1");
        assert_eq!(sys.read(Path::new("/etc/x")).unwrap(), Some(b"1".to_vec()));
        sys.remove(Path::new("/etc/x")).unwrap();
        assert_eq!(sys.read(Path::new("/etc/x")).unwrap(), None);
    }
}
