//! What the root helper does for Free up space and Clean up apps. Each request names fixed items or catalog apps; nothing here runs a command a person typed.
use crate::app::remote::{AppStep, AppWire, Event, Reply, Request};
use secblitz::debloat::linux as apps;
use secblitz::linux::cmd::Sys;
use secblitz::space::linux as space;
use secblitz::space::{Fs, CLEAN_BUDGET, MEASURE_BUDGET};
use std::time::Instant;

pub fn handles(request: &Request) -> bool {
    matches!(
        request,
        Request::SpaceMeasure { .. }
            | Request::SpaceClean { .. }
            | Request::Apps
            | Request::RemoveApps { .. }
    )
}

/// A sentence for the screen: the ones Secblitz wrote pass through, anything else goes to the log and the person gets a plain one.
fn plain(error: &anyhow::Error) -> String {
    let text = error.to_string();
    let known = [
        space::CANNOT_CLEAN,
        space::NOT_ON_THIS_SYSTEM,
        space::TRASH_NOT_EMPTIED,
    ];
    if known.contains(&text.as_str()) || apps::plain(&text).is_some() {
        return text;
    }
    eprintln!("A clean up step failed: {error:#}");
    space::CANNOT_CLEAN.to_owned()
}

/// Answers one clean up request, streaming what each item or app came to before the final reply.
pub fn run(sys: &dyn Sys, fs: &dyn Fs, now: u64, request: Request, emit: &mut dyn FnMut(Event)) {
    let reply = match request {
        Request::SpaceMeasure { items } => {
            for wire in items {
                let outcome = space::measure_machine(
                    sys,
                    fs,
                    wire.item(),
                    now,
                    Instant::now() + MEASURE_BUDGET,
                )
                .map_err(|e| plain(&e));
                emit(Event::Space {
                    item: wire,
                    outcome,
                });
            }
            Reply::Ok
        }
        Request::SpaceClean { items } => {
            for wire in items {
                let outcome =
                    space::clean_machine(sys, fs, wire.item(), now, Instant::now() + CLEAN_BUDGET)
                        .map_err(|e| plain(&e));
                emit(Event::Space {
                    item: wire,
                    outcome,
                });
            }
            Reply::Ok
        }
        Request::Apps => match apps::listable(sys) {
            Ok(found) => Reply::Apps(
                found
                    .into_iter()
                    .map(|i| AppWire {
                        index: i.index,
                        package: i.package,
                        version: i.version,
                    })
                    .collect(),
            ),
            Err(e) => Reply::Failed(match apps::plain(&e.to_string()) {
                Some(sentence) => sentence.to_owned(),
                None => {
                    eprintln!("Could not list the apps: {e:#}");
                    apps::LIST_FAILED.to_owned()
                }
            }),
        },
        Request::RemoveApps { packages } => {
            for package in packages {
                emit(Event::App {
                    package: package.clone(),
                    step: AppStep::Started,
                });
                let step = match apps::remove_package(sys, &package) {
                    secblitz::debloat::PackageOutcome::Removed => AppStep::Removed,
                    secblitz::debloat::PackageOutcome::Protected => {
                        AppStep::Failed(apps::REFUSED.to_owned())
                    }
                    secblitz::debloat::PackageOutcome::Failed(reason) => AppStep::Failed(reason),
                };
                emit(Event::App { package, step });
            }
            Reply::Ok
        }
        _ => Reply::Failed(apps::NOT_INSTALLED.to_owned()),
    };
    emit(Event::Done(reply));
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use secblitz::linux::cmd::Output;
    use secblitz::space::Entry;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Files and program replies held in memory; a program nobody planned for is an error.
    #[derive(Default)]
    pub struct Machine {
        pub files: BTreeMap<PathBuf, Vec<u8>>,
        pub replies: BTreeMap<String, Output>,
        pub calls: Mutex<Vec<String>>,
    }

    impl Machine {
        pub fn reply(&mut self, program: &str, args: &[&str], status: i32, stdout: &str) {
            let key = std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.replies.insert(
                key,
                Output {
                    status,
                    stdout: stdout.into(),
                    stderr: String::new(),
                },
            );
        }
    }

    impl Sys for Machine {
        fn run(&self, program: &'static str, args: &[&str]) -> anyhow::Result<Output> {
            let key = std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.calls.lock().unwrap().push(key.clone());
            self.replies
                .get(&key)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Unexpected program: {key}"))
        }
        fn read(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.files.get(path).cloned())
        }
        fn write_atomic(&self, _: &Path, _: &[u8], _: u32) -> anyhow::Result<()> {
            Ok(())
        }
        fn remove(&self, _: &Path) -> anyhow::Result<()> {
            Ok(())
        }
    }

    pub struct Nothing;

    impl Fs for Nothing {
        fn list(&self, dir: &Path, _max: usize) -> std::io::Result<Vec<Entry>> {
            if dir == Path::new("/var/crash") {
                Ok(vec![Entry {
                    path: "/var/crash/a.crash".into(),
                    is_dir: false,
                    reparse: false,
                    size: 2048,
                    created: 0,
                    written: 0,
                }])
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            }
        }
        fn delete_checked(
            &self,
            _: &Path,
            _: bool,
            check: &dyn Fn(&Entry) -> bool,
        ) -> std::io::Result<bool> {
            Ok(check(&Entry {
                path: "/var/crash/a.crash".into(),
                is_dir: false,
                reparse: false,
                size: 2048,
                created: 0,
                written: 0,
            }))
        }
        fn remove_empty_dir(
            &self,
            _: &Path,
            _: bool,
            _: &dyn Fn(&Entry) -> bool,
        ) -> std::io::Result<bool> {
            Ok(false)
        }
    }

    impl Machine {
        pub fn ubuntu() -> Machine {
            let mut m = Machine::default();
            m.files.insert(
                "/etc/os-release".into(),
                b"ID=ubuntu\nID_LIKE=debian\n".to_vec(),
            );
            m
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{Machine, Nothing};
    use super::*;
    use crate::app::remote::SpaceWire;

    fn ubuntu() -> Machine {
        Machine::ubuntu()
    }

    fn collect(machine: &Machine, request: Request) -> (Vec<String>, Reply) {
        let mut lines = Vec::new();
        let mut last = None;
        run(
            machine,
            &Nothing,
            100 * 86_400,
            request,
            &mut |event| match event {
                Event::Space { item, outcome } => lines.push(format!("{item:?} {outcome:?}")),
                Event::App { package, step } => lines.push(format!("{package} {step:?}")),
                Event::Progress { .. } => lines.push("progress".into()),
                Event::Done(reply) => last = Some(reply),
            },
        );
        (lines, last.expect("a final reply"))
    }

    #[test]
    fn measuring_answers_each_item_then_ends_with_ok() {
        let machine = ubuntu();
        let (lines, reply) = collect(
            &machine,
            Request::SpaceMeasure {
                items: vec![SpaceWire::CrashReports, SpaceWire::PackageCaches],
            },
        );
        assert!(matches!(reply, Reply::Ok));
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("CrashReports Ok(Tally { bytes: 2048, files: 1"));
        assert!(lines[1].starts_with("PackageCaches Ok("), "{}", lines[1]);
    }

    #[test]
    fn a_failing_item_does_not_stop_the_others_and_never_shows_a_path() {
        let machine = Machine::default();
        let (lines, reply) = collect(
            &machine,
            Request::SpaceMeasure {
                items: vec![SpaceWire::FlatpakRuntimes, SpaceWire::CrashReports],
            },
        );
        assert!(matches!(reply, Reply::Ok));
        assert!(lines[0].contains(space::CANNOT_CLEAN), "{}", lines[0]);
        assert!(!lines[0].contains("/usr/bin"));
        assert!(lines[1].starts_with("CrashReports Ok("));
    }

    #[test]
    fn cleaning_runs_the_package_manager_for_the_cache_only() {
        let mut machine = ubuntu();
        machine.reply("/usr/bin/apt-get", &["clean"], 0, "");
        let (lines, reply) = collect(
            &machine,
            Request::SpaceClean {
                items: vec![SpaceWire::PackageCaches],
            },
        );
        assert!(matches!(reply, Reply::Ok));
        assert!(lines[0].starts_with("PackageCaches Ok("));
        assert_eq!(
            machine.calls.lock().unwrap().as_slice(),
            ["/usr/bin/apt-get clean"]
        );
    }

    #[test]
    fn apps_are_listed_without_the_ones_whose_removal_would_take_more() {
        let mut machine = ubuntu();
        let dpkg = ["-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"];
        machine.reply(
            "/usr/bin/dpkg-query",
            &dpkg,
            0,
            "anydesk\t7\tii \nrustdesk\t1\tii \n",
        );
        machine.reply(
            "/usr/bin/apt-get",
            &["-s", "remove", "anydesk"],
            0,
            "Remv anydesk [7]\n",
        );
        machine.reply(
            "/usr/bin/apt-get",
            &["-s", "remove", "rustdesk"],
            0,
            "Remv rustdesk [1]\nRemv ubuntu-desktop [1]\n",
        );
        let (_, reply) = collect(&machine, Request::Apps);
        let Reply::Apps(found) = reply else {
            panic!("expected apps")
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].package, "anydesk");
    }

    #[test]
    fn removing_apps_reports_each_one_as_it_starts_and_ends() {
        let mut machine = ubuntu();
        machine.reply(
            "/usr/bin/apt-get",
            &["-s", "remove", "anydesk"],
            0,
            "Remv anydesk [7]\nRemv ubuntu-desktop [1]\n",
        );
        let (lines, reply) = collect(
            &machine,
            Request::RemoveApps {
                packages: vec!["anydesk".into()],
            },
        );
        assert!(matches!(reply, Reply::Ok));
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "anydesk Started");
        assert!(lines[1].starts_with("anydesk Failed("));
        assert!(lines[1].contains("other programs your computer needs"));
        assert!(!machine
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.contains("remove -y")));
    }

    #[test]
    fn this_module_only_takes_the_clean_up_requests() {
        assert!(handles(&Request::Apps));
        assert!(!handles(&Request::Audit));
        assert!(!handles(&Request::Undo));
        let machine = Machine::default();
        let (_, reply) = collect(&machine, Request::Audit);
        assert!(matches!(reply, Reply::Failed(_)));
    }
}
