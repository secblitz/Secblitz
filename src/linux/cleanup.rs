//! The window's side of Free up space and Clean up apps: asks the helper for what needs rights and shows the answers as the same items and steps the Windows pages use.
use crate::app::remote::{stream, AppStep, Event, Reply, Request, SpaceWire, Transport};
use secblitz::debloat::linux as apps;
use secblitz::debloat::{remove_with_checkpoint, Batch, Installed, Kept, PackageOutcome, Progress};
use secblitz::space::{Item, Tally};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

fn wires(items: &[Item]) -> Vec<SpaceWire> {
    items.iter().filter_map(|i| SpaceWire::of(*i)).collect()
}

fn ask_items<T: Transport>(
    transport: &mut T,
    request: Request,
    on: &mut dyn FnMut(Item, Result<Tally, String>),
) -> anyhow::Result<()> {
    stream(transport, &request, &mut |event| {
        if let Event::Space { item, outcome } = event {
            on(item.item(), outcome);
        }
    })
    .map(drop)
}

/// The size of each item that needs the helper, one answer per item as it arrives.
pub fn measure<T: Transport>(
    transport: &mut T,
    items: &[Item],
    on: &mut dyn FnMut(Item, Result<Tally, String>),
) -> anyhow::Result<()> {
    ask_items(
        transport,
        Request::SpaceMeasure {
            items: wires(items),
        },
        on,
    )
}

/// Cleans each item that needs the helper. The password is asked for once, before the first.
pub fn clean<T: Transport>(
    transport: &mut T,
    items: &[Item],
    on: &mut dyn FnMut(Item, Result<Tally, String>),
) -> anyhow::Result<()> {
    ask_items(
        transport,
        Request::SpaceClean {
            items: wires(items),
        },
        on,
    )
}

/// The remote-control apps installed here that can be taken off safely.
pub fn inventory<T: Transport>(transport: &mut T) -> anyhow::Result<Vec<Installed>> {
    match stream(transport, &Request::Apps, &mut |_| {})? {
        Reply::Apps(found) => Ok(found
            .into_iter()
            .map(|a| Installed {
                index: a.index,
                package: a.package,
                version: a.version,
            })
            .collect()),
        _ => anyhow::bail!(apps::LIST_FAILED),
    }
}

/// A sentence the page can show: Secblitz's own pass through, anything else becomes a plain one.
fn sentence(error: &anyhow::Error) -> String {
    let text = error.to_string();
    if apps::plain(&text).is_some() || text == crate::linux_bus::polkit::NOT_ALLOWED {
        text
    } else {
        eprintln!("The helper could not remove the apps: {error:#}");
        apps::RUN_FAILED.to_owned()
    }
}

/// Removes the chosen apps in one request, so the password is asked for once, and reports each app as the helper finishes it.
pub fn remove<T: Transport + Send>(
    transport: &mut T,
    indices: &[u16],
    emit: &dyn Fn(Progress),
) -> anyhow::Result<Batch> {
    let installed = inventory(transport)?;
    let packages: Vec<String> = indices
        .iter()
        .flat_map(|index| installed.iter().filter(move |i| i.index == *index))
        .map(|i| i.package.clone())
        .collect();
    let (tx, rx) = mpsc::channel::<(String, AppStep)>();
    let failure: Arc<Mutex<Option<String>>> = Arc::default();
    let seen_by_call = failure.clone();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let result = stream(transport, &Request::RemoveApps { packages }, &mut |event| {
                if let Event::App { package, step } = event {
                    let _ = tx.send((package, step));
                }
            });
            if let Err(error) = result {
                *seen_by_call.lock().unwrap_or_else(|e| e.into_inner()) = Some(sentence(&error));
            }
        });
        let run = |package: &str| -> PackageOutcome {
            loop {
                match rx.recv() {
                    Ok((name, AppStep::Removed)) if name == package => {
                        return PackageOutcome::Removed
                    }
                    Ok((name, AppStep::Failed(reason))) if name == package => {
                        return PackageOutcome::Failed(reason)
                    }
                    Ok(_) => {}
                    Err(_) => {
                        let reason = failure
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone()
                            .unwrap_or_else(|| apps::RUN_FAILED.to_owned());
                        return PackageOutcome::Failed(reason);
                    }
                }
            }
        };
        // No copy is kept on Linux, so there is no step for saving one.
        let show = |progress: Progress| {
            if !matches!(progress, Progress::Saving(_)) {
                emit(progress);
            }
        };
        remove_with_checkpoint(
            indices,
            &installed,
            &|_: &Installed| -> Result<(), Kept> { Ok(()) },
            &run,
            &show,
            &|_| Ok(()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::remote::{decode_request, encode_request};
    use crate::linux_bus::ops;

    /// Carries each request straight to the helper's own code over a machine held in memory.
    struct Direct<'a> {
        sys: &'a (dyn secblitz::linux::cmd::Sys + Sync),
        asked: Vec<String>,
    }

    impl Transport for Direct<'_> {
        fn call(
            &mut self,
            request: &[u8],
            on_event: &mut dyn FnMut(&[u8]) -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            let request = decode_request(request)?;
            self.asked.push(format!("{request:?}"));
            let mut failure = None;
            ops::run(
                self.sys,
                &ops::tests_support::Nothing,
                0,
                request,
                &mut |event| {
                    if failure.is_none() {
                        let sent = serde_json::to_vec(&event)
                            .map_err(Into::into)
                            .and_then(|bytes| on_event(&bytes));
                        failure = sent.err();
                    }
                },
            );
            failure.map_or(Ok(()), Err)
        }
    }

    struct Down;

    impl Transport for Down {
        fn call(
            &mut self,
            _: &[u8],
            _: &mut dyn FnMut(&[u8]) -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            anyhow::bail!(crate::linux_bus::polkit::NOT_ALLOWED)
        }
    }

    #[test]
    fn only_the_items_that_need_the_helper_are_sent() {
        let items = [
            Item::PackageCaches,
            Item::ThumbnailCache,
            Item::Trash,
            Item::CrashReports,
            Item::FlatpakRuntimes,
            Item::OldSnaps,
            Item::OldKernels,
            Item::Temp,
        ];
        assert_eq!(
            wires(&items),
            [
                SpaceWire::PackageCaches,
                SpaceWire::CrashReports,
                SpaceWire::FlatpakRuntimes,
                SpaceWire::OldSnaps,
                SpaceWire::OldKernels
            ]
        );
    }

    #[test]
    fn a_closed_door_is_reported_for_removals_with_the_password_sentence() {
        let result = measure(&mut Down, &[Item::PackageCaches], &mut |_, _| {});
        assert_eq!(
            result.unwrap_err().to_string(),
            crate::linux_bus::polkit::NOT_ALLOWED
        );
        assert_eq!(
            sentence(&anyhow::anyhow!(crate::linux_bus::polkit::NOT_ALLOWED)),
            crate::linux_bus::polkit::NOT_ALLOWED
        );
        assert_eq!(
            sentence(&anyhow::anyhow!("D-Bus error: weird")),
            apps::RUN_FAILED
        );
    }

    #[test]
    fn requests_cross_the_wire_unchanged() {
        let request = Request::RemoveApps {
            packages: vec!["anydesk".into()],
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), request);
        let bad = Request::RemoveApps {
            packages: vec!["ubuntu-desktop".into()],
        };
        assert!(encode_request(&bad).is_err());
        let twice = Request::SpaceClean {
            items: vec![SpaceWire::CrashReports, SpaceWire::CrashReports],
        };
        assert!(encode_request(&twice).is_err());
    }

    #[test]
    fn removing_apps_asks_once_and_fills_the_same_batch_the_windows_page_reads() {
        use crate::linux_bus::ops::tests_support::Machine;
        let mut machine = Machine::ubuntu();
        machine.reply(
            "/usr/bin/dpkg-query",
            &["-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"],
            0,
            "anydesk\t7\tii \nrustdesk\t1\tii \n",
        );
        for name in ["anydesk", "rustdesk"] {
            machine.reply(
                "/usr/bin/apt-get",
                &["-s", "remove", name],
                0,
                &format!("Remv {name} [1]\n"),
            );
            machine.reply(
                "/usr/bin/dpkg-query",
                &["-W", "-f=${db:Status-Abbrev}", name],
                1,
                "",
            );
        }
        let mut transport = Direct {
            sys: &machine,
            asked: Vec::new(),
        };
        let first = secblitz::debloat::linux::owner("anydesk").unwrap();
        let second = secblitz::debloat::linux::owner("rustdesk").unwrap();
        let steps = Mutex::new(Vec::new());
        let batch = remove(&mut transport, &[first, second], &|p| {
            steps.lock().unwrap().push(format!("{p:?}"));
        })
        .unwrap();
        assert_eq!(batch.removed_apps(), 2, "{batch:?} {:?}", transport.asked);
        assert!(batch.failed.is_empty());
        let steps = steps.into_inner().unwrap();
        assert_eq!(steps.len(), 4, "{steps:?}");
        assert!(steps.iter().all(|s| !s.contains("Saving")));
        let removals = transport
            .asked
            .iter()
            .filter(|a| a.starts_with("RemoveApps"))
            .count();
        assert_eq!(removals, 1);
    }

    #[test]
    fn a_refused_password_fails_every_app_with_the_password_sentence() {
        struct Gate {
            listed: bool,
        }
        impl Transport for Gate {
            fn call(
                &mut self,
                request: &[u8],
                on_event: &mut dyn FnMut(&[u8]) -> anyhow::Result<()>,
            ) -> anyhow::Result<()> {
                match decode_request(request)? {
                    Request::Apps => {
                        self.listed = true;
                        let done = Event::Done(Reply::Apps(vec![crate::app::remote::AppWire {
                            index: secblitz::debloat::linux::owner("anydesk").unwrap(),
                            package: "anydesk".into(),
                            version: "7".into(),
                        }]));
                        on_event(&serde_json::to_vec(&done)?)
                    }
                    _ => anyhow::bail!(crate::linux_bus::polkit::NOT_ALLOWED),
                }
            }
        }
        let index = secblitz::debloat::linux::owner("anydesk").unwrap();
        let batch = remove(&mut Gate { listed: false }, &[index], &|_| {}).unwrap();
        assert_eq!(batch.failed.len(), 1);
        assert_eq!(
            batch.failed[0].reason,
            crate::linux_bus::polkit::NOT_ALLOWED
        );
        assert!(batch.removed.is_empty());
    }
}
