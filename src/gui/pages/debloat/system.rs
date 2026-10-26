//! How Free up space and Clean up apps reach the computer on Linux: through the root helper for anything that needs rights, and in this window, as the signed-in person, for their own folders. Windows keeps its own paths in the pages, so everything here answers "not available" there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
use iced::futures::Stream;
use secblitz::debloat::linux::Removed;
use secblitz::debloat::{Batch, Installed, Progress};
use secblitz::space::{Item, Tally, UserArea};

pub type Outcome = Result<Tally, String>;

/// Whether the person's own folders can be handled from this window.
pub fn person_ready() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
mod real {
    use super::*;
    use crate::gui::blocking_stream;
    use crate::linux_bus::{cleanup, client::DbusTransport};
    use secblitz::linux::cmd::{RealSys, SessionSys, Sys};
    use secblitz::linux::person::session_bus;
    use secblitz::space::linux::{self as space, PersonDirs, RealFs};

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn plain(error: &anyhow::Error) -> String {
        let text = error.to_string();
        if [
            space::CANNOT_CLEAN,
            space::NOT_ON_THIS_SYSTEM,
            space::TRASH_NOT_EMPTIED,
            crate::linux_bus::polkit::NOT_ALLOWED,
        ]
        .contains(&text.as_str())
        {
            text
        } else {
            eprintln!("A clean up step failed: {error:#}");
            space::CANNOT_CLEAN.to_owned()
        }
    }

    pub fn person(area: UserArea, delete: bool) -> Outcome {
        let dirs = PersonDirs::from_env().ok_or_else(|| space::CANNOT_CLEAN.to_owned())?;
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let bus_env = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        let bus = session_bus(uid, bus_env.as_deref(), |p| p.exists());
        // The desktop's Trash tool does nothing, yet succeeds, without the person's message bus.
        let sys = match bus.as_deref().map(|b| SessionSys::new(b, uid)) {
            Some(Ok(sys)) => Some(sys),
            _ => None,
        };
        let result = match (&sys, area) {
            (None, UserArea::Trash) if delete => Err(anyhow::anyhow!(space::TRASH_NOT_EMPTIED)),
            (Some(sys), _) => run_person(sys, &dirs, area, delete),
            (None, _) => run_person(&RealSys, &dirs, area, delete),
        };
        result.map_err(|e| plain(&e))
    }

    fn run_person(
        sys: &dyn Sys,
        dirs: &PersonDirs,
        area: UserArea,
        delete: bool,
    ) -> anyhow::Result<Tally> {
        if delete {
            space::clean_person(sys, &RealFs, dirs, area, now())
        } else {
            space::measure_person(sys, &RealFs, dirs, area, now())
        }
    }

    /// One answer per item, as the helper gives them. If the helper cannot be reached, every item that got no answer gets the reason.
    pub fn machine(items: Vec<Item>, delete: bool) -> impl Stream<Item = (Item, Outcome)> {
        blocking_stream(move |emit: &dyn Fn((Item, Outcome))| {
            let mut transport = DbusTransport::system();
            let mut answered = Vec::new();
            let mut on = |item: Item, outcome: Outcome| {
                answered.push(item);
                emit((item, outcome));
            };
            let result = if delete {
                cleanup::clean(&mut transport, &items, &mut on)
            } else {
                cleanup::measure(&mut transport, &items, &mut on)
            };
            if let Err(error) = result {
                let reason = plain(&error);
                for item in items.iter().filter(|i| !answered.contains(i)) {
                    emit((*item, Err(reason.clone())));
                }
            }
        })
    }

    pub fn inventory() -> anyhow::Result<Vec<Installed>> {
        cleanup::inventory(&mut DbusTransport::system())
    }

    pub fn remove(indices: &[u16], emit: &dyn Fn(Progress)) -> anyhow::Result<Batch> {
        cleanup::remove(&mut DbusTransport::system(), indices, emit)
    }

    pub fn removed() -> anyhow::Result<Vec<Removed>> {
        cleanup::removed(&mut DbusTransport::system())
    }

    pub fn reinstall(package: &str) -> Result<(), String> {
        cleanup::reinstall(&mut DbusTransport::system(), package)
    }
}

#[cfg(target_os = "linux")]
pub use real::{inventory, machine, person, reinstall, remove, removed};

#[cfg(not(target_os = "linux"))]
mod other {
    use super::*;

    pub fn person(_: UserArea, _: bool) -> Outcome {
        Err("unavailable".into())
    }

    pub fn machine(items: Vec<Item>, _: bool) -> impl Stream<Item = (Item, Outcome)> {
        iced::futures::stream::iter(
            items
                .into_iter()
                .map(|item| (item, Err("unavailable".to_owned()))),
        )
    }

    pub fn inventory() -> anyhow::Result<Vec<Installed>> {
        anyhow::bail!("unavailable")
    }

    pub fn remove(_: &[u16], _: &dyn Fn(Progress)) -> anyhow::Result<Batch> {
        anyhow::bail!("unavailable")
    }

    pub fn removed() -> anyhow::Result<Vec<Removed>> {
        anyhow::bail!("unavailable")
    }

    pub fn reinstall(_: &str) -> Result<(), String> {
        Err("unavailable".into())
    }
}

#[cfg(not(target_os = "linux"))]
pub use other::{inventory, machine, person, reinstall, remove, removed};
