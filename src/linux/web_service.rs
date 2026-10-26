//! The filter as a system service: it tells the system manager when it is answering and stops when asked.

use anyhow::{ensure, Result};
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

static SIGNALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    SIGNALLED.store(true, Ordering::Release);
}

fn watch_signals() -> Result<()> {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: the handler only stores into an atomic, which is allowed in a signal handler.
        let previous =
            unsafe { libc::signal(signal, on_signal as *const () as libc::sighandler_t) };
        ensure!(
            previous != libc::SIG_ERR,
            "Could not watch for a stop request"
        );
    }
    Ok(())
}

/// Sends one message to the system manager's notification socket. A path starting with `@` is an abstract name.
pub fn send_to(socket: &str, message: &str) -> io::Result<()> {
    let sender = UnixDatagram::unbound()?;
    if let Some(name) = socket.strip_prefix('@') {
        let address = SocketAddr::from_abstract_name(name.as_bytes())?;
        sender.send_to_addr(message.as_bytes(), &address)?;
    } else if socket.starts_with('/') {
        sender.send_to(message.as_bytes(), socket)?;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The notification socket is not a path",
        ));
    }
    Ok(())
}

/// Tells the system manager about the service's state. Does nothing when it was not started by one.
pub fn notify(message: &str) {
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET").and_then(|s| s.into_string().ok()) {
        if let Err(error) = send_to(&socket, message) {
            eprintln!("Could not tell the system manager: {error}");
        }
    }
}

/// Runs until the system asks it to stop. Ready is announced once the filter is answering, which is when lookups may be
/// sent to it.
pub fn run() -> Result<()> {
    watch_signals()?;
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if SIGNALLED.load(Ordering::Acquire) {
                    notify("STOPPING=1\n");
                    stop.store(true, Ordering::Release);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let outcome = crate::filter::service::run_production(&stop, &|| notify("READY=1\n"));
    stop.store(true, Ordering::Release);
    let _ = watcher.join();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_reaches_a_socket_by_path() {
        let dir = tempfile::tempdir_in("/dev/shm").unwrap();
        let path = dir.path().join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap();
        send_to(path.to_str().unwrap(), "READY=1\n").unwrap();
        let mut buffer = [0u8; 64];
        let n = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], b"READY=1\n");
    }

    #[test]
    fn a_message_reaches_a_socket_by_abstract_name() {
        let name = format!("secblitz-test-{}", std::process::id());
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap())
                .unwrap();
        send_to(&format!("@{name}"), "STOPPING=1\n").unwrap();
        let mut buffer = [0u8; 64];
        let n = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], b"STOPPING=1\n");
    }

    #[test]
    fn a_socket_that_is_not_a_path_is_refused() {
        assert!(send_to("notify", "READY=1\n").is_err());
        assert!(send_to("", "READY=1\n").is_err());
    }
}
