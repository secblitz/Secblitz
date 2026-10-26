//! The window's side of the helper: sends each request over the system bus and hands back the events as they arrive.
use super::helper::{BUSY, INTERFACE, NAME, PATH};
use crate::app::remote::{self, RemoteSession, Transport};
use crate::launcher::NOT_INSTALLED;
use secblitz::filter::config::Config;
use secblitz::linux::web::{PauseFor, WebState};
use zbus::{fdo, Connection};

/// The helper runs one job at a time and turns away a second one, so this window sends one request at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// How often a request the helper turned away for another program's job is sent again, a second apart.
const BUSY_TRIES: u32 = 30;

const UNREACHABLE: &str = "Secblitz could not reach its helper. Try again, and reinstall Secblitz from the software app if it keeps happening.";

pub struct DbusTransport {
    address: Option<String>,
    connection: Option<Connection>,
}

impl DbusTransport {
    pub fn system() -> Self {
        Self {
            address: None,
            connection: None,
        }
    }

    /// Talks to a bus other than the system one. Used by the tests.
    #[cfg(test)]
    pub fn at(address: &str) -> Self {
        Self {
            address: Some(address.to_owned()),
            connection: None,
        }
    }

    async fn connect(&mut self) -> anyhow::Result<Connection> {
        if let Some(connection) = &self.connection {
            return Ok(connection.clone());
        }
        let builder = match &self.address {
            Some(address) => zbus::connection::Builder::address(address.as_str()),
            #[cfg(not(test))]
            None => zbus::connection::Builder::system(),
            // Tests never reach the helper a real install runs on this machine.
            #[cfg(test)]
            None => anyhow::bail!(NOT_INSTALLED),
        };
        let connection = builder.build().await.map_err(|error| {
            eprintln!("Cannot reach the system bus: {error}");
            anyhow::anyhow!(NOT_INSTALLED)
        })?;
        self.connection = Some(connection.clone());
        Ok(connection)
    }
}

/// Turns a failed call into a sentence a person can act on; the detail goes to the log.
fn plain(error: zbus::Error) -> anyhow::Error {
    eprintln!("The helper call failed: {error}");
    if let zbus::Error::FDO(inner) = &error {
        match inner.as_ref() {
            fdo::Error::Failed(message) | fdo::Error::AccessDenied(message) => {
                return anyhow::anyhow!(message.clone());
            }
            fdo::Error::ServiceUnknown(_)
            | fdo::Error::NameHasNoOwner(_)
            | fdo::Error::SpawnExecFailed(_)
            | fdo::Error::SpawnFailed(_)
            | fdo::Error::SpawnServiceNotFound(_)
            | fdo::Error::SpawnServiceNotValid(_)
            | fdo::Error::SpawnChildExited(_)
            | fdo::Error::SpawnChildSignaled(_)
            | fdo::Error::SpawnFailedToSetup(_)
            | fdo::Error::SpawnConfigInvalid(_)
            | fdo::Error::SpawnFileInvalid(_)
            | fdo::Error::SpawnForkFailed(_)
            | fdo::Error::SpawnNoMemory(_)
            | fdo::Error::SpawnPermissionsInvalid(_) => return anyhow::anyhow!(NOT_INSTALLED),
            _ => (),
        }
    }
    anyhow::anyhow!(UNREACHABLE)
}

impl Transport for DbusTransport {
    fn call(
        &mut self,
        request: &[u8],
        on_event: &mut dyn FnMut(&[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        zbus::block_on(async {
            let connection = self.connect().await?;
            let mut tries = 0;
            let reply = loop {
                match connection
                    .call_method(
                        Some(NAME),
                        PATH,
                        Some(INTERFACE),
                        "Begin",
                        &request.to_vec(),
                    )
                    .await
                    .map_err(plain)
                {
                    Err(e) if e.to_string() == BUSY && tries < BUSY_TRIES => {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    other => break other?,
                }
            };
            let job: u64 = reply.body().deserialize().map_err(plain)?;
            loop {
                let reply = connection
                    .call_method(Some(NAME), PATH, Some(INTERFACE), "Next", &job)
                    .await
                    .map_err(plain)?;
                let (events, done): (Vec<Vec<u8>>, bool) =
                    reply.body().deserialize().map_err(plain)?;
                for event in &events {
                    on_event(event)?;
                }
                if done {
                    return Ok(());
                }
            }
        })
    }
}

/// A session backed by the helper. Connecting asks it which settings it can handle, which also wakes it up.
pub fn session() -> anyhow::Result<RemoteSession<DbusTransport>> {
    RemoteSession::connect(DbusTransport::system())
}

pub fn start_fresh() -> anyhow::Result<()> {
    remote::start_fresh(&mut DbusTransport::system())
}

/// Asks the helper to remove Secblitz's package. Returns once the removal has started.
pub fn remove_self() -> anyhow::Result<()> {
    remote::remove_self(&mut DbusTransport::system())
}

/// Everything the web protection page shows. Needs no password.
pub fn web_state() -> anyhow::Result<WebState> {
    remote::web_state(&mut DbusTransport::system())
}

/// Saves the web protection switches. Turning them all off also stops the filter.
pub fn web_apply(config: Config) -> anyhow::Result<()> {
    remote::web_apply(&mut DbusTransport::system(), config)
}

pub fn web_pause(length: PauseFor) -> anyhow::Result<()> {
    remote::web_pause(&mut DbusTransport::system(), length)
}

pub fn web_resume() -> anyhow::Result<()> {
    remote::web_resume(&mut DbusTransport::system())
}

pub fn web_allow(site: &str) -> anyhow::Result<()> {
    remote::web_allow(&mut DbusTransport::system(), site)
}

pub fn web_allow_once(site: &str) -> anyhow::Result<()> {
    remote::web_allow_once(&mut DbusTransport::system(), site)
}

pub fn web_remove_allowed(site: &str) -> anyhow::Result<()> {
    remote::web_remove_allowed(&mut DbusTransport::system(), site)
}
