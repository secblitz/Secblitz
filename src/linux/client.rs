//! The window's side of the helper: sends each request over the system bus and hands back the events as they arrive.
use super::helper::{INTERFACE, NAME, PATH};
use crate::app::remote::{self, RemoteSession, Transport};
use crate::launcher::NOT_INSTALLED;
use zbus::{fdo, Connection};

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
            None => zbus::connection::Builder::system(),
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
        zbus::block_on(async {
            let connection = self.connect().await?;
            let reply = connection
                .call_method(
                    Some(NAME),
                    PATH,
                    Some(INTERFACE),
                    "Begin",
                    &request.to_vec(),
                )
                .await
                .map_err(plain)?;
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
