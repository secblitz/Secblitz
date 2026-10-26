//! Locking and durable journal writes.

#[cfg(test)]
use super::fsio::write_snapshot_with_fault;
use super::fsio::{
    io_boundary, metadata_safe, open_file, publish_snapshot, read_bytes, same_file, sync_directory,
};
use super::journal::{record_bytes, Record, Transaction};
use super::{Engine, LOCK_NAME, MAX_WAL, SCHEMA};
use anyhow::{ensure, Context, Result};
use std::{fs, fs::File, io::Write};

/// On Linux and macOS the lock belongs to the open file, and a program another
/// thread is starting holds a copy of every open file until it is running, so a
/// lock released a moment ago can still look taken.
#[cfg(unix)]
fn try_lock_briefly(file: &File) -> std::io::Result<()> {
    let contended = fs2::lock_contended_error().raw_os_error();
    for _ in 0..50 {
        match fs2::FileExt::try_lock_exclusive(file) {
            Err(e) if e.raw_os_error() == contended => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            done => return done,
        }
    }
    fs2::FileExt::try_lock_exclusive(file)
}

#[cfg(not(unix))]
fn try_lock_briefly(file: &File) -> std::io::Result<()> {
    fs2::FileExt::try_lock_exclusive(file)
}

impl Engine {
    pub(super) fn lock(&self) -> Result<File> {
        ensure!(
            !self.storage_failed,
            "Journal storage failed; reopen the engine after resolving storage failure"
        );
        metadata_safe(&fs::symlink_metadata(&self.dir)?, true)?;
        let path = self.dir.join(LOCK_NAME);
        let file = match fs::symlink_metadata(&path) {
            Ok(_) => open_file(&path, false)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match open_file(&path, true) {
                Ok(f) => f,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
                {
                    open_file(&path, false)?
                }
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e.into()),
        };
        try_lock_briefly(&file).context("Another Secblitz operation holds the journal lock")?;
        same_file(&file, &path)?;
        Ok(file)
    }

    pub(super) fn append(&mut self, tx: &mut Transaction, record: Record) -> Result<()> {
        let result = (|| {
            let path = self.dir.join(format!("{}.jsonl", tx.name));
            if let Some(file) = tx.file.as_mut() {
                same_file(file, &path)?;
                ensure!(
                    file.metadata()?.len() == tx.length,
                    "Journal length changed since validation"
                );
                ensure!(
                    read_bytes(file)? == tx.disk_bytes,
                    "Journal bytes changed since validation"
                );
            } else {
                ensure!(
                    tx.length == 0 && !path.try_exists()?,
                    "Missing journal handle"
                );
            }
            let mut bytes = tx.bytes.clone();
            bytes.extend(record_bytes(&record)?);
            ensure!(bytes.len() as u64 <= MAX_WAL, "Journal is full");
            if tx.bytes != tx.disk_bytes {
                self.preserve_evidence(&tx.name, &tx.disk_bytes)?;
            }
            let stage_path = self.dir.join(format!("{}.jsonl.next", tx.name));
            io_boundary("snapshot_create")?;
            let mut staged = open_file(&stage_path, true)?;
            io_boundary("snapshot_write")?;
            #[cfg(test)]
            write_snapshot_with_fault(&mut staged, &bytes)?;
            #[cfg(not(test))]
            staged.write_all(&bytes)?;
            staged.flush()?;
            io_boundary("snapshot_sync")?;
            staged.sync_all()?;
            same_file(&staged, &stage_path)?;
            if let Some(file) = tx.file.as_mut() {
                same_file(file, &path)?;
                ensure!(
                    read_bytes(file)? == tx.disk_bytes,
                    "Journal changed during snapshot write"
                );
            }
            drop(staged);
            // The shared engine lock and protected directory remain pinned
            // through the narrow Windows close/rename/reopen window.
            drop(tx.file.take());
            io_boundary("snapshot_replace")?;
            publish_snapshot(&stage_path, &path)?;
            io_boundary("snapshot_directory")?;
            sync_directory(&self.dir)?;
            io_boundary("snapshot_reopen")?;
            tx.file = Some(open_file(&path, false)?);
            tx.length = bytes.len() as u64;
            tx.disk_bytes = bytes.clone();
            tx.bytes = bytes;
            Ok(())
        })();
        if result.is_err() {
            self.storage_failed = true;
        }
        result
    }

    pub(super) fn durable(&mut self, transactions: &[Transaction]) -> Result<()> {
        let result = (|| {
            for tx in transactions {
                tx.file
                    .as_ref()
                    .context("Missing journal handle")?
                    .sync_all()?;
            }
            sync_directory(&self.dir)
        })();
        if result.is_err() {
            self.storage_failed = true;
        }
        result
    }

    pub(super) fn create(&mut self, sequence: u64) -> Result<Transaction> {
        let name = format!("{sequence:020}-{}", uuid::Uuid::new_v4());
        let mut tx = Transaction {
            name: name.clone(),
            sequence,
            entries: Vec::new(),
            sealed: false,
            reverting: false,
            reverted: false,
            file: None,
            length: 0,
            bytes: Vec::new(),
            disk_bytes: Vec::new(),
        };
        self.append(
            &mut tx,
            Record::Header {
                schema: SCHEMA,
                machine: self.machine.clone(),
                transaction: name,
                sequence,
            },
        )?;
        if let Err(e) = sync_directory(&self.dir) {
            self.storage_failed = true;
            return Err(e);
        }
        Ok(tx)
    }
}
