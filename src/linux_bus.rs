//! The root helper on the system message bus and the window's side of it.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
#[path = "linux/cleanup.rs"]
pub mod cleanup;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "linux/client.rs"]
pub mod client;
#[cfg(target_os = "linux")]
#[path = "linux/helper.rs"]
pub mod helper;
#[path = "linux/ops.rs"]
pub mod ops;
#[path = "linux/polkit.rs"]
pub mod polkit;
