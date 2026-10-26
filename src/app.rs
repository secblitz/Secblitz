//! UI-independent application layer shared by the GUI.
pub mod app_access;
#[cfg(any(target_os = "linux", test))]
pub mod composite;
pub mod flow;
pub mod history;
pub mod last_check;
pub mod maintenance;
pub mod open_request;
pub mod os_text;
#[allow(dead_code)]
pub mod remote;
pub mod score;
pub mod search;
pub mod settings;
pub mod support;
pub mod topics;
pub mod welcome;
pub mod whats_new;
pub mod worker;
