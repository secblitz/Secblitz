//! Secblitz engine: Windows hardening checks, fixes and undo, plus the update, service and diagnostics support the GUI and CLI build on.
//!
//! The library holds logic that depends on neither the GUI nor the command line: checks, fixes and undo, plain-language advice and explanations, user settings, updates and the background service. The binary crate (`main.rs`) holds the GUI, the command line, the launcher and the admin helper.
pub mod actions;
pub mod advice;
pub mod clock;
pub mod damaged;
pub mod debloat;
pub mod diagnostics;
pub mod engine;
pub mod explain;
pub mod filter;
pub mod hardening;
pub mod linux;
pub mod model;
pub mod operations;
pub mod os;
pub mod patching;
pub mod permissions;
pub mod platform;
pub mod readiness;
pub mod service;
pub mod software_install;
pub mod space;
pub mod status;
pub mod text;
pub mod updater;
pub mod user_settings;
pub mod vbs;
