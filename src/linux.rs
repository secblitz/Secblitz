//! Linux support: how the app reaches the system, which distribution and desktop it runs on, and the compiled Linux catalog.
//! Everything here compiles on every system so the tests run anywhere; only the real command runner is Linux-only.
pub mod catalog;
pub mod cmd;
pub mod distro;
pub mod person;
