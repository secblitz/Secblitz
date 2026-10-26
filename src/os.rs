//! The operating system this build runs on. Each one has its own compiled catalog of checks.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Windows,
    Linux,
    Macos,
}

impl Os {
    #[cfg(windows)]
    pub const CURRENT: Os = Os::Windows;
    #[cfg(target_os = "macos")]
    pub const CURRENT: Os = Os::Macos;
    #[cfg(not(any(windows, target_os = "macos")))]
    pub const CURRENT: Os = Os::Linux;

    pub fn name(self) -> &'static str {
        match self {
            Os::Windows => "Windows",
            Os::Linux => "Linux",
            Os::Macos => "macOS",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_the_plain_product_names() {
        assert_eq!(Os::Windows.name(), "Windows");
        assert_eq!(Os::Linux.name(), "Linux");
        assert_eq!(Os::Macos.name(), "macOS");
    }

    #[test]
    fn the_running_system_is_chosen_at_build_time() {
        #[cfg(windows)]
        assert_eq!(Os::CURRENT, Os::Windows);
        #[cfg(target_os = "macos")]
        assert_eq!(Os::CURRENT, Os::Macos);
        #[cfg(target_os = "linux")]
        assert_eq!(Os::CURRENT, Os::Linux);
    }
}
