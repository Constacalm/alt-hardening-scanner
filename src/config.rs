use std::path::PathBuf;

pub const APP_ID: &str = "org.firstbeelancer.alt-hardening-scanner";
pub const APP_NAME: &str = "ALT Hardening Scanner";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const REPORT_DIR_NAME: &str = "alt-hardening-scanner";
pub const LOG_FILE_NAME: &str = "scan.log";

pub fn reports_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join(REPORT_DIR_NAME);
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(REPORT_DIR_NAME)
}

pub fn log_file_path() -> PathBuf {
    reports_dir().join(LOG_FILE_NAME)
}
