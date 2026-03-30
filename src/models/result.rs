#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Na,
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass => "Соответствует",
            Self::Fail => "Требует внимания",
            Self::Na => "Не применимо",
        }
    }

    pub fn css_class(&self) -> &'static str {
        match self {
            Self::Pass => "status-pass",
            Self::Fail => "status-fail",
            Self::Na => "status-na",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub check: crate::models::Check,
    pub current_value: String,
    pub status: Status,
}

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub kernel: String,
    pub username: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct HostAnalytics {
    pub uptime: String,
    pub last_update: String,
    pub repositories: Vec<String>,
    pub ip_address: String,
    pub network_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScanSession {
    pub scan_started_at: String,
    pub scan_finished_at: String,
    pub hostname: String,
    pub username: String,
    pub user_id: String,
}

#[derive(Debug, Clone)]
pub enum ReportFormat {
    Html,
    Pdf,
}

impl ReportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Pdf => "pdf",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Html => "HTML",
            Self::Pdf => "PDF",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReportMetadata {
    pub hostname: String,
    pub scan_started_at: String,
    pub scan_finished_at: String,
    pub username: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct ApplyResult {
    pub applied: Vec<String>,
    pub failed: Vec<ApplyError>,
    pub needs_reboot: bool,
}

#[derive(Debug, Clone)]
pub struct ApplyError {
    pub param: String,
    pub reason: String,
}
