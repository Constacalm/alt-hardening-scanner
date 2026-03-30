use regex::Regex;
use std::fs;
use std::process::Command;

use crate::checks::all_checks;
use crate::models::{Check, HostAnalytics, Interface, ScanResult, Status, SystemInfo};

pub fn scan_all() -> Vec<ScanResult> {
    let checks = all_checks();
    let grub_cmdline = read_grub_cmdline();
    let mut results = Vec::with_capacity(checks.len());

    for check in checks {
        let result = match check.interface {
            Interface::Sysctl => scan_sysctl(&check),
            Interface::Grub => scan_grub(&check, &grub_cmdline),
        };
        results.push(result);
    }

    results.sort_by_key(|item| item.check.id);
    results
}

pub fn get_system_info() -> SystemInfo {
    SystemInfo {
        hostname: read_file_trimmed("/proc/sys/kernel/hostname")
            .unwrap_or_else(|| "unknown".to_string()),
        os_name: read_os_name(),
        kernel: command_stdout("uname", &["-r"]).unwrap_or_else(|| "unknown".to_string()),
        username: read_username(),
        user_id: read_user_id(),
    }
}

pub fn get_host_analytics() -> HostAnalytics {
    HostAnalytics {
        uptime: read_uptime(),
        last_update: read_last_update(),
        repositories: read_repositories(),
        ip_address: read_primary_ip(),
        network_name: read_network_name(),
    }
}

pub fn grub_param_present(cmdline: &str, param: &str) -> bool {
    let tokens: Vec<&str> = param.split_whitespace().collect();
    tokens.iter().all(|token| {
        let key = token.split('=').next().unwrap_or(token);
        let pattern = format!(r"(?:^|\s){}(?:=\S*)?(?:\s|$)", regex::escape(key));
        Regex::new(&pattern)
            .map(|regex| regex.is_match(cmdline))
            .unwrap_or(false)
    })
}

fn scan_sysctl(check: &Check) -> ScanResult {
    let output = Command::new("sysctl").args(["-n", &check.param]).output();

    match output {
        Ok(out) if out.status.success() || !out.stdout.is_empty() => {
            let current_value = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let status = if current_value == check.target_value {
                Status::Pass
            } else {
                Status::Fail
            };

            ScanResult {
                check: check.clone(),
                current_value,
                status,
            }
        }
        _ => ScanResult {
            check: check.clone(),
            current_value: "—".to_string(),
            status: Status::Na,
        },
    }
}

fn scan_grub(check: &Check, grub_cmdline: &Option<String>) -> ScanResult {
    let Some(cmdline) = grub_cmdline else {
        return ScanResult {
            check: check.clone(),
            current_value: "—".to_string(),
            status: Status::Na,
        };
    };

    let present = grub_param_present(cmdline, &check.param);
    ScanResult {
        check: check.clone(),
        current_value: if present {
            check.param.clone()
        } else {
            "—".to_string()
        },
        status: if present { Status::Pass } else { Status::Fail },
    }
}

fn read_grub_cmdline() -> Option<String> {
    let content = fs::read_to_string("/etc/default/grub").ok()?;
    let regex = Regex::new(r#"GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*"([^"]*)""#).ok()?;
    let captures = regex.captures(&content)?;
    Some(captures[1].to_string())
}

fn read_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| command_stdout("whoami", &[]))
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_user_id() -> String {
    command_stdout("id", &["-u"])
        .or_else(|| read_file_trimmed("/proc/self/loginuid"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_os_name() -> String {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        if let Ok(regex) = Regex::new(r#"PRETTY_NAME\s*=\s*"([^"]*)""#) {
            if let Some(captures) = regex.captures(&content) {
                return captures[1].to_string();
            }
        }
    }

    command_stdout("uname", &["-s"]).unwrap_or_else(|| "Linux".to_string())
}

fn read_uptime() -> String {
    let Some(raw) = read_file_trimmed("/proc/uptime") else {
        return "недоступно".to_string();
    };

    let seconds = raw
        .split_whitespace()
        .next()
        .and_then(|value| value.split('.').next())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();

    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    format!("{days} дн. {hours} ч. {minutes} мин.")
}

fn read_last_update() -> String {
    let candidates = [
        "/var/lib/apt/lists",
        "/var/cache/apt/pkgcache.bin",
        "/var/cache/apt/srcpkgcache.bin",
    ];

    for path in candidates {
        if let Ok(metadata) = fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                let datetime = chrono::DateTime::<chrono::Local>::from(modified);
                return datetime.format("%Y-%m-%d %H:%M:%S").to_string();
            }
        }
    }

    "неизвестно".to_string()
}

fn read_repositories() -> Vec<String> {
    let files = ["/etc/apt/sources.list", "/etc/apt/sources.list.d"];
    let mut repositories = Vec::new();

    for path in files {
        let metadata = fs::metadata(path);
        match metadata {
            Ok(meta) if meta.is_file() => {
                if let Ok(content) = fs::read_to_string(path) {
                    repositories.extend(
                        content
                            .lines()
                            .map(str::trim)
                            .filter(|line| !line.is_empty() && !line.starts_with('#'))
                            .map(ToOwned::to_owned),
                    );
                }
            }
            Ok(meta) if meta.is_dir() => {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            repositories.extend(
                                content
                                    .lines()
                                    .map(str::trim)
                                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                                    .map(ToOwned::to_owned),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if repositories.is_empty() {
        repositories.push("репозитории не обнаружены".to_string());
    }

    repositories
}

fn read_primary_ip() -> String {
    if let Some(value) = command_stdout("hostname", &["-I"]) {
        let ip = value.split_whitespace().next().unwrap_or_default();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }

    command_stdout("ip", &["route", "get", "1.1.1.1"])
        .and_then(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let index = parts.iter().position(|item| *item == "src")?;
            parts.get(index + 1).map(|value| (*value).to_string())
        })
        .unwrap_or_else(|| "неизвестно".to_string())
}

fn read_network_name() -> String {
    command_stdout("hostname", &["-d"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "локальный сегмент".to_string())
}

fn command_stdout(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() && output.stdout.is_empty() {
        return None;
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn read_file_trimmed(path: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let value = content.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}
