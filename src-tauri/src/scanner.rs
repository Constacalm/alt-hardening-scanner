use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;

use crate::checks::{all_checks, Check, Interface};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Status {
    Pass,
    Fail,
    Na,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub check: Check,
    pub current_value: String,
    pub status: Status,
}

#[tauri::command]
pub async fn scan_all() -> Result<Vec<ScanResult>, String> {
    let checks = all_checks();
    let grub_cmdline = read_grub_cmdline();
    let mut results = Vec::with_capacity(checks.len());

    for check in checks {
        let result = match &check.interface {
            Interface::Sysctl => scan_sysctl(&check),
            Interface::Grub => scan_grub(&check, &grub_cmdline),
        };
        results.push(result);
    }

    // Сортируем по id для стабильного порядка в таблице
    results.sort_by_key(|r| r.check.id);
    Ok(results)
}

fn scan_sysctl(check: &Check) -> ScanResult {
    let output = Command::new("sysctl").args(["-n", check.param]).output();

    match output {
        Err(_) => ScanResult {
            check: check.clone(),
            current_value: "—".to_string(),
            status: Status::Na,
        },
        Ok(out) => {
            if !out.status.success() && out.stdout.is_empty() {
                return ScanResult {
                    check: check.clone(),
                    current_value: "—".to_string(),
                    status: Status::Na,
                };
            }
            let current = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let status = if current == check.target_value {
                Status::Pass
            } else {
                Status::Fail
            };
            ScanResult {
                check: check.clone(),
                current_value: current,
                status,
            }
        }
    }
}

fn scan_grub(check: &Check, cmdline: &Option<String>) -> ScanResult {
    let cmdline = match cmdline {
        None => {
            return ScanResult {
                check: check.clone(),
                current_value: "—".to_string(),
                status: Status::Na,
            }
        }
        Some(s) => s,
    };

    let present = grub_param_present(cmdline, check.param);
    ScanResult {
        check: check.clone(),
        current_value: if present {
            check.param.to_string()
        } else {
            "—".to_string()
        },
        status: if present { Status::Pass } else { Status::Fail },
    }
}

/// Читает /etc/default/grub и возвращает содержимое GRUB_CMDLINE_LINUX_DEFAULT
fn read_grub_cmdline() -> Option<String> {
    let content = fs::read_to_string("/etc/default/grub").ok()?;
    let re = Regex::new(r#"GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*"([^"]*)""#).ok()?;
    let caps = re.captures(&content)?;
    Some(caps[1].to_string())
}

/// Проверяет наличие параметра в cmdline строке.
/// Поддерживает параметры вида:
///   - "iommu=force" — ищет точное совпадение ключа
///   - "slab_nomerge" — флаг без значения
///   - "iommu=force" в составе "iommu=force iommu.strict=1 ..." — все токены должны присутствовать
pub fn grub_param_present(cmdline: &str, param: &str) -> bool {
    // Параметр id=5 содержит несколько токенов через пробел
    let tokens: Vec<&str> = param.split_whitespace().collect();
    tokens.iter().all(|token| {
        let key = token.split('=').next().unwrap_or(token);
        // Ищем точный ключ в cmdline (окружённый пробелом или краем строки)
        let pattern = format!(r"(?:^|\s){}(?:=\S*)?(?:\s|$)", regex::escape(key));
        let re = Regex::new(&pattern).unwrap_or_else(|_| Regex::new(r"NOMATCH").unwrap());
        re.is_match(cmdline)
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub kernel: String,
    pub username: String,
    pub user_id: String,
}

#[tauri::command]
pub async fn get_system_info() -> Result<SystemInfo, String> {
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let os_name = read_os_name();
    let username = read_username();
    let user_id = read_user_id();

    let kernel = Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    Ok(SystemInfo {
        hostname,
        os_name,
        kernel,
        username,
        user_id,
    })
}

fn read_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            Command::new("whoami")
                .output()
                .ok()
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_user_id() -> String {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fs::read_to_string("/proc/self/loginuid")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_os_name() -> String {
    // Пытаемся прочитать /etc/os-release
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        let re = Regex::new(r#"PRETTY_NAME\s*=\s*"([^"]*)""#).unwrap();
        if let Some(caps) = re.captures(&content) {
            return caps[1].to_string();
        }
    }
    // Fallback — uname -s
    Command::new("uname")
        .arg("-s")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Linux".to_string())
}
