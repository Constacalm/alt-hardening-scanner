use chrono::Local;
use regex::Regex;
use serde::Serialize;
use std::fs;
use std::process::Command;

use crate::checks::{all_checks, Interface};
use crate::scanner::{grub_param_present, ScanResult, Status};

#[derive(Debug, Serialize)]
pub struct ApplyResult {
    pub applied: Vec<String>,
    pub failed: Vec<ApplyError>,
    pub needs_reboot: bool,
}

#[derive(Debug, Serialize)]
pub struct ApplyError {
    pub param: String,
    pub reason: String,
}

#[tauri::command]
pub async fn apply_settings(check_ids: Vec<u32>) -> Result<ApplyResult, String> {
    // Проверяем права root
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            return Err(
                "Для применения настроек требуются права root. \
                 Перезапустите: sudo alt-hardening-scanner"
                    .to_string(),
            );
        }
    }

    let all = all_checks();
    let targets: Vec<_> = all
        .into_iter()
        .filter(|c| check_ids.contains(&c.id))
        .collect();

    let mut applied = Vec::new();
    let mut failed = Vec::new();
    let mut needs_reboot = false;

    let sysctl_targets: Vec<_> = targets
        .iter()
        .filter(|c| matches!(c.interface, Interface::Sysctl))
        .collect();

    let grub_targets: Vec<_> = targets
        .iter()
        .filter(|c| matches!(c.interface, Interface::Grub))
        .collect();

    // ── Применяем sysctl-параметры ────────────────────────────────────────────
    if !sysctl_targets.is_empty() {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let backup_path = format!("/etc/sysctl.conf.bak_{}", timestamp);

        if let Err(e) = fs::copy("/etc/sysctl.conf", &backup_path) {
            // Если файла нет — создадим пустой и попробуем снова
            if e.kind() == std::io::ErrorKind::NotFound {
                let _ = fs::write("/etc/sysctl.conf", "");
                let _ = fs::copy("/etc/sysctl.conf", &backup_path);
            }
        }

        let sysctl_content = fs::read_to_string("/etc/sysctl.conf").unwrap_or_default();

        let mut new_content = sysctl_content.clone();

        for check in &sysctl_targets {
            let line = format!("{} = {}", check.param, check.target_value);

            // Ищем строку с этим параметром (с возможным комментарием)
            let pattern = format!(r"(?m)^[#\s]*{}\s*=.*$", regex::escape(check.param));
            let re = Regex::new(&pattern).unwrap();

            if re.is_match(&new_content) {
                // Заменяем существующую строку
                new_content = re.replace(&new_content, line.as_str()).to_string();
            } else {
                // Добавляем в конец
                if !new_content.ends_with('\n') && !new_content.is_empty() {
                    new_content.push('\n');
                }
                new_content.push_str(&line);
                new_content.push('\n');
            }

            // Применяем немедленно через sysctl -w
            let apply = Command::new("sysctl")
                .args(["-w", &format!("{}={}", check.param, check.target_value)])
                .output();

            match apply {
                Ok(out) if out.status.success() => {
                    applied.push(check.param.to_string());
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    failed.push(ApplyError {
                        param: check.param.to_string(),
                        reason: stderr,
                    });
                }
                Err(e) => {
                    failed.push(ApplyError {
                        param: check.param.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        if let Err(e) = fs::write("/etc/sysctl.conf", &new_content) {
            return Err(format!("Не удалось записать /etc/sysctl.conf: {}", e));
        }
    }

    // ── Применяем GRUB-параметры ──────────────────────────────────────────────
    if !grub_targets.is_empty() {
        let grub_path = "/etc/default/grub";
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let backup_path = format!("{}.bak_{}", grub_path, timestamp);

        let grub_content = fs::read_to_string(grub_path)
            .map_err(|e| format!("Не удалось прочитать {}: {}", grub_path, e))?;

        let _ = fs::copy(grub_path, &backup_path);

        // Извлекаем текущий GRUB_CMDLINE_LINUX_DEFAULT
        let cmdline_re =
            Regex::new(r#"(GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*")([^"]*)(")"#).unwrap();

        let new_grub = if let Some(caps) = cmdline_re.captures(&grub_content) {
            let prefix = caps[1].to_string();
            let mut cmdline = caps[2].to_string();
            let suffix = caps[3].to_string();

            for check in &grub_targets {
                // Разбиваем параметр на отдельные токены (для id=5 их несколько)
                let tokens: Vec<&str> = check.param.split_whitespace().collect();
                for token in tokens {
                    if !grub_param_present(&cmdline, token) {
                        if !cmdline.is_empty() {
                            cmdline.push(' ');
                        }
                        cmdline.push_str(token);
                    }
                }
                applied.push(check.param.to_string());
            }

            cmdline_re
                .replace(&grub_content, format!("{}{}{}", prefix, cmdline, suffix))
                .to_string()
        } else {
            return Err(
                "GRUB_CMDLINE_LINUX_DEFAULT не найден в /etc/default/grub".to_string()
            );
        };

        fs::write(grub_path, &new_grub)
            .map_err(|e| format!("Не удалось записать {}: {}", grub_path, e))?;

        // Запускаем update-grub
        let update = Command::new("update-grub").output();
        match update {
            Ok(out) if out.status.success() => {
                needs_reboot = true;
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                failed.push(ApplyError {
                    param: "update-grub".to_string(),
                    reason: stderr,
                });
            }
            Err(e) => {
                failed.push(ApplyError {
                    param: "update-grub".to_string(),
                    reason: format!("update-grub не найден: {}", e),
                });
            }
        }
    }

    Ok(ApplyResult {
        applied,
        failed,
        needs_reboot,
    })
}

/// Возвращает список id проверок, которые имеют статус Fail
#[tauri::command]
pub async fn get_fail_ids(results: Vec<ScanResult>) -> Result<Vec<u32>, String> {
    let ids = results
        .iter()
        .filter(|r| matches!(r.status, Status::Fail))
        .map(|r| r.check.id)
        .collect();
    Ok(ids)
}
