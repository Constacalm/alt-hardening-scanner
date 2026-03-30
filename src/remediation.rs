use chrono::Local;
use regex::Regex;
use std::fs;
use std::process::Command;

use crate::checks::all_checks;
use crate::models::{ApplyError, ApplyResult, Interface, ScanResult, Status};
use crate::scanner::grub_param_present;

pub fn apply_settings(check_ids: &[u32]) -> Result<ApplyResult, String> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            return Err(
                "Для применения настроек требуются права root. Перезапустите приложение через sudo."
                    .to_string(),
            );
        }
    }

    let targets: Vec<_> = all_checks()
        .into_iter()
        .filter(|check| check_ids.contains(&check.id))
        .collect();

    let mut applied = Vec::new();
    let mut failed = Vec::new();
    let mut needs_reboot = false;

    let sysctl_targets: Vec<_> = targets
        .iter()
        .filter(|check| matches!(check.interface, Interface::Sysctl))
        .collect();

    let grub_targets: Vec<_> = targets
        .iter()
        .filter(|check| matches!(check.interface, Interface::Grub))
        .collect();

    if !sysctl_targets.is_empty() {
        apply_sysctl_targets(&sysctl_targets, &mut applied, &mut failed)?;
    }

    if !grub_targets.is_empty() {
        let grub_result = apply_grub_targets(&grub_targets, &mut applied, &mut failed)?;
        needs_reboot = grub_result;
    }

    Ok(ApplyResult {
        applied,
        failed,
        needs_reboot,
    })
}

pub fn get_fail_ids(results: &[ScanResult]) -> Vec<u32> {
    results
        .iter()
        .filter(|item| item.status == Status::Fail)
        .map(|item| item.check.id)
        .collect()
}

fn apply_sysctl_targets(
    checks: &[&crate::models::Check],
    applied: &mut Vec<String>,
    failed: &mut Vec<ApplyError>,
) -> Result<(), String> {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = format!("/etc/sysctl.conf.bak_{timestamp}");

    if fs::metadata("/etc/sysctl.conf").is_err() {
        fs::write("/etc/sysctl.conf", "").map_err(|error| error.to_string())?;
    }

    let _ = fs::copy("/etc/sysctl.conf", &backup_path);

    let mut content = fs::read_to_string("/etc/sysctl.conf").unwrap_or_default();

    for check in checks {
        let line = format!("{} = {}", check.param, check.target_value);
        let pattern = format!(r"(?m)^[#\s]*{}\s*=.*$", regex::escape(&check.param));
        let regex = Regex::new(&pattern).map_err(|error| error.to_string())?;

        if regex.is_match(&content) {
            content = regex.replace(&content, line.as_str()).to_string();
        } else {
            if !content.ends_with('\n') && !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&line);
            content.push('\n');
        }

        let output = Command::new("sysctl")
            .args(["-w", &format!("{}={}", check.param, check.target_value)])
            .output();

        match output {
            Ok(result) if result.status.success() => applied.push(check.param.clone()),
            Ok(result) => failed.push(ApplyError {
                param: check.param.clone(),
                reason: String::from_utf8_lossy(&result.stderr).trim().to_string(),
            }),
            Err(error) => failed.push(ApplyError {
                param: check.param.clone(),
                reason: error.to_string(),
            }),
        }
    }

    fs::write("/etc/sysctl.conf", content)
        .map_err(|error| format!("Не удалось записать /etc/sysctl.conf: {error}"))?;

    Ok(())
}

fn apply_grub_targets(
    checks: &[&crate::models::Check],
    applied: &mut Vec<String>,
    failed: &mut Vec<ApplyError>,
) -> Result<bool, String> {
    let grub_path = "/etc/default/grub";
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = format!("{grub_path}.bak_{timestamp}");

    let content = fs::read_to_string(grub_path)
        .map_err(|error| format!("Не удалось прочитать {grub_path}: {error}"))?;

    let _ = fs::copy(grub_path, &backup_path);

    let regex = Regex::new(r#"(GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*")([^"]*)(")"#)
        .map_err(|error| error.to_string())?;

    let Some(captures) = regex.captures(&content) else {
        return Err("GRUB_CMDLINE_LINUX_DEFAULT не найден в /etc/default/grub".to_string());
    };

    let prefix = captures[1].to_string();
    let mut cmdline = captures[2].to_string();
    let suffix = captures[3].to_string();

    for check in checks {
        for token in check.param.split_whitespace() {
            if !grub_param_present(&cmdline, token) {
                if !cmdline.is_empty() {
                    cmdline.push(' ');
                }
                cmdline.push_str(token);
            }
        }
        applied.push(check.param.clone());
    }

    let new_content = regex
        .replace(&content, format!("{prefix}{cmdline}{suffix}"))
        .to_string();

    fs::write(grub_path, new_content)
        .map_err(|error| format!("Не удалось записать {grub_path}: {error}"))?;

    match Command::new("update-grub").output() {
        Ok(result) if result.status.success() => Ok(true),
        Ok(result) => {
            failed.push(ApplyError {
                param: "update-grub".to_string(),
                reason: String::from_utf8_lossy(&result.stderr).trim().to_string(),
            });
            Ok(false)
        }
        Err(error) => {
            failed.push(ApplyError {
                param: "update-grub".to_string(),
                reason: error.to_string(),
            });
            Ok(false)
        }
    }
}
