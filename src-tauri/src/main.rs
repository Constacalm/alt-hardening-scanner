// Предотвращаем появление консольного окна в Windows в release-сборке
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod checks;
mod remediation;
mod report;
mod scanner;

use remediation::{apply_settings, get_fail_ids};
use report::generate_report;
use scanner::{get_system_info, scan_all};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan_all,
            get_system_info,
            apply_settings,
            get_fail_ids,
            generate_report,
        ])
        .run(tauri::generate_context!())
        .expect("Ошибка запуска Tauri-приложения");
}
