use chrono::Local;
use serde::Deserialize;
use std::fs;
use std::process::Command;

use crate::checks::Interface;
use crate::scanner::{ScanResult, Status};

#[derive(Debug, Deserialize)]
pub enum ReportFormat {
    Html,
    Pdf,
}

#[derive(Debug, Deserialize)]
pub struct ReportMetadata {
    pub hostname: String,
    pub scan_started_at: String,
    pub scan_finished_at: String,
    pub username: String,
    pub user_id: String,
}

#[tauri::command]
pub async fn generate_report(
    results: Vec<ScanResult>,
    output_path: String,
    format: ReportFormat,
    metadata: ReportMetadata,
) -> Result<String, String> {
    let html = build_html(&results, &metadata);

    match format {
        ReportFormat::Html => {
            fs::write(&output_path, &html)
                .map_err(|e| format!("Ошибка записи HTML: {}", e))?;
            Ok(format!("HTML-отчёт сохранён: {}", output_path))
        }
        ReportFormat::Pdf => {
            let html_tmp = format!("{}.tmp.html", output_path);
            fs::write(&html_tmp, &html)
                .map_err(|e| format!("Ошибка записи временного HTML: {}", e))?;

            let result = Command::new("wkhtmltopdf")
                .args([
                    "--quiet",
                    "--page-size",
                    "A4",
                    "--margin-top",
                    "15mm",
                    "--margin-bottom",
                    "15mm",
                    "--margin-left",
                    "20mm",
                    "--margin-right",
                    "20mm",
                    &html_tmp,
                    &output_path,
                ])
                .output();

            let _ = fs::remove_file(&html_tmp);

            match result {
                Ok(out) if out.status.success() => {
                    Ok(format!("PDF-отчёт сохранён: {}", output_path))
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    let html_fallback = output_path.replace(".pdf", ".html");
                    let _ = fs::write(&html_fallback, &html);
                    Err(format!(
                        "wkhtmltopdf вернул ошибку: {}\nHTML-отчёт сохранён как: {}",
                        stderr, html_fallback
                    ))
                }
                Err(_) => {
                    let html_fallback = output_path.replace(".pdf", ".html");
                    fs::write(&html_fallback, &html)
                        .map_err(|e| format!("Ошибка записи HTML fallback: {}", e))?;
                    Err(format!(
                        "wkhtmltopdf не найден в системе. HTML-отчёт сохранён: {}",
                        html_fallback
                    ))
                }
            }
        }
    }
}

fn build_html(results: &[ScanResult], metadata: &ReportMetadata) -> String {
    let generated_at = Local::now().format("%d.%m.%Y %H:%M:%S").to_string();
    let total = results.len();
    let pass_count = results
        .iter()
        .filter(|r| matches!(r.status, Status::Pass))
        .count();
    let fail_count = results
        .iter()
        .filter(|r| matches!(r.status, Status::Fail))
        .count();
    let na_count = results
        .iter()
        .filter(|r| matches!(r.status, Status::Na))
        .count();
    let compliance = if total == 0 {
        0
    } else {
        ((pass_count as f64 / total as f64) * 100.0).round() as usize
    };
    let rows = build_rows(results);

    format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ALT Hardening Scanner — Отчёт</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 13px;
      color: #1d2b4f;
      background: #eef3ff;
      padding: 24px;
    }}
    .report-header {{
      background: linear-gradient(140deg, #ffffff 0%, #f2f6ff 100%);
      border: 1px solid #d7e2ff;
      border-radius: 18px;
      padding: 24px 28px;
      margin-bottom: 18px;
      box-shadow: 0 12px 28px rgba(28, 73, 160, 0.08);
    }}
    .report-header h1 {{
      font-size: 24px;
      font-weight: 800;
      color: #184a9f;
      margin-bottom: 10px;
    }}
    .report-header .meta {{
      color: #4e679a;
      font-size: 13px;
      line-height: 1.6;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}
    .meta-card {{
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid #d7e2ff;
      border-radius: 14px;
      padding: 12px 14px;
    }}
    .meta-card .label {{
      display: block;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #6a7cab;
      margin-bottom: 6px;
    }}
    .meta-card .value {{
      font-size: 14px;
      font-weight: 700;
      color: #173e86;
    }}
    .summary {{
      display: flex;
      gap: 12px;
      margin-bottom: 18px;
      flex-wrap: wrap;
    }}
    .summary-card {{
      background: #ffffff;
      border: 1px solid #d7e2ff;
      border-radius: 16px;
      padding: 14px 20px;
      box-shadow: 0 10px 24px rgba(28, 73, 160, 0.06);
      text-align: center;
      min-width: 140px;
    }}
    .summary-card .value {{ font-size: 30px; font-weight: 800; }}
    .summary-card .label {{ font-size: 11px; color: #6a7cab; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .pass-card .value {{ color: #14946b; }}
    .fail-card .value {{ color: #d6455d; }}
    .na-card .value {{ color: #6f7fa8; }}
    .score-card .value {{ color: #2a5bd7; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #ffffff;
      box-shadow: 0 10px 24px rgba(28, 73, 160, 0.06);
      border-radius: 18px;
      overflow: hidden;
    }}
    thead {{
      background: linear-gradient(90deg, #184a9f 0%, #3d74ea 100%);
      color: #ffffff;
    }}
    thead th {{
      padding: 12px 14px;
      text-align: left;
      font-weight: 700;
      font-size: 12px;
      letter-spacing: 0.04em;
    }}
    tbody tr {{ border-bottom: 1px solid #edf2ff; }}
    tbody td {{ padding: 10px 14px; vertical-align: top; }}
    .row-pass {{ background: #edf9f3; }}
    .row-fail {{ background: #fff1f4; }}
    .row-na {{ background: #f7f9ff; color: #6d7ba0; }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
    }}
    .badge-pass {{ background: #c8f1df; color: #0d7c58; }}
    .badge-fail {{ background: #ffd4dc; color: #b63148; }}
    .badge-na {{ background: #dfe6fb; color: #5d6d97; }}
    .iface-badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      background: #dbe8ff;
      color: #1d55ba;
      text-transform: uppercase;
    }}
    .grub-badge {{
      background: #e6efff;
      color: #355fc4;
    }}
    code {{
      font-family: "Cascadia Code", "Consolas", monospace;
      font-size: 12px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .footer {{
      margin-top: 18px;
      text-align: center;
      font-size: 11px;
      color: #7d8caf;
    }}
  </style>
</head>
<body>
  <div class="report-header">
    <h1>ALT Hardening Scanner — Отчёт проверки</h1>
    <div class="meta">
      Документ соответствия РД ФСТЭК «Рекомендации по обеспечению безопасной настройки ОС Linux» от 25.12.2022.<br>
      Отчёт сформирован: <strong>{generated_at}</strong>
    </div>

    <div class="meta-grid">
      <div class="meta-card">
        <span class="label">Имя хоста</span>
        <span class="value">{hostname}</span>
      </div>
      <div class="meta-card">
        <span class="label">Пользователь</span>
        <span class="value">{username}</span>
      </div>
      <div class="meta-card">
        <span class="label">ID пользователя</span>
        <span class="value">{user_id}</span>
      </div>
      <div class="meta-card">
        <span class="label">Начало сканирования</span>
        <span class="value">{scan_started_at}</span>
      </div>
      <div class="meta-card">
        <span class="label">Окончание сканирования</span>
        <span class="value">{scan_finished_at}</span>
      </div>
      <div class="meta-card">
        <span class="label">Состояние профиля</span>
        <span class="value">{compliance}% соответствия</span>
      </div>
    </div>
  </div>

  <div class="summary">
    <div class="summary-card">
      <div class="value">{total}</div>
      <div class="label">Всего проверок</div>
    </div>
    <div class="summary-card pass-card">
      <div class="value">{pass_count}</div>
      <div class="label">Соответствует</div>
    </div>
    <div class="summary-card fail-card">
      <div class="value">{fail_count}</div>
      <div class="label">Требует внимания</div>
    </div>
    <div class="summary-card na-card">
      <div class="value">{na_count}</div>
      <div class="label">Не применимо</div>
    </div>
    <div class="summary-card score-card">
      <div class="value">{compliance}%</div>
      <div class="label">Индекс соответствия</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th style="width: 44px">№</th>
        <th style="width: 100px">Интерфейс</th>
        <th>Параметр</th>
        <th style="width: 130px">Текущее</th>
        <th style="width: 130px">Цель</th>
        <th style="width: 92px">Статус</th>
        <th>Описание</th>
        <th>Раздел документа</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <div class="footer">
    Сформировано инструментом ALT Hardening Scanner v1.0 | {generated_at}
  </div>
</body>
</html>"#,
        generated_at = generated_at,
        hostname = html_escape(&metadata.hostname),
        username = html_escape(&metadata.username),
        user_id = html_escape(&metadata.user_id),
        scan_started_at = html_escape(&metadata.scan_started_at),
        scan_finished_at = html_escape(&metadata.scan_finished_at),
        total = total,
        pass_count = pass_count,
        fail_count = fail_count,
        na_count = na_count,
        compliance = compliance,
        rows = rows,
    )
}

fn build_rows(results: &[ScanResult]) -> String {
    results
        .iter()
        .map(|r| {
            let (row_class, badge_class, status_text) = match r.status {
                Status::Pass => ("row-pass", "badge-pass", "PASS"),
                Status::Fail => ("row-fail", "badge-fail", "FAIL"),
                Status::Na => ("row-na", "badge-na", "N/A"),
            };
            let (iface_class, iface_text) = match r.check.interface {
                Interface::Sysctl => ("iface-badge", "sysctl"),
                Interface::Grub => ("iface-badge grub-badge", "grub"),
            };

            format!(
                r#"<tr class="{row_class}">
  <td style="text-align:center">{id}</td>
  <td><span class="{iface_class}">{iface_text}</span></td>
  <td><code>{param}</code></td>
  <td><code>{current}</code></td>
  <td><code>{target}</code></td>
  <td style="text-align:center"><span class="badge {badge_class}">{status}</span></td>
  <td style="font-size:12px">{description}</td>
  <td style="font-size:11px;color:#55698e">{section}</td>
</tr>"#,
                row_class = row_class,
                id = r.check.id,
                iface_class = iface_class,
                iface_text = iface_text,
                param = html_escape(r.check.param),
                current = html_escape(&r.current_value),
                target = html_escape(r.check.target_value),
                badge_class = badge_class,
                status = status_text,
                description = html_escape(r.check.description),
                section = html_escape(r.check.section),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
