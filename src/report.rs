use chrono::Local;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::models::{Interface, ReportFormat, ReportMetadata, ScanResult, Status};

pub fn generate_report(
    results: &[ScanResult],
    output_path: &Path,
    format: &ReportFormat,
    metadata: &ReportMetadata,
) -> Result<String, String> {
    let html = build_html(results, metadata);

    match format {
        ReportFormat::Html => {
            fs::write(output_path, html).map_err(|error| format!("Ошибка записи HTML: {error}"))?;
            Ok(format!("HTML-отчёт сохранён: {}", output_path.display()))
        }
        ReportFormat::Pdf => {
            let html_path = output_path.with_extension("html");
            fs::write(&html_path, &html)
                .map_err(|error| format!("Ошибка записи временного HTML: {error}"))?;

            match Command::new("wkhtmltopdf")
                .args([
                    "--quiet",
                    "--page-size",
                    "A4",
                    "--margin-top",
                    "15mm",
                    "--margin-bottom",
                    "15mm",
                    "--margin-left",
                    "18mm",
                    "--margin-right",
                    "18mm",
                    html_path.to_string_lossy().as_ref(),
                    output_path.to_string_lossy().as_ref(),
                ])
                .output()
            {
                Ok(result) if result.status.success() => {
                    let _ = fs::remove_file(&html_path);
                    Ok(format!("PDF-отчёт сохранён: {}", output_path.display()))
                }
                Ok(result) => Err(format!(
                    "wkhtmltopdf завершился с ошибкой: {}. HTML-версия сохранена рядом: {}",
                    String::from_utf8_lossy(&result.stderr).trim(),
                    html_path.display()
                )),
                Err(_) => Err(format!(
                    "wkhtmltopdf не найден в системе. HTML-версия сохранена: {}",
                    html_path.display()
                )),
            }
        }
    }
}

fn build_html(results: &[ScanResult], metadata: &ReportMetadata) -> String {
    let generated_at = Local::now().format("%d.%m.%Y %H:%M:%S").to_string();
    let total = results.len();
    let pass = results
        .iter()
        .filter(|item| item.status == Status::Pass)
        .count();
    let fail = results
        .iter()
        .filter(|item| item.status == Status::Fail)
        .count();
    let na = results
        .iter()
        .filter(|item| item.status == Status::Na)
        .count();
    let compliance = if total == 0 {
        0
    } else {
        ((pass as f64 / total as f64) * 100.0).round() as usize
    };

    let rows = results
        .iter()
        .map(|item| {
            let (row_class, badge_class, status_text) = match item.status {
                Status::Pass => ("row-pass", "badge-pass", "PASS"),
                Status::Fail => ("row-fail", "badge-fail", "FAIL"),
                Status::Na => ("row-na", "badge-na", "N/A"),
            };
            let interface = match item.check.interface {
                Interface::Sysctl => "sysctl",
                Interface::Grub => "grub",
            };

            format!(
                r#"<tr class="{row_class}">
<td>{id}</td>
<td>{interface}</td>
<td><code>{param}</code></td>
<td>{current}</td>
<td>{target}</td>
<td><span class="badge {badge_class}">{status}</span></td>
<td>{description}</td>
<td>{section}</td>
</tr>"#,
                row_class = row_class,
                id = item.check.id,
                interface = interface,
                param = html_escape(&item.check.param),
                current = html_escape(&item.current_value),
                target = html_escape(&item.check.target_value),
                badge_class = badge_class,
                status = status_text,
                description = html_escape(&item.check.description),
                section = html_escape(&item.check.section),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ALT Hardening Scanner — Отчёт</title>
  <style>
    body {{
      font-family: "Inter", "Segoe UI", sans-serif;
      background: #f4f7ff;
      color: #17345f;
      padding: 24px;
      margin: 0;
    }}
    .panel {{
      background: #fff;
      border: 1px solid #d6e0fb;
      border-radius: 18px;
      padding: 20px 24px;
      margin-bottom: 18px;
      box-shadow: 0 14px 30px rgba(23, 52, 95, 0.08);
    }}
    h1 {{
      margin: 0 0 8px;
      color: #16459f;
      font-size: 24px;
    }}
    .meta-grid, .summary {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-top: 16px;
    }}
    .summary {{
      grid-template-columns: repeat(5, minmax(0, 1fr));
    }}
    .card {{
      background: #f8fbff;
      border: 1px solid #dbe5fb;
      border-radius: 14px;
      padding: 12px 14px;
    }}
    .label {{
      display: block;
      font-size: 11px;
      color: #7284ac;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 6px;
    }}
    .value {{
      font-size: 16px;
      font-weight: 700;
      color: #17345f;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border-radius: 18px;
      overflow: hidden;
      box-shadow: 0 14px 30px rgba(23, 52, 95, 0.08);
    }}
    thead {{
      background: #2559d6;
      color: #fff;
    }}
    th, td {{
      padding: 12px 14px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid #edf2ff;
    }}
    .row-pass {{ background: #eef9f3; }}
    .row-fail {{ background: #fff0f3; }}
    .row-na {{ background: #f5f8ff; }}
    .badge {{
      display: inline-block;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 11px;
      font-weight: 700;
    }}
    .badge-pass {{ background: #d5f5e4; color: #167c57; }}
    .badge-fail {{ background: #ffd8e0; color: #c6455d; }}
    .badge-na {{ background: #dde5fb; color: #62749d; }}
    code {{ font-family: "Cascadia Code", "Consolas", monospace; }}
    .foot {{
      text-align: center;
      margin-top: 16px;
      color: #7a89ab;
      font-size: 12px;
    }}
  </style>
</head>
<body>
  <div class="panel">
    <h1>Отчёт о состоянии безопасности</h1>
    <div>РД ФСТЭК «Рекомендации по обеспечению безопасной настройки ОС Linux» от 25.12.2022</div>
    <div class="meta-grid">
      <div class="card"><span class="label">Хост</span><span class="value">{hostname}</span></div>
      <div class="card"><span class="label">Пользователь</span><span class="value">{username}</span></div>
      <div class="card"><span class="label">ID пользователя</span><span class="value">{user_id}</span></div>
      <div class="card"><span class="label">Начало сканирования</span><span class="value">{scan_started}</span></div>
      <div class="card"><span class="label">Окончание сканирования</span><span class="value">{scan_finished}</span></div>
      <div class="card"><span class="label">Сформировано</span><span class="value">{generated_at}</span></div>
    </div>
  </div>

  <div class="summary">
    <div class="card"><span class="label">Проверено</span><span class="value">{total}</span></div>
    <div class="card"><span class="label">Соответствует</span><span class="value">{pass}</span></div>
    <div class="card"><span class="label">Требует внимания</span><span class="value">{fail}</span></div>
    <div class="card"><span class="label">Не применимо</span><span class="value">{na}</span></div>
    <div class="card"><span class="label">Соответствие</span><span class="value">{compliance}%</span></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>№</th>
        <th>Интерфейс</th>
        <th>Параметр</th>
        <th>Текущее</th>
        <th>Цель</th>
        <th>Статус</th>
        <th>Описание</th>
        <th>Раздел документа</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <div class="foot">Сформировано инструментом ALT Hardening Scanner v1.0</div>
</body>
</html>"#,
        hostname = html_escape(&metadata.hostname),
        username = html_escape(&metadata.username),
        user_id = html_escape(&metadata.user_id),
        scan_started = html_escape(&metadata.scan_started_at),
        scan_finished = html_escape(&metadata.scan_finished_at),
        generated_at = generated_at,
        total = total,
        pass = pass,
        fail = fail,
        na = na,
        compliance = compliance,
        rows = rows,
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
