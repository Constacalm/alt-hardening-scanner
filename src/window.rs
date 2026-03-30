use std::cell::RefCell;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use adw::prelude::*;
use chrono::Local;
use gtk::glib::{self, ControlFlow};
use gtk::prelude::*;

use crate::checks::all_checks;
use crate::config::{reports_dir, APP_NAME, APP_VERSION};
use crate::models::{
    ApplyResult, HostAnalytics, ReportFormat, ReportMetadata, ScanResult, ScanSession, Status,
    SystemInfo,
};
use crate::remediation::{apply_settings, get_fail_ids};
use crate::report::generate_report;
use crate::scanner::{get_host_analytics, get_system_info, scan_all};
use crate::widgets::build_scan_row;

#[derive(Debug, Default)]
struct UiState {
    results: Vec<ScanResult>,
    system_info: SystemInfo,
    analytics: HostAnalytics,
    session: ScanSession,
    report_history: Vec<String>,
    logs: Vec<String>,
}

enum WorkerResponse {
    ScanFinished {
        results: Vec<ScanResult>,
        system_info: SystemInfo,
        analytics: HostAnalytics,
        finished_at: String,
    },
    ScanFailed(String),
    ApplyFinished(Result<ApplyResult, String>),
}

pub struct MainWindow {
    window: adw::ApplicationWindow,
}

impl MainWindow {
    pub fn new(app: &adw::Application) -> Self {
        let state = Rc::new(RefCell::new(UiState::default()));

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title(APP_NAME)
            .default_width(1360)
            .default_height(880)
            .build();

        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let header = adw::HeaderBar::new();
        let title = adw::WindowTitle::builder()
            .title(APP_NAME)
            .subtitle("ALT Linux p11 • GTK4/libadwaita")
            .build();
        header.set_title_widget(Some(&title));

        let scan_button = gtk::Button::with_label("Запустить сканирование");
        scan_button.add_css_class("suggested-action");
        let apply_button = gtk::Button::with_label("Применить настройки");
        let export_html_button = gtk::Button::with_label("Экспорт HTML");
        let export_pdf_button = gtk::Button::with_label("Экспорт PDF");

        header.pack_start(&scan_button);
        header.pack_start(&apply_button);
        header.pack_end(&export_pdf_button);
        header.pack_end(&export_html_button);

        let content = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        content.set_margin_top(12);
        content.set_margin_bottom(12);
        content.set_margin_start(12);
        content.set_margin_end(12);

        let stack = gtk::Stack::new();
        stack.set_hexpand(true);
        stack.set_vexpand(true);
        stack.set_transition_type(gtk::StackTransitionType::SlideLeftRight);

        let sidebar = gtk::StackSidebar::new();
        sidebar.set_stack(Some(&stack));
        sidebar.add_css_class("sidebar");
        sidebar.set_size_request(220, -1);

        let dashboard_page = gtk::Box::new(gtk::Orientation::Vertical, 12);
        let summary_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let checked_label = summary_card("Проверено", "0");
        let pass_label = summary_card("Соответствует", "0");
        let fail_label = summary_card("Требует внимания", "0");
        let na_label = summary_card("Не применимо", "0");
        summary_box.append(&checked_label.0);
        summary_box.append(&pass_label.0);
        summary_box.append(&fail_label.0);
        summary_box.append(&na_label.0);

        let progress = gtk::ProgressBar::new();
        progress.set_show_text(true);
        progress.set_visible(false);
        progress.set_text(Some("Ожидание"));

        let status_label = gtk::Label::new(Some("Готово к первичному сканированию."));
        status_label.set_xalign(0.0);
        status_label.add_css_class("status-caption");

        let results_list = gtk::ListBox::new();
        results_list.set_selection_mode(gtk::SelectionMode::None);
        let results_scroll = gtk::ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .child(&results_list)
            .build();

        dashboard_page.append(&summary_box);
        dashboard_page.append(&progress);
        dashboard_page.append(&status_label);
        dashboard_page.append(&section_title("Результаты сканирования"));
        dashboard_page.append(&results_scroll);

        let policies_list = gtk::ListBox::new();
        policies_list.set_selection_mode(gtk::SelectionMode::None);
        let policies_scroll = gtk::ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .child(&policies_list)
            .build();
        let policies_page = page_with_title(
            "Политики",
            "Нумерованный перечень политик и параметров РД ФСТЭК.",
        );
        policies_page.append(&policies_scroll);

        let reports_list = gtk::ListBox::new();
        reports_list.set_selection_mode(gtk::SelectionMode::None);
        let logs_list = gtk::ListBox::new();
        logs_list.set_selection_mode(gtk::SelectionMode::None);
        let reports_page = page_with_title(
            "Отчёты и журнал",
            "История экспортов и лог действий оператора.",
        );
        let report_split = gtk::Paned::new(gtk::Orientation::Horizontal);
        report_split.set_start_child(Some(&scrolled_list(&reports_list)));
        report_split.set_end_child(Some(&scrolled_list(&logs_list)));
        report_split.set_resize_start_child(true);
        report_split.set_position(540);
        reports_page.append(&report_split);

        let analytics_list = gtk::ListBox::new();
        analytics_list.set_selection_mode(gtk::SelectionMode::None);
        let analytics_page = page_with_title(
            "Аналитика",
            "Технические сведения о рабочей станции и сессии сканирования.",
        );
        analytics_page.append(&scrolled_list(&analytics_list));

        let system_list = gtk::ListBox::new();
        system_list.set_selection_mode(gtk::SelectionMode::None);
        let system_page = page_with_title(
            "Система",
            "Базовые сведения об узле и профиле защищённости.",
        );
        system_page.append(&scrolled_list(&system_list));

        stack.add_titled(&dashboard_page, Some("dashboard"), "Панель");
        stack.add_titled(&policies_page, Some("policies"), "Политики");
        stack.add_titled(&reports_page, Some("reports"), "Отчёты");
        stack.add_titled(&analytics_page, Some("analytics"), "Аналитика");
        stack.add_titled(&system_page, Some("system"), "Система");

        content.append(&sidebar);
        content.append(&stack);

        root.append(&header);
        root.append(&content);
        window.set_content(Some(&root));

        render_policies(&policies_list);
        render_results(&results_list, &[]);
        render_reports(&reports_list, &[]);
        render_logs(&logs_list, &[]);
        render_analytics(
            &analytics_list,
            &HostAnalytics::default(),
            &ScanSession::default(),
        );
        render_system(&system_list, &SystemInfo::default());

        connect_scan_action(
            &scan_button,
            state.clone(),
            progress.clone(),
            status_label.clone(),
            results_list.clone(),
            reports_list.clone(),
            logs_list.clone(),
            analytics_list.clone(),
            system_list.clone(),
            checked_label.1.clone(),
            pass_label.1.clone(),
            fail_label.1.clone(),
            na_label.1.clone(),
        );

        connect_apply_action(
            &apply_button,
            state.clone(),
            progress.clone(),
            status_label.clone(),
            results_list.clone(),
            reports_list.clone(),
            logs_list.clone(),
            analytics_list.clone(),
            system_list.clone(),
            checked_label.1.clone(),
            pass_label.1.clone(),
            fail_label.1.clone(),
            na_label.1.clone(),
        );

        connect_export_action(
            &export_html_button,
            state.clone(),
            status_label.clone(),
            reports_list.clone(),
            logs_list.clone(),
            ReportFormat::Html,
        );

        connect_export_action(
            &export_pdf_button,
            state.clone(),
            status_label.clone(),
            reports_list.clone(),
            logs_list.clone(),
            ReportFormat::Pdf,
        );

        start_scan(
            state,
            progress,
            status_label,
            results_list,
            reports_list,
            logs_list,
            analytics_list,
            system_list,
            checked_label.1,
            pass_label.1,
            fail_label.1,
            na_label.1,
        );

        Self { window }
    }

    pub fn present(&self) {
        self.window.present();
    }
}

#[allow(clippy::too_many_arguments)]
fn connect_scan_action(
    button: &gtk::Button,
    state: Rc<RefCell<UiState>>,
    progress: gtk::ProgressBar,
    status_label: gtk::Label,
    results_list: gtk::ListBox,
    reports_list: gtk::ListBox,
    logs_list: gtk::ListBox,
    analytics_list: gtk::ListBox,
    system_list: gtk::ListBox,
    checked_value: gtk::Label,
    pass_value: gtk::Label,
    fail_value: gtk::Label,
    na_value: gtk::Label,
) {
    button.connect_clicked(move |_| {
        start_scan(
            state.clone(),
            progress.clone(),
            status_label.clone(),
            results_list.clone(),
            reports_list.clone(),
            logs_list.clone(),
            analytics_list.clone(),
            system_list.clone(),
            checked_value.clone(),
            pass_value.clone(),
            fail_value.clone(),
            na_value.clone(),
        );
    });
}

#[allow(clippy::too_many_arguments)]
fn connect_apply_action(
    button: &gtk::Button,
    state: Rc<RefCell<UiState>>,
    progress: gtk::ProgressBar,
    status_label: gtk::Label,
    results_list: gtk::ListBox,
    reports_list: gtk::ListBox,
    logs_list: gtk::ListBox,
    analytics_list: gtk::ListBox,
    system_list: gtk::ListBox,
    checked_value: gtk::Label,
    pass_value: gtk::Label,
    fail_value: gtk::Label,
    na_value: gtk::Label,
) {
    button.connect_clicked(move |_| {
        let fail_ids = {
            let snapshot = state.borrow();
            get_fail_ids(&snapshot.results)
        };

        if fail_ids.is_empty() {
            set_status(&status_label, "Параметры со статусом FAIL отсутствуют.");
            return;
        }

        progress.set_visible(true);
        progress.set_text(Some("Применение настроек..."));
        progress.pulse();

        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let response = apply_settings(&fail_ids);
            let _ = sender.send(WorkerResponse::ApplyFinished(response));
        });

        let state = state.clone();
        let progress = progress.clone();
        let status_label = status_label.clone();
        let results_list = results_list.clone();
        let reports_list = reports_list.clone();
        let logs_list = logs_list.clone();
        let analytics_list = analytics_list.clone();
        let system_list = system_list.clone();
        let checked_value = checked_value.clone();
        let pass_value = pass_value.clone();
        let fail_value = fail_value.clone();
        let na_value = na_value.clone();

        glib::timeout_add_local(Duration::from_millis(90), move || {
            progress.pulse();
            match receiver.try_recv() {
                Ok(WorkerResponse::ApplyFinished(result)) => {
                    progress.set_visible(false);

                    match result {
                        Ok(apply_result) => {
                            let mut state_ref = state.borrow_mut();
                            let summary = if apply_result.failed.is_empty() {
                                format!(
                                    "Применение завершено. Успешно: {}.",
                                    apply_result.applied.len()
                                )
                            } else {
                                format!(
                                    "Применение завершено с ошибками. Успешно: {}, ошибок: {}.",
                                    apply_result.applied.len(),
                                    apply_result.failed.len()
                                )
                            };
                            push_log(&mut state_ref, &summary);
                            if apply_result.needs_reboot {
                                push_log(
                                    &mut state_ref,
                                    "Изменены параметры GRUB: требуется перезагрузка.",
                                );
                            }
                            set_status(&status_label, &summary);
                            render_reports(&reports_list, &state_ref.report_history);
                            render_logs(&logs_list, &state_ref.logs);
                            drop(state_ref);

                            start_scan(
                                state.clone(),
                                progress.clone(),
                                status_label.clone(),
                                results_list.clone(),
                                reports_list.clone(),
                                logs_list.clone(),
                                analytics_list.clone(),
                                system_list.clone(),
                                checked_value.clone(),
                                pass_value.clone(),
                                fail_value.clone(),
                                na_value.clone(),
                            );
                        }
                        Err(error) => {
                            let mut state_ref = state.borrow_mut();
                            push_log(&mut state_ref, &format!("Ошибка применения: {error}"));
                            render_logs(&logs_list, &state_ref.logs);
                            set_status(&status_label, &error);
                        }
                    }
                    ControlFlow::Break
                }
                Ok(_) => ControlFlow::Continue,
                Err(mpsc::TryRecvError::Empty) => ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    progress.set_visible(false);
                    set_status(&status_label, "Фоновая операция применения прервана.");
                    ControlFlow::Break
                }
            }
        });
    });
}

fn connect_export_action(
    button: &gtk::Button,
    state: Rc<RefCell<UiState>>,
    status_label: gtk::Label,
    reports_list: gtk::ListBox,
    logs_list: gtk::ListBox,
    format: ReportFormat,
) {
    button.connect_clicked(move |_| {
        let mut state_ref = state.borrow_mut();
        if state_ref.results.is_empty() {
            set_status(&status_label, "Сначала выполните сканирование.");
            return;
        }

        let output_dir = reports_dir();
        if let Err(error) = fs::create_dir_all(&output_dir) {
            set_status(
                &status_label,
                &format!("Не удалось создать каталог отчётов: {error}"),
            );
            return;
        }

        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let path = output_dir.join(format!(
            "alt-hardening-scanner-{timestamp}.{}",
            format.extension()
        ));

        let metadata = ReportMetadata {
            hostname: state_ref.session.hostname.clone(),
            scan_started_at: state_ref.session.scan_started_at.clone(),
            scan_finished_at: state_ref.session.scan_finished_at.clone(),
            username: state_ref.session.username.clone(),
            user_id: state_ref.session.user_id.clone(),
        };

        match generate_report(&state_ref.results, &path, &format, &metadata) {
            Ok(message) => {
                state_ref
                    .report_history
                    .insert(0, path.display().to_string());
                push_log(&mut state_ref, &message);
                render_reports(&reports_list, &state_ref.report_history);
                render_logs(&logs_list, &state_ref.logs);
                set_status(&status_label, &message);
            }
            Err(error) => {
                push_log(&mut state_ref, &error);
                render_logs(&logs_list, &state_ref.logs);
                set_status(&status_label, &error);
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn start_scan(
    state: Rc<RefCell<UiState>>,
    progress: gtk::ProgressBar,
    status_label: gtk::Label,
    results_list: gtk::ListBox,
    reports_list: gtk::ListBox,
    logs_list: gtk::ListBox,
    analytics_list: gtk::ListBox,
    system_list: gtk::ListBox,
    checked_value: gtk::Label,
    pass_value: gtk::Label,
    fail_value: gtk::Label,
    na_value: gtk::Label,
) {
    let started_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    {
        let mut state_ref = state.borrow_mut();
        state_ref.session.scan_started_at = started_at.clone();
        push_log(
            &mut state_ref,
            &format!("Стартовало сканирование в {started_at}."),
        );
        render_logs(&logs_list, &state_ref.logs);
        render_reports(&reports_list, &state_ref.report_history);
    }

    progress.set_visible(true);
    progress.set_text(Some("Сканирование..."));
    set_status(
        &status_label,
        "Выполняется сканирование параметров безопасности.",
    );

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let system_info = get_system_info();
        let analytics = get_host_analytics();
        let results = scan_all();
        let finished_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = sender.send(WorkerResponse::ScanFinished {
            results,
            system_info,
            analytics,
            finished_at,
        });
    });

    glib::timeout_add_local(Duration::from_millis(90), move || {
        progress.pulse();
        match receiver.try_recv() {
            Ok(WorkerResponse::ScanFinished {
                results,
                system_info,
                analytics,
                finished_at,
            }) => {
                progress.set_visible(false);

                let mut state_ref = state.borrow_mut();
                state_ref.results = results;
                state_ref.system_info = system_info.clone();
                state_ref.analytics = analytics.clone();
                state_ref.session.scan_finished_at = finished_at.clone();
                state_ref.session.hostname = system_info.hostname.clone();
                state_ref.session.username = system_info.username.clone();
                state_ref.session.user_id = system_info.user_id.clone();

                let pass = state_ref
                    .results
                    .iter()
                    .filter(|item| item.status == Status::Pass)
                    .count();
                let fail = state_ref
                    .results
                    .iter()
                    .filter(|item| item.status == Status::Fail)
                    .count();
                let na = state_ref
                    .results
                    .iter()
                    .filter(|item| item.status == Status::Na)
                    .count();
                let total = state_ref.results.len();

                checked_value.set_text(&total.to_string());
                pass_value.set_text(&pass.to_string());
                fail_value.set_text(&fail.to_string());
                na_value.set_text(&na.to_string());

                render_results(&results_list, &state_ref.results);
                render_analytics(&analytics_list, &state_ref.analytics, &state_ref.session);
                render_system(&system_list, &state_ref.system_info);

                let message = format!(
                    "Сканирование завершено: проверено {total}, соответствует {pass}, требует внимания {fail}, не применимо {na}."
                );
                push_log(&mut state_ref, &message);
                render_logs(&logs_list, &state_ref.logs);
                set_status(&status_label, &message);
                ControlFlow::Break
            }
            Ok(WorkerResponse::ScanFailed(error)) => {
                progress.set_visible(false);
                set_status(&status_label, &error);
                let mut state_ref = state.borrow_mut();
                push_log(&mut state_ref, &error);
                render_logs(&logs_list, &state_ref.logs);
                ControlFlow::Break
            }
            Ok(_) => ControlFlow::Continue,
            Err(mpsc::TryRecvError::Empty) => ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                progress.set_visible(false);
                set_status(&status_label, "Фоновое сканирование прервано.");
                ControlFlow::Break
            }
        }
    });
}

fn render_policies(list: &gtk::ListBox) {
    clear_listbox(list);
    for check in all_checks() {
        let row = gtk::ListBoxRow::new();
        let card = gtk::Box::new(gtk::Orientation::Vertical, 6);
        card.set_margin_top(10);
        card.set_margin_bottom(10);
        card.set_margin_start(12);
        card.set_margin_end(12);

        let title = gtk::Label::new(Some(&format!("{}. {}", check.id, check.param)));
        title.set_xalign(0.0);
        title.add_css_class("page-title");

        let description = gtk::Label::new(Some(&check.description));
        description.set_wrap(true);
        description.set_xalign(0.0);

        let meta = gtk::Label::new(Some(&format!(
            "Интерфейс: {} • Цель: {} • По умолчанию: {}",
            check.interface.as_str(),
            check.target_value,
            check.default_value
        )));
        meta.set_xalign(0.0);
        meta.add_css_class("dim-label");

        card.append(&title);
        card.append(&description);
        card.append(&meta);
        row.set_child(Some(&card));
        list.append(&row);
    }
}

fn render_results(list: &gtk::ListBox, results: &[ScanResult]) {
    clear_listbox(list);
    if results.is_empty() {
        let row = gtk::ListBoxRow::new();
        row.set_child(Some(&gtk::Label::new(Some(
            "Результатов пока нет. Запустите сканирование.",
        ))));
        list.append(&row);
        return;
    }

    for result in results {
        list.append(&build_scan_row(result));
    }
}

fn render_reports(list: &gtk::ListBox, history: &[String]) {
    clear_listbox(list);
    if history.is_empty() {
        list.append(&simple_row("Экспортов ещё не было."));
        return;
    }

    for item in history {
        list.append(&simple_row(item));
    }
}

fn render_logs(list: &gtk::ListBox, logs: &[String]) {
    clear_listbox(list);
    if logs.is_empty() {
        list.append(&simple_row("Логи пока отсутствуют."));
        return;
    }

    for item in logs {
        list.append(&simple_row(item));
    }
}

fn render_analytics(list: &gtk::ListBox, analytics: &HostAnalytics, session: &ScanSession) {
    clear_listbox(list);
    let items = [
        ("Аптайм", analytics.uptime.clone()),
        ("Последнее обновление", analytics.last_update.clone()),
        ("IP-адрес", analytics.ip_address.clone()),
        ("Сетевой сегмент", analytics.network_name.clone()),
        ("Репозитории", analytics.repositories.join("\n")),
        (
            "Сессия сканирования",
            format!(
                "Начало: {}\nОкончание: {}\nПользователь: {}\nID: {}\nХост: {}",
                session.scan_started_at,
                session.scan_finished_at,
                session.username,
                session.user_id,
                session.hostname
            ),
        ),
    ];

    for (label, value) in items {
        list.append(&kv_row(label, &value));
    }
}

fn render_system(list: &gtk::ListBox, system: &SystemInfo) {
    clear_listbox(list);
    let items = [
        ("Имя хоста", system.hostname.clone()),
        ("ОС", system.os_name.clone()),
        ("Версия ядра", system.kernel.clone()),
        ("Пользователь", system.username.clone()),
        ("ID пользователя", system.user_id.clone()),
        (
            "Профиль системы",
            "Рабочая станция общего назначения с усиленной политикой hardening для ALT Linux."
                .to_string(),
        ),
    ];

    for (label, value) in items {
        list.append(&kv_row(label, &value));
    }
}

fn summary_card(title: &str, value: &str) -> (gtk::Frame, gtk::Label) {
    let frame = gtk::Frame::new(None);
    frame.add_css_class("summary-card");

    let box_ = gtk::Box::new(gtk::Orientation::Vertical, 6);
    box_.set_margin_top(12);
    box_.set_margin_bottom(12);
    box_.set_margin_start(12);
    box_.set_margin_end(12);

    let title_label = gtk::Label::new(Some(title));
    title_label.set_xalign(0.0);
    title_label.add_css_class("dim-label");

    let value_label = gtk::Label::new(Some(value));
    value_label.set_xalign(0.0);
    value_label.add_css_class("summary-value");

    box_.append(&title_label);
    box_.append(&value_label);
    frame.set_child(Some(&box_));
    (frame, value_label)
}

fn page_with_title(title: &str, subtitle: &str) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.append(&section_title(title));
    let subtitle_label = gtk::Label::new(Some(subtitle));
    subtitle_label.set_xalign(0.0);
    subtitle_label.add_css_class("dim-label");
    page.append(&subtitle_label);
    page
}

fn section_title(title: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    label.add_css_class("section-title");
    label
}

fn scrolled_list(list: &gtk::ListBox) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder()
        .hexpand(true)
        .vexpand(true)
        .child(list)
        .build()
}

fn simple_row(text: &str) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    let label = gtk::Label::new(Some(text));
    label.set_margin_top(10);
    label.set_margin_bottom(10);
    label.set_margin_start(12);
    label.set_margin_end(12);
    label.set_wrap(true);
    label.set_xalign(0.0);
    row.set_child(Some(&label));
    row
}

fn kv_row(label: &str, value: &str) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    let box_ = gtk::Box::new(gtk::Orientation::Vertical, 6);
    box_.set_margin_top(10);
    box_.set_margin_bottom(10);
    box_.set_margin_start(12);
    box_.set_margin_end(12);

    let key = gtk::Label::new(Some(label));
    key.set_xalign(0.0);
    key.add_css_class("page-title");

    let val = gtk::Label::new(Some(value));
    val.set_xalign(0.0);
    val.set_wrap(true);

    box_.append(&key);
    box_.append(&val);
    row.set_child(Some(&box_));
    row
}

fn clear_listbox(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

fn set_status(label: &gtk::Label, message: &str) {
    label.set_text(message);
}

fn push_log(state: &mut UiState, message: &str) {
    let line = format!("{} — {}", Local::now().format("%Y-%m-%d %H:%M:%S"), message);
    state.logs.insert(0, line.clone());
    append_log_file(&line);
}

fn append_log_file(line: &str) {
    let path = crate::config::log_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{line}");
    }
}
