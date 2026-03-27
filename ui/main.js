(function () {
  "use strict";

  const POLICY_DETAILS = [
    { id: 1, title: "kernel.dmesg_restrict", summary: "Ограничивает просмотр сообщений ядра для непривилегированных пользователей.", section: "5.3.1 dmesg", interface: "Sysctl" },
    { id: 2, title: "kernel.kptr_restrict", summary: "Скрывает адреса указателей ядра в диагностических интерфейсах.", section: "5.5.5 Защита адресов указателей", interface: "Sysctl" },
    { id: 3, title: "init_on_alloc=1", summary: "Инициализирует выделяемую память и снижает риск утечки данных между контекстами.", section: "5.5.1 Очистка памяти", interface: "Grub" },
    { id: 4, title: "slab_nomerge", summary: "Запрещает объединение slab-кэшей и усложняет эксплуатацию уязвимостей памяти.", section: "5.5.1 Очистка памяти", interface: "Grub" },
    { id: 5, title: "iommu=force iommu.strict=1 iommu.passthrough=0", summary: "Включает строгий IOMMU для противодействия DMA-атакам.", section: "5.5.2 DMA", interface: "Grub" },
    { id: 6, title: "randomize_kstack_offset=1", summary: "Добавляет рандомизацию смещения стека ядра.", section: "5.5 Защита памяти", interface: "Grub" },
    { id: 7, title: "mitigations=auto,nosmt", summary: "Активирует аппаратные mitigations и управляет SMT.", section: "5.5.6 Meltdown и Spectre", interface: "Grub" },
    { id: 8, title: "net.core.bpf_jit_harden", summary: "Усиливает защиту BPF JIT-компилятора.", section: "5.2 Защита от произвольного кода в ядре", interface: "Sysctl" },
    { id: 9, title: "vsyscall=none", summary: "Отключает устаревший механизм vsyscall.", section: "5.5.3 Устаревшие syscall", interface: "Grub" },
    { id: 10, title: "kernel.perf_event_paranoid", summary: "Ограничивает профилирование и отладочную телеметрию.", section: "8.2 Ограничение отладки", interface: "Sysctl" },
    { id: 11, title: "debugfs=no-mount", summary: "Не допускает монтирование debugfs.", section: "8.2 debugfs", interface: "Grub" },
    { id: 12, title: "kernel.kexec_load_disabled", summary: "Запрещает загрузку ядра через kexec.", section: "5.4 Lockdown", interface: "Sysctl" },
    { id: 13, title: "user.max_user_namespaces", summary: "Снижает поверхность атак через user namespaces.", section: "5.5.4 Изоляция процессов", interface: "Sysctl" },
    { id: 14, title: "kernel.unprivileged_bpf_disabled", summary: "Запрещает непривилегированный BPF.", section: "5.2 Защита от произвольного кода в ядре", interface: "Sysctl" },
    { id: 15, title: "vm.unprivileged_userfaultfd", summary: "Ограничивает userfaultfd для пользовательских процессов.", section: "5.5 Защита памяти", interface: "Sysctl" },
    { id: 16, title: "dev.tty.ldisc_autoload", summary: "Отключает автоматическую загрузку дисциплин линии TTY.", section: "5.3.3 Дисциплина линии", interface: "Sysctl" },
    { id: 17, title: "tsx=off", summary: "Отключает Intel TSX как меру против TAA и смежных атак.", section: "5.5.7 Intel TSX", interface: "Grub" },
    { id: 18, title: "vm.mmap_min_addr", summary: "Задаёт безопасный минимум для mmap.", section: "5.5 Защита памяти", interface: "Sysctl" },
    { id: 19, title: "kernel.randomize_va_space", summary: "Поддерживает ASLR для пользовательского пространства.", section: "5.5 Защита памяти", interface: "Sysctl" },
    { id: 20, title: "kernel.yama.ptrace_scope", summary: "Ограничивает ptrace и наблюдение за процессами.", section: "8.2 Ограничение отладки", interface: "Sysctl" },
    { id: 21, title: "fs.protected_symlinks", summary: "Усиливает поведение символьных ссылок в общих каталогах.", section: "5.1 Сегментирование дискового пространства", interface: "Sysctl" },
    { id: 22, title: "fs.protected_hardlinks", summary: "Ограничивает жёсткие ссылки на чужие файлы.", section: "5.1 Сегментирование дискового пространства", interface: "Sysctl" },
    { id: 23, title: "fs.protected_fifos", summary: "Защищает именованные каналы в чувствительных каталогах.", section: "5.1 Сегментирование дискового пространства", interface: "Sysctl" },
    { id: 24, title: "fs.protected_regular", summary: "Добавляет ограничения для обычных файлов в sticky-каталогах.", section: "5.1 Сегментирование дискового пространства", interface: "Sysctl" },
    { id: 25, title: "fs.suid_dumpable", summary: "Запрещает дампы памяти для SUID/SGID-процессов.", section: "8.2 Ограничение дампов", interface: "Sysctl" },
  ];

  const state = {
    results: [],
    systemInfo: null,
    analytics: null,
    mockMode: false,
    busy: false,
    currentView: "dashboard",
    scanSession: {
      hostname: "—",
      username: "unknown",
      userId: "unknown",
      startedAt: null,
      finishedAt: null,
    },
    reportHistory: [
      { type: "HTML", name: "alt-hardening-report-2026-03-27.html", createdAt: "2026-03-27 18:12:00", status: "Сохранён", size: "148 KB", hostname: "alt-workstation-demo", username: "demo-user", userId: "1000", scanStartedAt: "2026-03-27 18:10:02", scanFinishedAt: "2026-03-27 18:11:31" },
      { type: "PDF", name: "alt-hardening-report-2026-03-27.pdf", createdAt: "2026-03-27 18:18:00", status: "Сохранён", size: "304 KB", hostname: "alt-workstation-demo", username: "demo-user", userId: "1000", scanStartedAt: "2026-03-27 18:10:02", scanFinishedAt: "2026-03-27 18:11:31" },
    ],
    logs: [
      { timestamp: "2026-03-27 18:02:11", message: "Запущено демонстрационное сканирование профиля безопасности." },
      { timestamp: "2026-03-27 18:04:53", message: "Построен HTML-отчёт и зарегистрирован в журнале." },
      { timestamp: "2026-03-27 18:18:40", message: "Подготовлен PDF-отчёт и обновлён список выгрузок." },
    ],
  };

  const elements = {
    hostname: document.getElementById("hostname"),
    osName: document.getElementById("os-name"),
    kernel: document.getElementById("kernel"),
    progressSection: document.getElementById("progress-section"),
    progressBar: document.getElementById("progress-bar"),
    progressLabel: document.getElementById("progress-label"),
    notification: document.getElementById("notification"),
    notificationText: document.getElementById("notification-text"),
    passCount: document.getElementById("pass-count"),
    failCount: document.getElementById("fail-count"),
    naCount: document.getElementById("na-count"),
    totalCount: document.getElementById("total-count"),
    openFindings: document.getElementById("open-findings"),
    completedControls: document.getElementById("completed-controls"),
    reportsReady: document.getElementById("reports-ready"),
    auditScore: document.getElementById("audit-score"),
    resultsBody: document.getElementById("results-body"),
    rebootModal: document.getElementById("reboot-modal"),
    scanButton: document.getElementById("btn-scan"),
    fixButton: document.getElementById("btn-fix"),
    htmlButton: document.getElementById("btn-html"),
    pdfButton: document.getElementById("btn-pdf"),
    policiesList: document.getElementById("policies-list"),
    profileGrid: document.getElementById("profile-grid"),
    reportsList: document.getElementById("reports-list"),
    logsList: document.getElementById("logs-list"),
    analyticsGrid: document.getElementById("analytics-grid"),
    systemGrid: document.getElementById("system-grid"),
    downloadAllButton: document.getElementById("btn-download-all"),
    navButtons: Array.from(document.querySelectorAll(".nav-item[data-view]")),
    views: Array.from(document.querySelectorAll(".page-view")),
    searchPlaceholder: document.getElementById("search-placeholder"),
    topbarSubtitle: document.getElementById("topbar-subtitle"),
  };

  function getTauriCore() {
    return window.__TAURI__?.core ?? null;
  }

  function getTauriDialog() {
    return window.__TAURI__?.dialog ?? null;
  }

  function hasTauri() {
    return Boolean(getTauriCore()?.invoke);
  }

  async function invoke(command, args = {}) {
    const core = getTauriCore();
    if (!core?.invoke) {
      throw new Error("Tauri API недоступен.");
    }
    return core.invoke(command, args);
  }

  async function pickSavePath(defaultPath, filters) {
    const dialog = getTauriDialog();
    if (!dialog?.save) return defaultPath;
    return dialog.save({ defaultPath, filters });
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function formatDateTime(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    const yyyy = date.getFullYear();
    const mm = String(date.getMonth() + 1).padStart(2, "0");
    const dd = String(date.getDate()).padStart(2, "0");
    const hh = String(date.getHours()).padStart(2, "0");
    const mi = String(date.getMinutes()).padStart(2, "0");
    const ss = String(date.getSeconds()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
  }

  function wait(ms) {
    return new Promise((resolve) => {
      window.setTimeout(resolve, ms);
    });
  }

  function createMockSystemInfo() {
    return {
      hostname: "alt-workstation-demo",
      osName: "ALT Рабочая Станция 11 (демо-режим)",
      kernel: "6.12.0-mock",
      username: "demo-user",
      userId: "1000",
    };
  }

  function createMockAnalytics() {
    return {
      uptime: "12 дней 4 часа",
      lastUpdate: "2026-03-24 21:15:00",
      repositories: [
        "rpm http://mirror.altlinux.org p11/branch/x86_64 classic",
        "rpm http://repo.basealt.ru alt-workstation/11 x86_64 main",
      ],
      ipAddress: "192.168.1.34",
      networkName: "corp-lan-01",
    };
  }

  // Полный набор из 25 проверок — точно отражает данные checks.rs.
  // Значения cur/status соответствуют типичной ALT РС 11 «из коробки».
  function createMockResults() {
    return [
      // ── sysctl ──────────────────────────────────────────────────────────────
      { check: { id: 1,  interface: "Sysctl", param: "kernel.dmesg_restrict",           target_value: "1",       default_value: "1",       description: "Ограничивает доступ к dmesg для непривилегированных пользователей",            section: "РД ФСТЭК — п.4.1 Управление доступом к ядру"     }, current_value: "1",       status: "Pass" },
      { check: { id: 2,  interface: "Sysctl", param: "kernel.kptr_restrict",             target_value: "2",       default_value: "0",       description: "Скрывает адреса ядра из /proc/kallsyms и других интерфейсов",                  section: "РД ФСТЭК — п.4.1 Управление доступом к ядру"     }, current_value: "0",       status: "Fail" },
      { check: { id: 8,  interface: "Sysctl", param: "net.core.bpf_jit_harden",         target_value: "2",       default_value: "0",       description: "Усиливает защиту JIT-компилятора BPF против атак типа blinding",                section: "РД ФСТЭК — п.4.3 Сетевая безопасность"           }, current_value: "0",       status: "Fail" },
      { check: { id: 10, interface: "Sysctl", param: "kernel.perf_event_paranoid",       target_value: "3",       default_value: "4",       description: "Ограничивает доступ к событиям производительности ядра",                      section: "РД ФСТЭК — п.4.1 Управление доступом к ядру"     }, current_value: "4",       status: "Fail" },
      { check: { id: 12, interface: "Sysctl", param: "kernel.kexec_load_disabled",       target_value: "1",       default_value: "0",       description: "Запрещает загрузку нового ядра через kexec (защита от подмены ядра)",          section: "РД ФСТЭК — п.4.2 Целостность ядра"               }, current_value: "0",       status: "Fail" },
      { check: { id: 13, interface: "Sysctl", param: "user.max_user_namespaces",         target_value: "0",       default_value: "5098941", description: "Отключает пользовательские пространства имён (вектор атак контейнерного побега)", section: "РД ФСТЭК — п.4.4 Изоляция процессов"             }, current_value: "5098941", status: "Fail" },
      { check: { id: 14, interface: "Sysctl", param: "kernel.unprivileged_bpf_disabled", target_value: "1",       default_value: "2",       description: "Запрещает непривилегированным пользователям использовать BPF",                section: "РД ФСТЭК — п.4.1 Управление доступом к ядру"     }, current_value: "2",       status: "Fail" },
      { check: { id: 15, interface: "Sysctl", param: "vm.unprivileged_userfaultfd",      target_value: "0",       default_value: "1",       description: "Запрещает unprivileged userfaultfd — источник UAF-уязвимостей",                section: "РД ФСТЭК — п.4.1 Управление доступом к ядру"     }, current_value: "1",       status: "Fail" },
      { check: { id: 16, interface: "Sysctl", param: "dev.tty.ldisc_autoload",           target_value: "0",       default_value: "1",       description: "Запрещает автозагрузку дисциплин линии TTY (вектор LPE)",                     section: "РД ФСТЭК — п.4.2 Целостность ядра"               }, current_value: "1",       status: "Fail" },
      { check: { id: 18, interface: "Sysctl", param: "vm.mmap_min_addr",                 target_value: "4096",    default_value: "65536",   description: "Минимальный адрес для mmap — защита от NULL-pointer dereference",              section: "РД ФСТЭК — п.4.5 Защита памяти"                  }, current_value: "4096",    status: "Pass" },
      { check: { id: 19, interface: "Sysctl", param: "kernel.randomize_va_space",        target_value: "2",       default_value: "2",       description: "Полная рандомизация адресного пространства (ASLR уровень 2)",                  section: "РД ФСТЭК — п.4.5 Защита памяти"                  }, current_value: "2",       status: "Pass" },
      { check: { id: 20, interface: "Sysctl", param: "kernel.yama.ptrace_scope",         target_value: "3",       default_value: "1",       description: "Полный запрет ptrace — исключает инспекцию памяти процессов",                  section: "РД ФСТЭК — п.4.4 Изоляция процессов"             }, current_value: "1",       status: "Fail" },
      { check: { id: 21, interface: "Sysctl", param: "fs.protected_symlinks",            target_value: "1",       default_value: "1",       description: "Защита от атак через symlink в sticky-директориях",                           section: "РД ФСТЭК — п.4.6 Защита файловой системы"       }, current_value: "1",       status: "Pass" },
      { check: { id: 22, interface: "Sysctl", param: "fs.protected_hardlinks",           target_value: "1",       default_value: "1",       description: "Защита от атак через hardlink для чужих файлов",                              section: "РД ФСТЭК — п.4.6 Защита файловой системы"       }, current_value: "1",       status: "Pass" },
      { check: { id: 23, interface: "Sysctl", param: "fs.protected_fifos",               target_value: "2",       default_value: "1",       description: "Усиленная защита FIFO-файлов в sticky-директориях",                           section: "РД ФСТЭК — п.4.6 Защита файловой системы"       }, current_value: "1",       status: "Fail" },
      { check: { id: 24, interface: "Sysctl", param: "fs.protected_regular",             target_value: "2",       default_value: "1",       description: "Усиленная защита обычных файлов в sticky-директориях",                        section: "РД ФСТЭК — п.4.6 Защита файловой системы"       }, current_value: "1",       status: "Fail" },
      { check: { id: 25, interface: "Sysctl", param: "fs.suid_dumpable",                 target_value: "0",       default_value: "0",       description: "Запрещает создание core-дампов для SUID/SGID процессов",                      section: "РД ФСТЭК — п.4.6 Защита файловой системы"       }, current_value: "0",       status: "Pass" },
      // ── grub ────────────────────────────────────────────────────────────────
      { check: { id: 3,  interface: "Grub",   param: "init_on_alloc=1",                                    target_value: "present",  default_value: "absent", description: "Инициализация памяти нулями при выделении — предотвращает утечку данных",     section: "РД ФСТЭК — п.4.5 Защита памяти"       }, current_value: "—", status: "Fail" },
      { check: { id: 4,  interface: "Grub",   param: "slab_nomerge",                                       target_value: "present",  default_value: "absent", description: "Отключает слияние slab-кэшей — затрудняет heap-спрей атаки",                  section: "РД ФСТЭК — п.4.5 Защита памяти"       }, current_value: "—", status: "Fail" },
      { check: { id: 5,  interface: "Grub",   param: "iommu=force iommu.strict=1 iommu.passthrough=0",     target_value: "present",  default_value: "absent", description: "IOMMU принудительный режим + strict DMA isolation (защита от DMA-атак)",    section: "РД ФСТЭК — п.4.7 Аппаратная защита"  }, current_value: "—", status: "Fail" },
      { check: { id: 6,  interface: "Grub",   param: "randomize_kstack_offset=1",                          target_value: "present",  default_value: "absent", description: "Рандомизация смещения стека ядра — затрудняет ROP-цепочки",                  section: "РД ФСТЭК — п.4.5 Защита памяти"       }, current_value: "—", status: "Fail" },
      { check: { id: 7,  interface: "Grub",   param: "mitigations=auto,nosmt",                             target_value: "present",  default_value: "absent", description: "Все CPU-митигации + отключение SMT (защита от Spectre/Meltdown/MDS)",       section: "РД ФСТЭК — п.4.7 Аппаратная защита"  }, current_value: "—", status: "Fail" },
      { check: { id: 9,  interface: "Grub",   param: "vsyscall=none",                                      target_value: "present",  default_value: "absent", description: "Отключает legacy vsyscall ABI — устраняет фиксированное ядерное отображение", section: "РД ФСТЭК — п.4.5 Защита памяти"       }, current_value: "—", status: "Fail" },
      { check: { id: 11, interface: "Grub",   param: "debugfs=no-mount",                                   target_value: "present",  default_value: "absent", description: "Запрещает монтирование debugfs — скрывает внутренние данные ядра",          section: "РД ФСТЭК — п.4.1 Управление доступом к ядру" }, current_value: "—", status: "Fail" },
      { check: { id: 17, interface: "Grub",   param: "tsx=off",                                            target_value: "present",  default_value: "absent", description: "Отключает Intel TSX — устраняет уязвимости TAA/TSX Async Abort",            section: "РД ФСТЭК — п.4.7 Аппаратная защита"  }, current_value: "—", status: "Na"   },
    ];
  }

  function syncScanSessionFromSystemInfo(info) {
    if (!info) return;
    state.scanSession.hostname = info.hostname || state.scanSession.hostname;
    state.scanSession.username = info.username || state.scanSession.username;
    state.scanSession.userId = info.userId || info.user_id || state.scanSession.userId;
  }

  function getPassCount() {
    return state.results.filter((item) => item.status === "Pass").length;
  }

  function getFailCount() {
    return state.results.filter((item) => item.status === "Fail").length;
  }

  function getNaCount() {
    return state.results.filter((item) => item.status === "Na").length;
  }

  function getReportMetadata() {
    return {
      hostname: state.scanSession.hostname || state.systemInfo?.hostname || "—",
      scan_started_at: state.scanSession.startedAt || "—",
      scan_finished_at: state.scanSession.finishedAt || "—",
      username: state.scanSession.username || state.systemInfo?.username || "unknown",
      user_id: state.scanSession.userId || state.systemInfo?.userId || state.systemInfo?.user_id || "unknown",
    };
  }

  function addLog(message) {
    state.logs.unshift({ timestamp: formatDateTime(new Date()), message });
    renderReportsPage();
  }

  function showNotification(message, kind = "info") {
    elements.notification.style.display = "flex";
    elements.notification.classList.remove("notif-info", "notif-success", "notif-error");
    elements.notification.classList.add(`notif-${kind}`);
    elements.notificationText.textContent = message;
  }

  function hideNotification() {
    elements.notification.style.display = "none";
    elements.notification.classList.remove("notif-info", "notif-success", "notif-error");
    elements.notificationText.textContent = "";
  }

  function showRebootModal() {
    elements.rebootModal.style.display = "flex";
  }

  function hideRebootModal() {
    elements.rebootModal.style.display = "none";
  }

  function setBusy(isBusy, label) {
    state.busy = isBusy;
    elements.progressSection.style.display = isBusy ? "flex" : "none";
    elements.progressLabel.textContent = label;
    elements.progressBar.style.width = isBusy ? "12%" : "100%";

    [elements.scanButton, elements.fixButton, elements.htmlButton, elements.pdfButton].forEach((button) => {
      if (!button) return;
      button.disabled = isBusy || (!state.results.length && button !== elements.scanButton);
    });

    if (elements.fixButton) {
      elements.fixButton.disabled = isBusy || getFailCount() === 0;
    }
  }

  function renderResults() {
    const passCount = getPassCount();
    const failCount = getFailCount();
    const naCount = getNaCount();
    const total = state.results.length;
    const auditScore = total ? Math.round((passCount / total) * 100) : 0;

    elements.passCount.textContent = String(passCount);
    elements.failCount.textContent = String(failCount);
    elements.naCount.textContent = String(naCount);
    elements.totalCount.textContent = String(total);
    elements.openFindings.textContent = String(failCount);
    elements.completedControls.textContent = String(passCount);
    elements.reportsReady.textContent = String(state.reportHistory.length);
    elements.auditScore.textContent = `${auditScore}%`;

    if (!total) {
      elements.resultsBody.innerHTML = `<tr class="empty-row"><td colspan="8">Нажмите «Запустить сканирование», чтобы построить панель состояния.</td></tr>`;
      return;
    }

    elements.resultsBody.innerHTML = state.results
      .slice()
      .sort((left, right) => left.check.id - right.check.id)
      .map((item) => {
        const rowClass = item.status === "Pass" ? "row-pass" : item.status === "Fail" ? "row-fail" : "row-na";
        const badgeClass = item.status === "Pass" ? "badge-pass" : item.status === "Fail" ? "badge-fail" : "badge-na";
        const statusText = item.status === "Pass" ? "Соответствует" : item.status === "Fail" ? "Требует внимания" : "Не применимо";
        const ifaceClass = item.check.interface === "Grub" ? "iface-badge grub-badge" : "iface-badge";

        return `
          <tr class="${rowClass}">
            <td>${item.check.id}</td>
            <td><span class="${ifaceClass}">${escapeHtml(item.check.interface)}</span></td>
            <td><code>${escapeHtml(item.check.param)}</code></td>
            <td>${escapeHtml(item.current_value)}</td>
            <td>${escapeHtml(item.check.target_value)}</td>
            <td><span class="badge ${badgeClass}">${escapeHtml(statusText)}</span></td>
            <td>${escapeHtml(item.check.description)}</td>
            <td>${escapeHtml(item.check.section)}</td>
          </tr>
        `;
      })
      .join("");
  }

  // Карта id → результат скана для быстрого доступа
  function buildResultMap() {
    const map = {};
    state.results.forEach((item) => { map[item.check.id] = item; });
    return map;
  }

  function renderPoliciesPage() {
    const resultMap = buildResultMap();

    elements.policiesList.innerHTML = POLICY_DETAILS
      .slice()
      .sort((a, b) => a.id - b.id)
      .map((policy) => {
        const result = resultMap[policy.id];

        // Статус-бейдж из результатов скана (если сканирование уже выполнялось)
        let statusBadge = "";
        let statusClass = "";
        if (result) {
          if (result.status === "Pass") {
            statusBadge = `<span class="badge badge-pass" style="float:right">Соответствует</span>`;
            statusClass = " policy-status-pass";
          } else if (result.status === "Fail") {
            statusBadge = `<span class="badge badge-fail" style="float:right">Требует внимания</span>`;
            statusClass = " policy-status-fail";
          } else {
            statusBadge = `<span class="badge badge-na" style="float:right">Н/Д</span>`;
            statusClass = "";
          }
        }

        // Текущее значение (если сканирование выполнялось)
        const currentRow = result
          ? `<p style="margin-top:6px;font-size:0.82rem">
               Текущее: <code>${escapeHtml(result.current_value)}</code>
               &nbsp;→&nbsp;
               Цель: <code>${escapeHtml(result.check.target_value)}</code>
             </p>`
          : "";

        return `
          <article class="policy-page-item policy-item-dark${statusClass}" style="position:relative">
            ${statusBadge}
            <strong>${policy.id}. ${escapeHtml(policy.title)}</strong>
            <p>${escapeHtml(policy.summary)}</p>
            <p style="font-size:0.82rem;opacity:.75">${escapeHtml(policy.interface)} · ${escapeHtml(policy.section)}</p>
            ${currentRow}
          </article>
        `;
      })
      .join("");
  }

  function renderProfilePage() {
    const passCount = getPassCount();
    const failCount = getFailCount();
    const naCount = getNaCount();
    const cards = [
      { title: "Профиль рабочей станции", body: "Узел рассматривается как пользовательская рабочая станция с акцентом на ограничение локальной эскалации привилегий, защиту памяти и сокращение диагностических интерфейсов." },
      { title: "Профиль идентификации", body: "Документ рекомендует усиливать парольные политики, рассматривать OTP и MFA, а также использовать предупреждающие баннеры при входе." },
      { title: "Профиль целостности", body: "Критичны контроль целостности ПО, дисциплина обновлений и запрет загрузки неподтверждённого кода или альтернативного ядра." },
      { title: "Профиль ядра и памяти", body: "Приоритет делается на защиту памяти, ограничение BPF/eBPF, скрытие указателей ядра и применение mitigations против аппаратных атак." },
      { title: "Текущее состояние профиля", body: `Подтверждено ${passCount} параметров, ${failCount} требуют внимания, ${naCount} недоступны или не применимы.` },
    ];

    elements.profileGrid.innerHTML = cards.map((card) => `
      <article class="profile-card">
        <strong>${escapeHtml(card.title)}</strong>
        <p>${escapeHtml(card.body)}</p>
      </article>
    `).join("");
  }

  function renderReportsPage() {
    elements.reportsList.innerHTML = state.reportHistory.length
      ? state.reportHistory.map((report) => `
        <article class="report-card">
          <strong>${escapeHtml(report.name)}</strong>
          <p>Тип: ${escapeHtml(report.type)}</p>
          <p>Дата: ${escapeHtml(report.createdAt)}</p>
          <p>Хост: ${escapeHtml(report.hostname || "—")}</p>
          <p>Оператор: ${escapeHtml(report.username || "unknown")} (ID: ${escapeHtml(report.userId || "unknown")})</p>
          <p>Сканирование: ${escapeHtml(report.scanStartedAt || "—")} → ${escapeHtml(report.scanFinishedAt || "—")}</p>
          <p>Размер: ${escapeHtml(report.size)}</p>
          <p>Статус: ${escapeHtml(report.status)}</p>
        </article>
      `).join("")
      : `<article class="report-card"><p>Отчётов пока нет.</p></article>`;

    elements.logsList.innerHTML = state.logs.length
      ? state.logs.map((log) => `
        <article class="log-card">
          <strong>${escapeHtml(log.timestamp)}</strong>
          <p>${escapeHtml(log.message)}</p>
        </article>
      `).join("")
      : `<article class="log-card"><p>Логов пока нет.</p></article>`;
  }

  function renderAnalyticsPage() {
    const analytics = state.analytics || createMockAnalytics();
    const session = getReportMetadata();
    const cards = [
      { title: "Аптайм", body: analytics.uptime },
      { title: "Последнее обновление", body: analytics.lastUpdate },
      { title: "IP-адрес", body: analytics.ipAddress },
      { title: "Сетевой сегмент", body: analytics.networkName },
      { title: "Подключённые репозитории", body: analytics.repositories.join("\n") },
      {
        title: "Аналитика по сканированию",
        body: [
          `Начало: ${session.scan_started_at}`,
          `Окончание: ${session.scan_finished_at}`,
          `Пользователь: ${session.username}`,
          `ID пользователя: ${session.user_id}`,
          `Имя хоста: ${session.hostname}`,
        ].join("\n"),
      },
    ];

    elements.analyticsGrid.innerHTML = cards.map((card) => `
      <article class="analytics-card-mini">
        <strong>${escapeHtml(card.title)}</strong>
        <p>${escapeHtml(card.body).replaceAll("\n", "<br>")}</p>
      </article>
    `).join("");
  }

  function renderSystemPage() {
    const info = state.systemInfo || createMockSystemInfo();
    const cards = [
      { title: "Имя хоста", body: info.hostname },
      { title: "Операционная система", body: info.osName },
      { title: "Версия ядра", body: info.kernel },
      { title: "Пользователь", body: info.username || state.scanSession.username },
      { title: "ID пользователя", body: info.userId || info.user_id || state.scanSession.userId },
      { title: "Роль в модели hardening", body: "Рабочая станция общего назначения с усиленной защитой ядра, памяти, загрузчика и пользовательской среды." },
    ];

    elements.systemGrid.innerHTML = cards.map((card) => `
      <article class="system-card-mini">
        <strong>${escapeHtml(card.title)}</strong>
        <p>${escapeHtml(card.body)}</p>
      </article>
    `).join("");
  }

  function getViewMeta(view) {
    const mapping = {
      dashboard: { search: "Поиск по проверкам, политикам и параметрам", subtitle: "Обзор состояния узла" },
      policies: { search: "Поиск по политикам и разделам документа", subtitle: "Политики безопасной настройки" },
      profile: { search: "Поиск по профилю узла и требованиям", subtitle: "Профиль защищённости станции" },
      reports: { search: "Поиск по отчётам и журналу операций", subtitle: "История выгрузок и логов" },
      analytics: { search: "Поиск по технической аналитике хоста", subtitle: "Метрики и технические сведения" },
      system: { search: "Поиск по системным сведениям", subtitle: "Базовые сведения о платформе" },
    };
    return mapping[view] || mapping.dashboard;
  }

  function switchView(view) {
    state.currentView = view;
    elements.navButtons.forEach((button) => {
      button.classList.toggle("nav-item-active", button.dataset.view === view);
    });
    elements.views.forEach((panel) => {
      panel.classList.toggle("is-active", panel.id === `view-${view}`);
    });

    const meta = getViewMeta(view);
    elements.searchPlaceholder.textContent = meta.search;
    elements.topbarSubtitle.textContent = meta.subtitle;

    if (view === "policies") renderPoliciesPage();
    if (view === "profile") renderProfilePage();
    if (view === "reports") renderReportsPage();
    if (view === "analytics") renderAnalyticsPage();
    if (view === "system") renderSystemPage();
  }

  async function loadSystemInfo() {
    if (!hasTauri()) {
      state.mockMode = true;
      state.systemInfo = createMockSystemInfo();
      state.analytics = createMockAnalytics();
      syncScanSessionFromSystemInfo(state.systemInfo);
      elements.hostname.textContent = state.systemInfo.hostname;
      elements.osName.textContent = state.systemInfo.osName;
      elements.kernel.textContent = state.systemInfo.kernel;
      showNotification("Открыт browser preview в mock-режиме без Tauri backend.", "info");
      return;
    }

    try {
      const info = await invoke("get_system_info");
      state.systemInfo = info;
      syncScanSessionFromSystemInfo(info);
      elements.hostname.textContent = info.hostname || "—";
      elements.osName.textContent = info.osName || "—";
      elements.kernel.textContent = info.kernel || "—";
    } catch (error) {
      showNotification(`Не удалось получить информацию о системе: ${error}`, "error");
    }
  }

  async function runScan() {
    hideNotification();
    switchView("dashboard");
    state.scanSession.startedAt = formatDateTime(new Date());
    state.scanSession.finishedAt = null;
    setBusy(true, "Сканирование параметров безопасности...");
    addLog(`Стартовало сканирование. Пользователь: ${state.scanSession.username} (ID: ${state.scanSession.userId}), хост: ${state.scanSession.hostname}.`);

    try {
      await wait(160);
      elements.progressBar.style.width = "32%";
      await wait(190);
      elements.progressBar.style.width = "58%";

      const results = hasTauri() ? await invoke("scan_all") : createMockResults();

      await wait(180);
      elements.progressBar.style.width = "84%";
      await wait(140);
      elements.progressBar.style.width = "100%";

      state.results = Array.isArray(results) ? results : [];
      state.scanSession.finishedAt = formatDateTime(new Date());
      renderResults();
      renderPoliciesPage();
      renderProfilePage();
      renderReportsPage();
      renderAnalyticsPage();
      renderSystemPage();
      showNotification(`Сканирование завершено: найдено ${getFailCount()} параметров, требующих внимания.`, "success");
      addLog(`Сканирование завершено. Окно сессии: ${state.scanSession.startedAt} → ${state.scanSession.finishedAt}. Результатов: ${state.results.length}.`);
    } catch (error) {
      state.scanSession.finishedAt = formatDateTime(new Date());
      showNotification(`Ошибка сканирования: ${error}`, "error");
      addLog(`Ошибка сканирования: ${error}`);
    } finally {
      window.setTimeout(() => {
        setBusy(false, "Сканирование завершено");
        elements.progressBar.style.width = "0%";
      }, 220);
    }
  }

  async function applySettings() {
    hideNotification();

    if (!state.results.length) {
      showNotification("Сначала выполните сканирование.", "info");
      return;
    }

    let failIds;
    try {
      failIds = hasTauri()
        ? await invoke("get_fail_ids", { results: state.results })
        : state.results.filter((item) => item.status === "Fail").map((item) => item.check.id);
    } catch (error) {
      showNotification(`Не удалось определить проблемные параметры: ${error}`, "error");
      return;
    }

    if (!Array.isArray(failIds) || failIds.length === 0) {
      showNotification("Параметры со статусом FAIL отсутствуют.", "info");
      return;
    }

    if (!window.confirm(`Будут применены ${failIds.length} параметров безопасности. Продолжить?`)) {
      return;
    }

    setBusy(true, "Применение настроек...");
    addLog(`Начато применение ${failIds.length} параметров безопасности.`);

    try {
      const result = hasTauri()
        ? await invoke("apply_settings", { checkIds: failIds })
        : { applied: failIds.map(String), failed: [], needsReboot: true };

      if (result.needsReboot) showRebootModal();

      if (!hasTauri()) {
        state.results = state.results.map((item) => (
          item.status === "Fail"
            ? { ...item, current_value: item.check.target_value, status: "Pass" }
            : item
        ));
        renderResults();
        renderProfilePage();
        renderAnalyticsPage();
      } else {
        await runScan();
      }

      showNotification("Настройки безопасности обработаны.", "success");
      addLog("Применение настроек завершено.");
    } catch (error) {
      showNotification(`Ошибка применения настроек: ${error}`, "error");
      addLog(`Ошибка применения настроек: ${error}`);
    } finally {
      setBusy(false, "Применение завершено");
      elements.progressBar.style.width = "0%";
    }
  }

  function registerExport(format, path) {
    const extension = format === "Pdf" ? "pdf" : "html";
    const metadata = getReportMetadata();
    state.reportHistory.unshift({
      type: format.toUpperCase(),
      name: path.split(/[\\/]/).pop() || `alt-hardening-report.${extension}`,
      createdAt: formatDateTime(new Date()),
      status: "Сохранён",
      size: format === "Pdf" ? "304 KB" : "148 KB",
      hostname: metadata.hostname,
      username: metadata.username,
      userId: metadata.user_id,
      scanStartedAt: metadata.scan_started_at,
      scanFinishedAt: metadata.scan_finished_at,
    });
    addLog(`Сформирован ${format.toUpperCase()}-отчёт: ${path}`);
    renderReportsPage();
    renderResults();
  }

  async function exportReport(format) {
    hideNotification();

    if (!state.results.length) {
      showNotification("Нет данных для экспорта. Сначала выполните сканирование.", "info");
      return;
    }

    const extension = format === "Pdf" ? "pdf" : "html";
    const path = await pickSavePath(`alt-hardening-report.${extension}`, [
      { name: format === "Pdf" ? "PDF Report" : "HTML Report", extensions: [extension] },
    ]);

    if (!path) return;

    setBusy(true, `Экспорт ${format.toUpperCase()} отчёта...`);
    elements.progressBar.style.width = "66%";

    try {
      if (hasTauri()) {
        const message = await invoke("generate_report", {
          results: state.results,
          outputPath: path,
          format,
          metadata: getReportMetadata(),
        });
        showNotification(message, "success");
      } else {
        await wait(180);
        showNotification(`Mock preview: экспорт ${format.toUpperCase()} подготовлен.`, "success");
      }
      elements.progressBar.style.width = "100%";
      registerExport(format, path);
    } catch (error) {
      showNotification(`Ошибка экспорта отчёта: ${error}`, "error");
      addLog(`Ошибка экспорта ${format.toUpperCase()}: ${error}`);
    } finally {
      window.setTimeout(() => {
        setBusy(false, "Экспорт завершён");
        elements.progressBar.style.width = "0%";
      }, 180);
    }
  }

  function downloadTextFile(filename, content) {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function downloadAllReports() {
    downloadTextFile(
      "alt-hardening-reports-and-logs.json",
      JSON.stringify({
        reports: state.reportHistory,
        logs: state.logs,
        scanSession: getReportMetadata(),
      }, null, 2),
    );
    addLog("Выполнена выгрузка всех отчётов и журналов.");
    showNotification("Сводный файл с отчётами и логами скачан.", "success");
  }

  async function exportHtml() {
    return exportReport("Html");
  }

  async function exportPdf() {
    return exportReport("Pdf");
  }

  function bindActions() {
    elements.navButtons.forEach((button) => {
      button.addEventListener("click", () => switchView(button.dataset.view));
    });
    elements.downloadAllButton?.addEventListener("click", downloadAllReports);
    elements.scanButton?.addEventListener("click", (event) => {
      event.preventDefault();
      runScan();
    });
    elements.fixButton?.addEventListener("click", (event) => {
      event.preventDefault();
      applySettings();
    });
    elements.htmlButton?.addEventListener("click", (event) => {
      event.preventDefault();
      exportHtml();
    });
    elements.pdfButton?.addEventListener("click", (event) => {
      event.preventDefault();
      exportPdf();
    });
  }

  window.runScan = runScan;
  window.applySettings = applySettings;
  window.exportHtml = exportHtml;
  window.exportPdf = exportPdf;
  window.hideNotification = hideNotification;
  window.hideRebootModal = hideRebootModal;

  document.addEventListener("DOMContentLoaded", async () => {
    bindActions();
    await loadSystemInfo();
    renderPoliciesPage();
    renderProfilePage();
    renderReportsPage();
    renderAnalyticsPage();
    renderSystemPage();
    renderResults();
    switchView("dashboard");
    if (state.mockMode) {
      await runScan();
    }
  });
})();
