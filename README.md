# ALT Hardening Scanner

Нативное desktop-приложение на **Rust + Tauri v2** для проверки и применения
рекомендаций безопасной настройки **ALT Рабочая Станция 11** по
РД ФСТЭК «Рекомендации по обеспечению безопасной настройки ОС Linux» от 25.12.2022.

---

## Возможности

| Функция | Описание |
|---------|----------|
| 🔍 Сканирование | Проверяет все 25 параметров Таблицы 2 (sysctl + GRUB) |
| 🔒 Применение | Устанавливает целевые значения с резервными копиями файлов |
| 📄 HTML-отчёт | Самодостаточный HTML с цветовой кодировкой |
| 📑 PDF-отчёт | Через wkhtmltopdf (fallback → HTML) |
| 📦 RPM-пакет | Собирается через `cargo tauri build --bundles rpm` |

---

## Структура проекта

```
alt-hardening-scanner/
├── src-tauri/
│   ├── Cargo.toml           # зависимости Rust
│   ├── tauri.conf.json      # конфигурация Tauri + RPM-метаданные
│   ├── build.rs
│   └── src/
│       ├── main.rs          # точка входа, регистрация команд
│       ├── checks.rs        # все 25 параметров Таблицы 2
│       ├── scanner.rs       # чтение sysctl + /etc/default/grub
│       ├── remediation.rs   # применение настроек (требует root)
│       └── report.rs        # генерация HTML/PDF отчётов
├── ui/
│   ├── index.html           # интерфейс (6 разделов)
│   ├── style.css            # корпоративный стиль
│   └── main.js              # логика фронтенда + Tauri invoke()
├── build-rpm.sh             # скрипт сборки RPM
└── README.md
```

---

## Требования для сборки

### На ALT Linux / ALT Рабочая Станция 11

```bash
# Rust toolchain
curl https://sh.rustup.rs | sh
source ~/.cargo/env

# Системные библиотеки
sudo apt-get install \
    webkit2gtk3-devel \
    libappindicator-gtk3-devel \
    openssl-devel \
    libsoup3-devel \
    rpm-build \
    gcc \
    pkg-config

# Tauri CLI
cargo install tauri-cli --version "^2"
```

### На Fedora / RHEL-совместимых

```bash
sudo dnf install \
    webkit2gtk4.0-devel \
    libappindicator-gtk3-devel \
    openssl-devel \
    rpm-build
```

---

## Разработка (dev-режим)

```bash
cd src-tauri
cargo tauri dev
```

Приложение откроется с hot-reload — изменения в `ui/` применяются сразу.

---

## Сборка RPM

### Быстрый способ (скрипт)

```bash
bash build-rpm.sh
```

### Вручную

```bash
cd src-tauri
cargo tauri build --bundles rpm
```

RPM появится в:
```
src-tauri/target/release/bundle/rpm/alt-hardening-scanner-1.0.0-alt1.x86_64.rpm
```

### Установка RPM

```bash
# Через rpm
sudo rpm -i src-tauri/target/release/bundle/rpm/*.rpm

# Через apt-rpm (ALT Linux)
sudo apt-get install ./src-tauri/target/release/bundle/rpm/*.rpm

# Через dnf (Fedora)
sudo dnf install ./src-tauri/target/release/bundle/rpm/*.rpm
```

После установки приложение запускается командой:

```bash
alt-hardening-scanner
# или с правами root для применения настроек:
sudo alt-hardening-scanner
```

---

## Права доступа

| Операция | Права |
|----------|-------|
| Сканирование | Обычный пользователь |
| Применение sysctl | **root** (`sudo`) |
| Применение GRUB | **root** (`sudo`) + перезагрузка |

Если приложение запущено без root и нажата кнопка «Включить защиту»,
появляется сообщение:
> *«Перезапустите: `sudo alt-hardening-scanner`»*

---

## Параметры (Таблица 2, РД ФСТЭК 25.12.2022)

### sysctl (`/etc/sysctl.conf`)

| № | Параметр | Цель | По умолчанию |
|---|----------|------|--------------|
| 1 | `kernel.dmesg_restrict` | 1 | 1 |
| 2 | `kernel.kptr_restrict` | 2 | 0 |
| 8 | `net.core.bpf_jit_harden` | 2 | 0 |
| 10 | `kernel.perf_event_paranoid` | 3 | 4 |
| 12 | `kernel.kexec_load_disabled` | 1 | 0 |
| 13 | `user.max_user_namespaces` | 0 | 5098941 |
| 14 | `kernel.unprivileged_bpf_disabled` | 1 | 2 |
| 15 | `vm.unprivileged_userfaultfd` | 0 | 1 |
| 16 | `dev.tty.ldisc_autoload` | 0 | 1 |
| 18 | `vm.mmap_min_addr` | 4096 | 65536 |
| 19 | `kernel.randomize_va_space` | 2 | 2 |
| 20 | `kernel.yama.ptrace_scope` | 3 | 1 |
| 21 | `fs.protected_symlinks` | 1 | 1 |
| 22 | `fs.protected_hardlinks` | 1 | 1 |
| 23 | `fs.protected_fifos` | 2 | 1 |
| 24 | `fs.protected_regular` | 2 | 1 |
| 25 | `fs.suid_dumpable` | 0 | 0 |

### GRUB (`GRUB_CMDLINE_LINUX_DEFAULT`)

| № | Параметр | Статус цели |
|---|----------|-------------|
| 3 | `init_on_alloc=1` | присутствует |
| 4 | `slab_nomerge` | присутствует |
| 5 | `iommu=force iommu.strict=1 iommu.passthrough=0` | все три |
| 6 | `randomize_kstack_offset=1` | присутствует |
| 7 | `mitigations=auto,nosmt` | присутствует |
| 9 | `vsyscall=none` | присутствует |
| 11 | `debugfs=no-mount` | присутствует |
| 17 | `tsx=off` | присутствует |

---

## Лицензия

MIT
