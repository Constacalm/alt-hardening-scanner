# ALT Hardening Scanner

Нативное desktop-приложение на **Rust + Tauri v2** для проверки и применения
рекомендаций безопасной настройки **ALT Рабочая Станция 11** по
РД ФСТЭК «Рекомендации по обеспечению безопасной настройки ОС Linux» от 25.12.2022.

---

## ⚡ Быстрый старт — получить RPM

> **Важно:** RPM собирается только на **Linux-машине** (ALT Linux, Fedora, RHEL).
> На Windows используйте WSL2 или GitHub Actions (см. ниже).

```bash
# 1. Клонировать репозиторий на Linux-машину
git clone https://github.com/firstbeelancer/alt-hardening-scanner.git
cd alt-hardening-scanner

# 2. Запустить скрипт сборки
#    Скрипт автоматически:
#      — определит дистрибутив (ALT Linux / Fedora / RHEL)
#      — проверит и установит зависимости (webkit2gtk, openssl, rpm-build)
#      — установит Rust и Tauri CLI если их нет
#      — соберёт релизный бинарь и упакует его в .rpm
bash build-rpm.sh
```

**RPM появится по пути:**
```
src-tauri/target/release/bundle/rpm/
  alt-hardening-scanner-1.0.0-alt1.x86_64.rpm
```

**Установка готового пакета:**
```bash
# Через rpm (универсально):
sudo rpm -i src-tauri/target/release/bundle/rpm/*.rpm

# Через apt-rpm (ALT Linux — разрешает зависимости):
sudo apt-get install ./src-tauri/target/release/bundle/rpm/*.rpm

# Через dnf (Fedora — разрешает зависимости):
sudo dnf install ./src-tauri/target/release/bundle/rpm/*.rpm
```

**Запуск после установки:**
```bash
alt-hardening-scanner          # сканирование (без root)
sudo alt-hardening-scanner     # + применение hardening-настроек
```

---

## Возможности

| Функция | Описание |
|---------|----------|
| 🔍 Сканирование | Проверяет все 25 параметров Таблицы 2 (sysctl + GRUB) |
| 🔒 Применение | Устанавливает целевые значения с резервными копиями файлов |
| 📄 HTML-отчёт | Самодостаточный HTML с цветовой кодировкой и метаданными |
| 📑 PDF-отчёт | Через wkhtmltopdf (автоматический fallback → HTML) |
| 📦 RPM-пакет | Собирается через `bash build-rpm.sh` |

---

## Структура проекта

```
alt-hardening-scanner/
├── src-tauri/
│   ├── Cargo.toml           # зависимости Rust
│   ├── tauri.conf.json      # конфигурация Tauri + RPM-метаданные
│   ├── build.rs             # скрипт сборки Tauri
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
├── build-rpm.sh             # ← скрипт сборки RPM (запускать этот)
└── README.md
```

---

## Требования для сборки

### ALT Linux / ALT Рабочая Станция 11

```bash
# Rust toolchain (если не установлен)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Системные библиотеки сборки
sudo apt-get install \
    webkit2gtk3-devel \
    libappindicator-gtk3-devel \
    openssl-devel \
    rpm-build \
    gcc \
    pkg-config

# Tauri CLI
cargo install tauri-cli --version "^2" --locked
```

### Fedora 39+ / RHEL 9+

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Системные библиотеки сборки
sudo dnf install \
    webkit2gtk4.0-devel \
    libappindicator-gtk3-devel \
    openssl-devel \
    rpm-build \
    gcc \
    pkg-config

# Tauri CLI
cargo install tauri-cli --version "^2" --locked
```

> **Примечание:** `build-rpm.sh` устанавливает всё это автоматически — ручная установка нужна только если хотите управлять зависимостями самостоятельно.

---

## Сборка без Linux-машины (WSL2 на Windows)

```powershell
# Открыть WSL2 (PowerShell):
wsl

# Внутри WSL2 — клонировать и собрать:
git clone https://github.com/firstbeelancer/alt-hardening-scanner.git
cd alt-hardening-scanner
bash build-rpm.sh

# Готовый RPM будет в:
# src-tauri/target/release/bundle/rpm/*.rpm
# Скопировать на Linux-машину и установить через rpm/dnf
```

---

## Разработка (dev-режим)

```bash
# На Linux-машине с установленными зависимостями:
cd src-tauri
cargo tauri dev
```

Приложение откроется с hot-reload — изменения в `ui/` применяются мгновенно без перекомпиляции.

---

## Права доступа

| Операция | Права |
|----------|-------|
| Сканирование (чтение) | Обычный пользователь |
| Применение sysctl | **root** (`sudo alt-hardening-scanner`) |
| Применение GRUB | **root** + **перезагрузка** |

Если приложение запущено без root и нажата кнопка «Включить защиту», появляется сообщение:
> *«Для применения настроек требуются права root. Перезапустите: `sudo alt-hardening-scanner`»*

---

## Параметры (Таблица 2, РД ФСТЭК 25.12.2022)

### sysctl (`/etc/sysctl.conf`)

| № | Параметр | Цель | По умолчанию | Описание |
|---|----------|------|--------------|----------|
| 1 | `kernel.dmesg_restrict` | 1 | 1 | Ограничение доступа к dmesg |
| 2 | `kernel.kptr_restrict` | 2 | 0 | Скрытие адресов ядра |
| 8 | `net.core.bpf_jit_harden` | 2 | 0 | Защита JIT-компилятора BPF |
| 10 | `kernel.perf_event_paranoid` | 3 | 4 | Ограничение perf events |
| 12 | `kernel.kexec_load_disabled` | 1 | 0 | Запрет загрузки ядра через kexec |
| 13 | `user.max_user_namespaces` | 0 | 5098941 | Отключение user namespaces |
| 14 | `kernel.unprivileged_bpf_disabled` | 1 | 2 | Запрет BPF без root |
| 15 | `vm.unprivileged_userfaultfd` | 0 | 1 | Запрет unprivileged userfaultfd |
| 16 | `dev.tty.ldisc_autoload` | 0 | 1 | Запрет автозагрузки TTY ldisc |
| 18 | `vm.mmap_min_addr` | 4096 | 65536 | Защита от NULL-ptr dereference |
| 19 | `kernel.randomize_va_space` | 2 | 2 | ASLR уровень 2 |
| 20 | `kernel.yama.ptrace_scope` | 3 | 1 | Полный запрет ptrace |
| 21 | `fs.protected_symlinks` | 1 | 1 | Защита symlink |
| 22 | `fs.protected_hardlinks` | 1 | 1 | Защита hardlink |
| 23 | `fs.protected_fifos` | 2 | 1 | Усиленная защита FIFO |
| 24 | `fs.protected_regular` | 2 | 1 | Усиленная защита файлов |
| 25 | `fs.suid_dumpable` | 0 | 0 | Запрет core-дампов для SUID |

### GRUB (`GRUB_CMDLINE_LINUX_DEFAULT`)

| № | Параметр | Описание |
|---|----------|----------|
| 3 | `init_on_alloc=1` | Инициализация памяти нулями при выделении |
| 4 | `slab_nomerge` | Запрет слияния slab-кэшей |
| 5 | `iommu=force iommu.strict=1 iommu.passthrough=0` | Принудительный IOMMU + strict DMA |
| 6 | `randomize_kstack_offset=1` | Рандомизация смещения стека ядра |
| 7 | `mitigations=auto,nosmt` | Все CPU-митигации + отключение SMT |
| 9 | `vsyscall=none` | Отключение legacy vsyscall ABI |
| 11 | `debugfs=no-mount` | Запрет монтирования debugfs |
| 17 | `tsx=off` | Отключение Intel TSX (TAA/TSX Async Abort) |

---

## Лицензия

MIT — свободное использование, включая коммерческое применение.
