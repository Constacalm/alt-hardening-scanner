#!/usr/bin/env bash
# =============================================================================
#  build-rpm.sh — Сборка ALT Hardening Scanner в .rpm
#
#  Поддерживаемые платформы:
#    • ALT Рабочая Станция 11 (p11)      — ОСНОВНАЯ ЦЕЛЬ
#    • ALT Сизиф (Sisyphus, rolling)      — ОСНОВНАЯ ЦЕЛЬ
#    • Fedora 38+                         — вторичная поддержка
#    • RHEL 9 / CentOS Stream 9           — вторичная поддержка
#
#  ИСПОЛЬЗОВАНИЕ:
#    git clone https://github.com/firstbeelancer/alt-hardening-scanner.git
#    cd alt-hardening-scanner
#    bash build-rpm.sh
#
#  РЕЗУЛЬТАТ:
#    src-tauri/target/release/bundle/rpm/
#      alt-hardening-scanner-1.0.0-alt1.x86_64.rpm
#
#  УСТАНОВКА НА ALT LINUX:
#    sudo apt-get install ./src-tauri/target/release/bundle/rpm/*.rpm
#    # или
#    sudo rpm -i src-tauri/target/release/bundle/rpm/*.rpm
#
#  ЗАПУСК ПОСЛЕ УСТАНОВКИ:
#    alt-hardening-scanner              # сканирование (без root)
#    sudo alt-hardening-scanner         # + применение настроек безопасности
#
# =============================================================================
#
#  ПОЧЕМУ OPENSSL И MD5 В ЗАВИСИМОСТЯХ? (Ответ на частый вопрос)
#  ─────────────────────────────────────────────────────────────────
#  Это НЕ наш код — это транзитивные зависимости самого Tauri:
#
#  • openssl  — Tauri использует TLS для загрузки ресурсов внутри WebView
#               (webkit2gtk также линкуется с системным OpenSSL).
#               Наш Cargo.toml не содержит openssl напрямую.
#
#  • sha2/md5 — tauri-bundler считает контрольные суммы при упаковке RPM/DEB,
#               чтобы пакет можно было верифицировать при установке.
#               Это стандартная практика для всех Linux-пакетов.
#
#  Посмотреть полное дерево зависимостей:
#    cd src-tauri && cargo tree | grep -E "md5|openssl|sha"
#
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

banner() {
    echo ""
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${BOLD}  ALT Hardening Scanner — Сборка RPM-пакета${NC}"
    echo -e "${CYAN}  РД ФСТЭК «Рекомендации по безопасной настройке ОС Linux»${NC}"
    echo -e "${CYAN}  25.12.2022 · Таблица 2 · 25 параметров ядра${NC}"
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

banner

# ═════════════════════════════════════════════════════════════════════════════
# ШАГ 1: Определяем дистрибутив
# ═════════════════════════════════════════════════════════════════════════════
step "Шаг 1/6 — Определение дистрибутива..."

DISTRO="unknown"
DISTRO_PRETTY="Unknown"

if grep -qi "ALT Linux\|ALT Workstation\|ALT Server\|Sisyphus" /etc/os-release 2>/dev/null \
   || [ -f /etc/altlinux-release ]; then

    DISTRO="altlinux"

    if grep -qi "sisyphus" /etc/os-release 2>/dev/null; then
        DISTRO_PRETTY="ALT Linux Sisyphus (rolling)"
    else
        VER=$(grep VERSION_ID /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "")
        DISTRO_PRETTY="ALT Linux p${VER:-11}"
    fi

elif [ -f /etc/fedora-release ]; then
    DISTRO="fedora"
    DISTRO_PRETTY="Fedora $(rpm -E %fedora 2>/dev/null || cat /etc/fedora-release)"

elif [ -f /etc/redhat-release ]; then
    DISTRO="rhel"
    DISTRO_PRETTY="RHEL/CentOS $(cat /etc/redhat-release)"

else
    warn "Дистрибутив не определён — продолжаем как ALT Linux."
    DISTRO="altlinux"
    DISTRO_PRETTY="Неизвестный (fallback → ALT Linux)"
fi

info "Обнаружен: ${BOLD}${DISTRO_PRETTY}${NC}"

# ═════════════════════════════════════════════════════════════════════════════
# ШАГ 2: Системные зависимости сборки
#
#  ALT Linux p11 / Sisyphus — точные имена пакетов
#  (источник: packages.altlinux.org + Tauri v2 prerequisites)
#  ─────────────────────────────────────────────────────────────
#  Пакет                  │ Зачем нужен
#  ───────────────────────┼────────────────────────────────────────────────
#  rust                   │ Компилятор rustc ≥ 1.77 (есть в ALT p11/Sisyphus)
#  cargo                  │ Менеджер пакетов Rust (идёт вместе с rust)
#  libwebkit2gtk-devel    │ WebView-движок Tauri (webkit2gtk-4.0 dev-заголовки)
#  openssl-devel          │ TLS — для WebView и tauri-bundler
#  gtk3-devel             │ GTK3 dev-заголовки (базовый UI-тулкит)
#  pkg-config             │ Поиск .pc-файлов при компиляции C-зависимостей
#  gcc                    │ C-компилятор (линковка системных библиотек)
#  gcc-c++                │ C++ (webkit2gtk требует C++)
#  rpm-build              │ rpmbuild — упаковщик финального .rpm файла
#
#  НЕ НУЖНО устанавливать вручную (придут автоматически):
#  • libwebkit2gtk    — runtime, подтянется как зависимость devel-пакета
#  • libssl           — runtime OpenSSL, уже есть в базовой системе
#  • libgtk+3         — GTK3 runtime, тоже уже есть
# ═════════════════════════════════════════════════════════════════════════════
step "Шаг 2/6 — Проверка системных зависимостей..."

# ALT Linux p11 / Sisyphus
ALT_DEPS=(
    "rust"
    "cargo"
    "libwebkit2gtk-devel"
    "openssl-devel"
    "gtk3-devel"
    "pkg-config"
    "gcc"
    "gcc-c++"
    "rpm-build"
)

# Fedora / RHEL (webkit2gtk4.0 — новее чем webkit2gtk-4.0)
FEDORA_DEPS=(
    "rust"
    "cargo"
    "webkit2gtk4.0-devel"
    "openssl-devel"
    "gtk3-devel"
    "pkg-config"
    "gcc"
    "gcc-c++"
    "rpm-build"
    "curl"
    "file"
)

MISSING=()

check_pkg() {
    if rpm -q "$1" &>/dev/null; then
        ok "  ✓ $1"
    else
        warn "  ✗ $1"
        MISSING+=("$1")
    fi
}

echo ""
if [ "$DISTRO" = "altlinux" ]; then
    info "Пакеты ALT Linux (apt-get / apt-rpm):"
    for p in "${ALT_DEPS[@]}"; do check_pkg "$p"; done
else
    info "Пакеты Fedora/RHEL (dnf):"
    for p in "${FEDORA_DEPS[@]}"; do check_pkg "$p"; done
fi

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo ""
    warn "Не установлено: ${MISSING[*]}"
    read -rp "  Установить автоматически? [y/N]: " ans
    if [[ "${ans,,}" != "y" ]]; then
        echo ""
        if [ "$DISTRO" = "altlinux" ]; then
            echo -e "${YELLOW}  sudo apt-get install -y ${MISSING[*]}${NC}"
        else
            echo -e "${YELLOW}  sudo dnf install -y ${MISSING[*]}${NC}"
        fi
        error "Сборка прервана — установите зависимости и повторите."
    fi
    if [ "$DISTRO" = "altlinux" ]; then
        # apt-get на ALT Linux — это apt-rpm (RPM-based APT), не Debian APT
        sudo apt-get install -y "${MISSING[@]}" \
            || error "apt-get завершился с ошибкой.\nОбновите базу пакетов: sudo apt-get update"
    else
        sudo dnf install -y "${MISSING[@]}" || error "dnf завершился с ошибкой."
    fi
    ok "Зависимости установлены."
else
    ok "Все зависимости в наличии."
fi

# ═════════════════════════════════════════════════════════════════════════════
# ШАГ 3: Rust toolchain
#
#  Tauri v2 требует rustc ≥ 1.77.2
#  ALT Linux p11 поставляет rust ≥ 1.84 — достаточно.
#  ALT Linux Sisyphus — rust ≥ 1.87+
#
#  Приоритет: системный Rust из репозитория → rustup как fallback
#  Путь бинарей: /usr/bin/rustc (системный) или ~/.cargo/bin/rustc (rustup)
# ═════════════════════════════════════════════════════════════════════════════
step "Шаг 3/6 — Проверка Rust toolchain..."

# Загружаем окружение rustup если был установлен ранее
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env" 2>/dev/null || true

if ! command -v rustc &>/dev/null; then
    warn "rustc не найден в PATH."

    if [ "$DISTRO" = "altlinux" ]; then
        info "Устанавливаю из репозитория ALT Linux..."
        sudo apt-get install -y rust cargo || {
            warn "Не удалось из репозитория. Использую rustup как fallback..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
                | sh -s -- -y --no-modify-path --profile minimal
            source "${HOME}/.cargo/env"
        }
    else
        sudo dnf install -y rust cargo 2>/dev/null || {
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
                | sh -s -- -y --no-modify-path --profile minimal
            source "${HOME}/.cargo/env"
        }
    fi
fi

RUSTC_VER=$(rustc --version 2>/dev/null || echo "unknown")
CARGO_VER=$(cargo --version 2>/dev/null || echo "unknown")
info "rustc: ${RUSTC_VER}"
info "cargo: ${CARGO_VER}"

# Проверяем минорную версию
RUSTC_MINOR=$(rustc --version | grep -oP '1\.\K[0-9]+' | head -1 || echo "0")
if [ "${RUSTC_MINOR}" -lt 77 ]; then
    error "Нужен rustc ≥ 1.77. Текущий: ${RUSTC_VER}\n\
  ALT Linux: sudo apt-get install -y rust\n\
  rustup:    rustup update stable"
fi
ok "Rust toolchain актуален (minor=${RUSTC_MINOR})."

# ═════════════════════════════════════════════════════════════════════════════
# ШАГ 4: Tauri CLI
#
#  Устанавливается через cargo install — в репах ALT Linux его нет.
#  Бинарь кешируется в ~/.cargo/bin/cargo-tauri после первой установки.
#  Первая компиляция: 5–15 минут.
#  Повторные запуски: мгновенно.
# ═════════════════════════════════════════════════════════════════════════════
step "Шаг 4/6 — Проверка Tauri CLI..."

if cargo tauri --version &>/dev/null 2>&1; then
    ok "Tauri CLI: $(cargo tauri --version 2>/dev/null)"
else
    info "Tauri CLI не найден. Собираю tauri-cli v2..."
    info "(Первая сборка займёт 5–15 минут)"
    cargo install tauri-cli --version "^2" --locked \
        || error "Не удалось установить tauri-cli.\n\
  Проверьте: sudo apt-get install -y gcc openssl-devel pkg-config"
    ok "Tauri CLI: $(cargo tauri --version 2>/dev/null)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# ШАГ 5: Проверка структуры проекта
# ═════════════════════════════════════════════════════════════════════════════
step "Шаг 5/6 — Проверка структуры проекта..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

[ -f "src-tauri/Cargo.toml" ]      || error "Не найден src-tauri/Cargo.toml — запускайте из корня репозитория."
[ -f "src-tauri/tauri.conf.json" ] || error "Не найден src-tauri/tauri.conf.json"
[ -f "ui/index.html" ]             || error "Не найден ui/index.html"
[ -f "ui/main.js" ]                || error "Не найден ui/main.js"

ok "Структура проекта в порядке."
echo ""
echo -e "  ${CYAN}Продукт:${NC}  $(grep -m1 '"productName"' src-tauri/tauri.conf.json | tr -d ' ",' | cut -d: -f2-)"
echo -e "  ${CYAN}Версия:${NC}   $(grep '"version"' src-tauri/tauri.conf.json | head -2 | tail -1 | tr -d ' ",' | cut -d: -f2-)"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# ШАГ 6: Сборка RPM
#
#  Что делает cargo tauri build --bundles rpm:
#  1. Компилирует Rust-бэкенд → release-бинарь
#     (profile.release: opt-level=s, lto=true, strip=true → ~4-8 МБ)
#  2. Встраивает UI (html/js/css) внутрь бинаря как статические ресурсы
#     (никакого Node.js, никакого npm на целевой машине не нужно!)
#  3. Формирует RPM через rpmbuild
#
#  Runtime-зависимости ГОТОВОГО пакета (что нужно на целевой машине):
#  • libwebkit2gtk  — WebView (уже есть в ALT p11 базовой установке)
#  • libssl         — OpenSSL runtime (уже есть)
#  • libgtk+3       — GTK3 (уже есть)
#  → RPM устанавливается без интернета на изолированных АРМ
#
#  WEBKIT_DISABLE_DMABUF_RENDERER=1 — обходной путь для конфигураций
#  ALT Linux с драйверами mesa/i915, где DMA-BUF вызывает падение WebView.
# ═════════════════════════════════════════════════════════════════════════════
step "Шаг 6/6 — Сборка RPM..."
echo ""
info "Запускаю: cargo tauri build --bundles rpm"

LOG="/tmp/tauri-build-$(date +%Y%m%d_%H%M%S).log"
info "Лог: ${LOG}"
echo ""

export WEBKIT_DISABLE_DMABUF_RENDERER=1

cd src-tauri
BUILD_OK=true
cargo tauri build --bundles rpm 2>&1 | tee "${LOG}" || BUILD_OK=false
cd ..

if [ "${BUILD_OK}" != "true" ]; then
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  ❌ СБОРКА ЗАВЕРШИЛАСЬ С ОШИБКОЙ${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}  Последние 30 строк лога:${NC}"
    tail -30 "${LOG}" | sed 's/^/    /'
    echo ""
    echo -e "${YELLOW}  Частые причины ошибок на ALT Linux p11:${NC}"
    echo "  1. webkit2gtk не найден  → sudo apt-get install -y libwebkit2gtk-devel"
    echo "  2. openssl не найден     → sudo apt-get install -y openssl-devel"
    echo "  3. Старый rustc          → sudo apt-get install -y rust  (или rustup update)"
    echo "  4. Нет pkg-config        → sudo apt-get install -y pkg-config"
    echo "  5. Нет rpmbuild          → sudo apt-get install -y rpm-build"
    echo ""
    echo -e "  Полный лог: ${LOG}"
    exit 1
fi

RPM_FILE=$(find src-tauri/target/release/bundle/rpm -name "*.rpm" 2>/dev/null | head -1)
[ -z "${RPM_FILE}" ] && error "RPM-файл не найден после сборки. Лог: ${LOG}"

RPM_NAME=$(basename "${RPM_FILE}")
RPM_SIZE=$(du -sh "${RPM_FILE}" | cut -f1)

echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✅ ГОТОВО${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}📦 Файл:${NC}   ${RPM_NAME}"
echo -e "  ${BOLD}Размер:${NC}  ${RPM_SIZE}"
echo -e "  ${BOLD}Путь:${NC}    ${RPM_FILE}"
echo ""
echo -e "  ${CYAN}Содержимое пакета:${NC}"
rpm -qpl "${RPM_FILE}" 2>/dev/null | sed 's/^/    /' || true
echo ""
echo -e "  ${CYAN}Runtime-зависимости (должны быть на целевой машине):${NC}"
rpm -qpR "${RPM_FILE}" 2>/dev/null | sed 's/^/    /' || true
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  УСТАНОВКА НА ALT LINUX p11 / Sisyphus:${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}# Через apt-get (рекомендуется — сам разрешит зависимости):${NC}"
echo -e "  sudo apt-get install ./${RPM_FILE}"
echo ""
echo -e "  ${BOLD}# Через rpm (без разрешения зависимостей):${NC}"
echo -e "  sudo rpm -i ${RPM_FILE}"
echo ""
echo -e "  ${BOLD}# Скопировать на другую машину и установить:${NC}"
echo -e "  scp ${RPM_FILE} user@target:/tmp/"
echo -e "  ssh user@target 'sudo apt-get install -y /tmp/${RPM_NAME}'"
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ЗАПУСК:${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}alt-hardening-scanner${NC}        # сканирование (без root)"
echo -e "  ${BOLD}sudo alt-hardening-scanner${NC}   # + применение настроек"
echo ""
echo -e "  ${YELLOW}⚠ GRUB-параметры (8 из 25):${NC}  вступят в силу после перезагрузки"
echo -e "  ${GREEN}✓ Sysctl-параметры (17 из 25):${NC} активны немедленно без перезагрузки"
echo ""
