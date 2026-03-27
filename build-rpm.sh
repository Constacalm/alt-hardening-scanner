#!/usr/bin/env bash
# =============================================================================
#  build-rpm.sh — Сборка ALT Hardening Scanner в .rpm
#  Поддерживаемые дистрибутивы: ALT Linux (ALT РС 11), Fedora, RHEL-совместимые
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
#  УСТАНОВКА ГОТОВОГО ПАКЕТА:
#    sudo rpm -i src-tauri/target/release/bundle/rpm/*.rpm
#    # или через менеджер пакетов:
#    sudo apt-get install ./src-tauri/target/release/bundle/rpm/*.rpm   # ALT Linux
#    sudo dnf install     ./src-tauri/target/release/bundle/rpm/*.rpm   # Fedora
#
#  ЗАПУСК ПОСЛЕ УСТАНОВКИ:
#    alt-hardening-scanner             # сканирование (без root)
#    sudo alt-hardening-scanner        # + применение настроек
# =============================================================================
set -euo pipefail

# ── Цвета и вспомогательные функции ──────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()    { echo -e "${BLUE}[STEP]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
banner()  {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  ALT Hardening Scanner — сборка RPM${NC}"
    echo -e "${BLUE}  РД ФСТЭК «Безопасная настройка ОС Linux» 25.12.2022${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

banner

# ── Шаг 1: Определяем дистрибутив ────────────────────────────────────────────
step "Шаг 1/5 — Определение дистрибутива..."

DISTRO="unknown"
PKG_MGR="unknown"

if [ -f /etc/altlinux-release ] || grep -qi "alt" /etc/os-release 2>/dev/null; then
    DISTRO="altlinux"
    PKG_MGR="apt-get"
    info "Обнаружен: ALT Linux"
elif [ -f /etc/fedora-release ]; then
    DISTRO="fedora"
    PKG_MGR="dnf"
    info "Обнаружен: Fedora"
elif [ -f /etc/redhat-release ]; then
    DISTRO="rhel"
    PKG_MGR="dnf"
    info "Обнаружен: RHEL-совместимый"
elif [ -f /etc/debian_version ]; then
    DISTRO="debian"
    PKG_MGR="apt-get"
    info "Обнаружен: Debian/Ubuntu"
else
    warn "Дистрибутив не определён — используем apt-get"
fi

# ── Шаг 2: Проверка Rust toolchain ────────────────────────────────────────────
step "Шаг 2/5 — Проверка Rust toolchain..."

if ! command -v cargo &>/dev/null; then
    warn "Rust не найден. Устанавливаю через rustup..."
    # Официальный установщик rustup — безопасен, используется на всех платформах
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # Загружаем переменные окружения Rust в текущую сессию
    source "${HOME}/.cargo/env"
    info "Rust $(rustc --version) установлен"
else
    info "Rust уже установлен: $(rustc --version)"
fi

# Убеждаемся, что cargo доступен в PATH (нужно после первой установки)
source "${HOME}/.cargo/env" 2>/dev/null || true

# ── Шаг 3: Проверка системных библиотек ──────────────────────────────────────
step "Шаг 3/5 — Проверка системных библиотек сборки..."
# Tauri требует webkit2gtk (WebView), openssl и rpm-build для упаковки

MISSING_PKGS=()

# Проверяем наличие пакета через rpm (работает на ALT, Fedora, RHEL)
pkg_check_rpm() {
    local pkg="$1"
    if ! rpm -q "$pkg" &>/dev/null; then
        MISSING_PKGS+=("$pkg")
        warn "  Не найден: $pkg"
    else
        info "  Найден: $pkg"
    fi
}

# Проверяем через наличие .pc файла (более универсально)
pkg_check_pc() {
    local pkg="$1"
    local pc_name="${2:-$1}"
    if ! pkg-config --exists "$pc_name" 2>/dev/null; then
        MISSING_PKGS+=("$pkg")
        warn "  Не найден pkg-config для: $pc_name (пакет: $pkg)"
    else
        info "  Найден: $pkg ($(pkg-config --modversion "$pc_name" 2>/dev/null || echo 'ok'))"
    fi
}

if [ "$DISTRO" = "altlinux" ]; then
    # ALT Linux — пакеты webkit2gtk3, libsoup
    pkg_check_rpm "webkit2gtk3-devel"
    pkg_check_rpm "openssl-devel"
    pkg_check_rpm "rpm-build"
    pkg_check_rpm "gcc"
    pkg_check_rpm "pkg-config"
    # libappindicator — опциональный, нужен для трей-иконки
    rpm -q "libappindicator-gtk3-devel" &>/dev/null || \
        warn "  libappindicator-gtk3-devel отсутствует (трей-иконка недоступна, не критично)"
elif [ "$DISTRO" = "fedora" ] || [ "$DISTRO" = "rhel" ]; then
    # Fedora / RHEL — webkit2gtk4.0
    pkg_check_rpm "webkit2gtk4.0-devel"
    pkg_check_rpm "openssl-devel"
    pkg_check_rpm "rpm-build"
    pkg_check_rpm "gcc"
    pkg_check_rpm "pkg-config"
elif [ "$DISTRO" = "debian" ]; then
    # Debian/Ubuntu — для справки, RPM пакет всё равно можно собрать
    pkg_check_pc "libwebkit2gtk-4.1-dev" "webkit2gtk-4.1"
    pkg_check_pc "libssl-dev" "openssl"
    if ! command -v rpmbuild &>/dev/null; then
        MISSING_PKGS+=("rpm")
    fi
fi

# Устанавливаем недостающие пакеты
if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    warn "Отсутствуют пакеты: ${MISSING_PKGS[*]}"
    warn "Установка потребует прав sudo."
    read -rp "  Установить автоматически? [y/N] " answer
    if [[ "${answer,,}" == "y" ]]; then
        sudo "$PKG_MGR" install -y "${MISSING_PKGS[@]}" \
            || error "Не удалось установить зависимости. Установите вручную и повторите."
        info "Зависимости установлены."
    else
        echo ""
        echo -e "${YELLOW}  Установите вручную и запустите скрипт снова:${NC}"
        echo -e "  sudo ${PKG_MGR} install ${MISSING_PKGS[*]}"
        echo ""
        error "Сборка прервана — отсутствуют зависимости."
    fi
else
    info "Все системные зависимости в наличии."
fi

# ── Шаг 4: Tauri CLI ──────────────────────────────────────────────────────────
step "Шаг 4/5 — Проверка Tauri CLI..."

if ! cargo tauri --version &>/dev/null 2>&1; then
    info "Tauri CLI не найден. Устанавливаю tauri-cli v2..."
    # cargo-tauri — официальный CLI для сборки Tauri-приложений
    cargo install tauri-cli --version "^2" --locked
    info "Tauri CLI установлен: $(cargo tauri --version)"
else
    info "Tauri CLI уже установлен: $(cargo tauri --version)"
fi

# ── Шаг 5: Сборка RPM ────────────────────────────────────────────────────────
step "Шаг 5/5 — Сборка RPM-пакета (это займёт несколько минут)..."
echo ""
info "  cargo tauri build --bundles rpm"
info "  Лог сохраняется в: /tmp/tauri-build.log"
echo ""

# Переходим в src-tauri — там находится Cargo.toml и tauri.conf.json
cd src-tauri

# --bundles rpm — собираем только RPM, без deb/appimage (быстрее)
# 2>&1 | tee — одновременно выводим и сохраняем лог
cargo tauri build --bundles rpm 2>&1 | tee /tmp/tauri-build.log

cd ..

# ── Поиск и проверка результата ──────────────────────────────────────────────
echo ""
info "Поиск собранного RPM..."

RPM_FILE=$(find src-tauri/target/release/bundle/rpm -name "*.rpm" 2>/dev/null | head -1)

if [ -z "${RPM_FILE}" ]; then
    echo ""
    error "RPM-файл не найден после сборки.\n  Проверьте лог: /tmp/tauri-build.log\n  Последние строки:\n$(tail -20 /tmp/tauri-build.log)"
fi

# ── Итог ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✅ СБОРКА ЗАВЕРШЕНА УСПЕШНО${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  📦 RPM-файл:"
echo -e "     ${RPM_FILE}"
echo ""

# Показываем размер и мета-информацию пакета
ls -lh "${RPM_FILE}"
echo ""
echo -e "  Содержимое пакета:"
rpm -qpl "${RPM_FILE}" 2>/dev/null | sed 's/^/    /' || true
echo ""

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  УСТАНОВКА:${NC}"
echo ""
echo -e "  # Через rpm (универсальный):"
echo -e "  sudo rpm -i ${RPM_FILE}"
echo ""
echo -e "  # Через apt-rpm (ALT Linux — разрешает зависимости):"
echo -e "  sudo apt-get install ./${RPM_FILE}"
echo ""
echo -e "  # Через dnf (Fedora — разрешает зависимости):"
echo -e "  sudo dnf install ./${RPM_FILE}"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ЗАПУСК ПОСЛЕ УСТАНОВКИ:${NC}"
echo ""
echo -e "  alt-hardening-scanner              # сканирование (без root)"
echo -e "  sudo alt-hardening-scanner         # + применение настроек"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
