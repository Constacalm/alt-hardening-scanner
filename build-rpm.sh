#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build-rpm.sh — сборка ALT Hardening Scanner в .rpm на ALT Linux / Fedora
# Запускать из корня проекта: bash build-rpm.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Цвета ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Зависимости ────────────────────────────────────────────────────────────
info "Проверка зависимостей сборки..."

check_cmd() {
    command -v "$1" &>/dev/null || error "$1 не найден. Установите: $2"
}

check_cmd cargo     "curl https://sh.rustup.rs | sh"
check_cmd rustc     "curl https://sh.rustup.rs | sh"
check_cmd rpmbuild  "apt-get install rpm-build  (ALT: apt-get install rpm-build)"

# Tauri CLI
if ! cargo tauri --version &>/dev/null; then
    info "Устанавливаю tauri-cli..."
    cargo install tauri-cli --version "^2"
fi

# ── Системные dev-библиотеки (ALT Linux / RPM-based) ──────────────────────
info "Проверка системных библиотек..."

MISSING_PKGS=()

pkg_exists() {
    rpm -q "$1" &>/dev/null || MISSING_PKGS+=("$1")
}

pkg_exists "webkit2gtk3-devel"
pkg_exists "libappindicator-gtk3-devel"
pkg_exists "openssl-devel"
pkg_exists "libsoup3-devel"

if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    warn "Не хватает пакетов: ${MISSING_PKGS[*]}"
    warn "Установка (нужен sudo или root):"
    echo "  sudo apt-get install ${MISSING_PKGS[*]}"
    read -rp "Установить автоматически? [y/N] " answer
    if [[ "${answer,,}" == "y" ]]; then
        sudo apt-get install -y "${MISSING_PKGS[@]}"
    else
        error "Прерываю сборку из-за отсутствующих зависимостей."
    fi
fi

# ── Сборка ──────────────────────────────────────────────────────────────────
info "Запускаю cargo tauri build --bundles rpm..."
cd src-tauri

cargo tauri build --bundles rpm 2>&1 | tee /tmp/tauri-build.log

cd ..

# ── Поиск результата ────────────────────────────────────────────────────────
RPM_FILE=$(find src-tauri/target/release/bundle/rpm -name "*.rpm" 2>/dev/null | head -1)

if [ -z "${RPM_FILE}" ]; then
    error "RPM-файл не найден. Лог: /tmp/tauri-build.log"
fi

info "RPM собран: ${RPM_FILE}"
ls -lh "${RPM_FILE}"

# ── Опциональная проверка пакета ────────────────────────────────────────────
info "Содержимое пакета:"
rpm -qpl "${RPM_FILE}" 2>/dev/null || true

echo ""
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN} Установка:${NC}"
echo -e "  sudo rpm -i ${RPM_FILE}"
echo -e "  # или через dnf/apt-rpm:"
echo -e "  sudo dnf install ${RPM_FILE}"
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
