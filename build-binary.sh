#!/usr/bin/env bash
# =============================================================================
#  build-binary.sh — Сборка ТОЛЬКО бинарника (без RPM-упаковки)
#
#  Результат: один исполняемый файл
#    ./alt-hardening-scanner  (в корне репозитория)
#
#  Размер: ~4–10 МБ (lto + strip + opt-level=s)
#  Зависимости на целевой машине: libwebkit2gtk, libgtk+3 (уже есть в ALT p11)
#
#  ОТЛИЧИЕ ОТ build-rpm.sh:
#    build-rpm.sh     → .rpm пакет (устанавливается через apt-get/rpm)
#    build-binary.sh  → голый бинарь (копируешь и запускаешь вручную)
#
#  ИСПОЛЬЗОВАНИЕ:
#    bash build-binary.sh
#
#  ЗАПУСК:
#    ./alt-hardening-scanner
#    sudo ./alt-hardening-scanner     # для применения настроек
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}${BOLD}  ALT Hardening Scanner — Сборка бинарника${NC}"
echo -e "${CYAN}  Результат: один исполняемый файл, без установки${NC}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Все артефакты сборки — в каталоге проекта, не в /tmp
export CARGO_TARGET_DIR="${SCRIPT_DIR}/src-tauri/target"

# ── Rust toolchain ────────────────────────────────────────────────────────────
step "Проверка Rust..."
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env" 2>/dev/null || true

if ! command -v cargo &>/dev/null; then
    error "cargo не найден.\n\
  ALT Linux: sudo apt-get install -y rust\n\
  (пакет 'cargo' отдельно не существует — cargo входит в пакет 'rust')\n\
  Без интернета: sudo apt-get install -y rust\n\
  С интернетом:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi
info "cargo: $(cargo --version)"

RUSTC_MINOR=$(rustc --version | grep -oP '1\.\K[0-9]+' | head -1 || echo "0")
if [ "${RUSTC_MINOR}" -lt 77 ]; then
    error "Нужен rustc ≥ 1.77. Текущий: $(rustc --version)\n  sudo apt-get install -y rust"
fi

# ── Системные библиотеки ──────────────────────────────────────────────────────
step "Проверка системных библиотек..."

# Реальные имена пакетов в ALT Linux (проверено на p11/Sisyphus)
MISSING=()
declare -A PKG_CHECK=(
    ["libwebkit2gtk-devel"]="libwebkit2gtk-devel"
    ["libssl-devel"]="libssl-devel"
    ["libgtk+3-devel"]="libgtk+3-devel"
    ["pkg-config"]="pkg-config"
    ["gcc"]="gcc"
    ["gcc-c++"]="gcc-c++"
)

for pkg in "${!PKG_CHECK[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
        ok "  ✓ $pkg"
    else
        warn "  ✗ $pkg"
        MISSING+=("$pkg")
    fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo ""
    warn "Не найдены: ${MISSING[*]}"
    read -rp "  Установить? [y/N]: " ans
    if [[ "${ans,,}" == "y" ]]; then
        sudo apt-get install -y "${MISSING[@]}" \
            || error "apt-get завершился с ошибкой. Попробуйте: sudo apt-get update"
    else
        error "Установите зависимости:\n  sudo apt-get install -y ${MISSING[*]}"
    fi
fi

# ── Сборка ────────────────────────────────────────────────────────────────────
step "Сборка release-бинарника..."
echo ""
info "cargo build --release  (артефакты: ${CARGO_TARGET_DIR})"
echo ""

export WEBKIT_DISABLE_DMABUF_RENDERER=1

cd src-tauri
cargo build --release 2>&1 \
    || error "Сборка провалилась. Запустите с RUST_BACKTRACE=1 для деталей."
cd ..

# ── Копируем бинарь в корень проекта ─────────────────────────────────────────
BINARY="${CARGO_TARGET_DIR}/release/alt-hardening-scanner"
[ -f "${BINARY}" ] || error "Бинарь не найден: ${BINARY}"

cp "${BINARY}" ./alt-hardening-scanner
chmod +x ./alt-hardening-scanner

SIZE=$(du -sh ./alt-hardening-scanner | cut -f1)

echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Бинарник готов${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Файл:${NC}    ./alt-hardening-scanner"
echo -e "  ${BOLD}Размер:${NC}  ${SIZE}"
echo ""
echo -e "  ${CYAN}Зависимости (должны быть на целевой машине):${NC}"
ldd ./alt-hardening-scanner 2>/dev/null | grep -E "webkit|gtk|ssl|glib" | sed 's/^/    /' || true
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ЗАПУСК:${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}./alt-hardening-scanner${NC}        # сканирование (без root)"
echo -e "  ${BOLD}sudo ./alt-hardening-scanner${NC}   # + применение настроек"
echo ""
echo -e "  ${BOLD}# Скопировать на другую машину:${NC}"
echo -e "  scp ./alt-hardening-scanner user@target:~/alt-hardening-scanner"
echo -e "  ssh user@target 'sudo ~/alt-hardening-scanner'"
echo ""
echo -e "  ${YELLOW}Требуется ALT Linux p11 / Sisyphus с webkit2gtk и gtk3${NC}"
echo -e "  ${YELLOW}(входят в базовую установку рабочей станции)${NC}"
echo ""
