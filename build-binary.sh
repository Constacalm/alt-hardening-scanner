#!/usr/bin/env bash
# =============================================================================
#  build-binary.sh — Сборка ТОЛЬКО бинарника (без RPM-упаковки)
#
#  Результат: один исполняемый файл
#    src-tauri/target/release/alt-hardening-scanner
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
#    # Бинарь будет в: ./alt-hardening-scanner  (в корне репозитория)
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
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}${BOLD}  ALT Hardening Scanner — Сборка бинарника${NC}"
echo -e "${CYAN}  Результат: один исполняемый файл, без установки${NC}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ── Rust toolchain ────────────────────────────────────────────────────────────
step "Проверка Rust..."
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env" 2>/dev/null || true
command -v cargo &>/dev/null || error "cargo не найден.\n  ALT Linux: sudo apt-get install -y rust cargo\n  или: curl https://sh.rustup.rs | sh"
info "cargo: $(cargo --version)"

# ── Tauri CLI ─────────────────────────────────────────────────────────────────
step "Проверка Tauri CLI..."
if ! cargo tauri --version &>/dev/null 2>&1; then
    info "Устанавливаю tauri-cli v2 (5–15 мин при первом запуске)..."
    cargo install tauri-cli --version "^2" --locked
fi
ok "Tauri CLI: $(cargo tauri --version 2>/dev/null)"

# ── Системные библиотеки ──────────────────────────────────────────────────────
step "Проверка системных библиотек..."

MISSING=()
for pkg in libwebkit2gtk-devel openssl-devel pkg-config gcc; do
    if ! rpm -q "$pkg" &>/dev/null; then
        MISSING+=("$pkg")
    fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo -e "${YELLOW}  Не найдены: ${MISSING[*]}${NC}"
    read -rp "  Установить? [y/N]: " ans
    [[ "${ans,,}" == "y" ]] && sudo apt-get install -y "${MISSING[@]}" \
        || error "Установите зависимости: sudo apt-get install -y ${MISSING[*]}"
fi

# ── Сборка ────────────────────────────────────────────────────────────────────
step "Сборка release-бинарника..."
echo ""
info "cargo tauri build"
echo ""

export WEBKIT_DISABLE_DMABUF_RENDERER=1

cd src-tauri
cargo tauri build 2>&1 || error "Сборка провалилась. Запустите с RUST_LOG=error для деталей."
cd ..

# ── Копируем бинарь в корень проекта ─────────────────────────────────────────
BINARY="src-tauri/target/release/alt-hardening-scanner"

[ -f "${BINARY}" ] || error "Бинарь не найден: ${BINARY}"

cp "${BINARY}" ./alt-hardening-scanner
chmod +x ./alt-hardening-scanner

SIZE=$(du -sh ./alt-hardening-scanner | cut -f1)

echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✅ Бинарник готов${NC}"
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
echo -e "  ${YELLOW}⚠ Требуется ALT Linux p11 / Sisyphus с webkit2gtk и gtk3${NC}"
echo -e "  ${YELLOW}  (входят в базовую установку рабочей станции)${NC}"
echo ""
