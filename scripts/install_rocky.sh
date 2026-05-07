#!/usr/bin/env bash
set -euo pipefail

# ── Detecta versão do Rocky Linux ────────────────────────────────────────────
if [ ! -f /etc/os-release ]; then
    echo "ERRO: /etc/os-release não encontrado. Este script é para Rocky Linux 8 ou 9."
    exit 1
fi
. /etc/os-release
OS_VERSION="${VERSION_ID%%.*}"   # "8.9" → "8",  "9.3" → "9"

case "$OS_VERSION" in
    8)
        BANNER="Rocky Linux 8"
        POWERTOOLS_REPO="powertools"
        PYTHON_PKG="python39 python39-devel"
        PYTHON_BIN="python3.9"
        ;;
    9)
        BANNER="Rocky Linux 9"
        POWERTOOLS_REPO="crb"
        PYTHON_PKG="python3 python3-devel"
        PYTHON_BIN="python3"
        ;;
    *)
        echo "AVISO: Rocky Linux $OS_VERSION não testado. Prosseguindo como RL9..."
        BANNER="Rocky Linux $OS_VERSION"
        POWERTOOLS_REPO="crb"
        PYTHON_PKG="python3 python3-devel"
        PYTHON_BIN="python3"
        ;;
esac

echo "╔══════════════════════════════════════════╗"
printf  "║  analise_pcap — instalação %-14s║\n" "$BANNER"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Permissão root necessária para dnf ───────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERRO: execute com sudo ou como root."
    echo "  sudo bash $0"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
INSTALL_DIR="$(pwd)"

# ── 1. Repositórios extras ────────────────────────────────────────────────────
echo "[1/5] Habilitando repositórios extras..."

dnf install -y epel-release
dnf config-manager --set-enabled "$POWERTOOLS_REPO" 2>/dev/null \
    || echo "       $POWERTOOLS_REPO já habilitado ou não encontrado — continuando"

# ── 2. tshark ─────────────────────────────────────────────────────────────────
echo "[2/5] Instalando wireshark-cli (tshark)..."
dnf install -y wireshark-cli
echo "       $(tshark --version | head -1)"

# ── 3. ffmpeg (opcional — necessário para G.729 / G.722) ─────────────────────
echo "[3/5] Instalando ffmpeg..."
FFMPEG_OK=false

if [ "$OS_VERSION" = "8" ]; then
    # ffmpeg está disponível no EPEL 8
    if dnf install -y ffmpeg 2>/dev/null; then
        FFMPEG_OK=true
    fi
else
    # RL9: ffmpeg requer RPM Fusion (não está no EPEL 9)
    RPM_FUSION="https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-${OS_VERSION}.noarch.rpm"
    if dnf install -y "$RPM_FUSION" 2>/dev/null && dnf install -y ffmpeg 2>/dev/null; then
        FFMPEG_OK=true
    fi
fi

if [ "$FFMPEG_OK" = true ]; then
    echo "       $(ffmpeg -version 2>&1 | head -1)"
else
    echo "       AVISO: ffmpeg não instalado."
    echo "              G.729 e G.722 não serão decodificados para WAV."
    echo "              Instale manualmente depois: https://rpmfusion.org"
fi

# ── 4. Python ─────────────────────────────────────────────────────────────────
echo "[4/5] Instalando Python ($PYTHON_PKG)..."
# shellcheck disable=SC2086
dnf install -y $PYTHON_PKG
"$PYTHON_BIN" -m ensurepip --upgrade 2>/dev/null || true
"$PYTHON_BIN" -m pip install --upgrade pip --quiet
echo "       $("$PYTHON_BIN" --version)"

# ── 5. Virtualenv + dependências Python ──────────────────────────────────────
echo "[5/5] Criando virtualenv e instalando dependências Python..."
cd "$INSTALL_DIR"
"$PYTHON_BIN" -m venv .venv

su -s /bin/bash "$REAL_USER" -c "
    set -e
    cd '$INSTALL_DIR'
    source .venv/bin/activate
    pip install --upgrade pip --quiet
    pip install -r requirements.txt
"

chown -R "$REAL_USER":"$(id -gn "$REAL_USER")" .venv

# ── Concluído ─────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Instalação concluída ($BANNER)."
echo ""
echo " Para usar:"
echo "   source .venv/bin/activate"
echo "   python main.py <arquivo.pcap> -o ./output"
echo "════════════════════════════════════════════"
