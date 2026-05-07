#!/usr/bin/env bash
set -euo pipefail

GO_MIN_MINOR=22   # requer Go 1.22+

# ── Detecta versão do Rocky Linux ────────────────────────────────────────────
if [ ! -f /etc/os-release ]; then
    echo "ERRO: /etc/os-release não encontrado. Este script é para Rocky Linux 8 ou 9."
    exit 1
fi
. /etc/os-release
OS_VERSION="${VERSION_ID%%.*}"   # "8.9" → "8",  "9.3" → "9"

case "$OS_VERSION" in
    8) BANNER="Rocky Linux 8" ;;
    9) BANNER="Rocky Linux 9" ;;
    *)
        echo "AVISO: Rocky Linux $OS_VERSION não testado. Prosseguindo como RL9..."
        BANNER="Rocky Linux $OS_VERSION"
        ;;
esac

echo "╔══════════════════════════════════════════╗"
printf  "║  callfrompcap — instalação %-14s║\n" "$BANNER"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Permissão root ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERRO: execute com sudo ou como root."
    echo "  sudo bash $0"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ── 1. Dependências base ──────────────────────────────────────────────────────
echo "[1/3] Instalando dependências base..."
dnf install -y curl tar ca-certificates

# ── 2. Go ─────────────────────────────────────────────────────────────────────
echo "[2/3] Verificando Go..."

go_meets_minimum() {
    command -v go &>/dev/null || /usr/local/go/bin/go version &>/dev/null || return 1
    local bin="go"
    command -v go &>/dev/null || bin="/usr/local/go/bin/go"
    local minor
    minor=$("$bin" version | grep -oE 'go1\.[0-9]+' | grep -oE '[0-9]+$')
    [ "${minor:-0}" -ge "$GO_MIN_MINOR" ]
}

if go_meets_minimum; then
    echo "       $(go version 2>/dev/null || /usr/local/go/bin/go version) — OK"
else
    echo "       Baixando Go da golang.org..."
    GO_VER=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    TARBALL="${GO_VER}.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/${TARBALL}" -o "/tmp/${TARBALL}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${TARBALL}"
    rm -f "/tmp/${TARBALL}"
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
    export PATH="$PATH:/usr/local/go/bin"
    echo "       $(go version)"
fi

# ── 3. ffmpeg (opcional — G.729 / G.722) ─────────────────────────────────────
echo "[3/3] Instalando ffmpeg (opcional)..."
FFMPEG_OK=false

if [ "$OS_VERSION" = "8" ]; then
    dnf install -y epel-release
    if dnf install -y ffmpeg 2>/dev/null; then
        FFMPEG_OK=true
    fi
else
    dnf install -y epel-release
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
    echo "              Instale manualmente: https://rpmfusion.org"
fi

# ── Compilar ──────────────────────────────────────────────────────────────────
echo ""
echo "Compilando callfrompcap..."
cd "$PROJECT_DIR"
export PATH="$PATH:/usr/local/go/bin"
su -s /bin/bash "$REAL_USER" -c "export PATH=\$PATH:/usr/local/go/bin && cd '$PROJECT_DIR' && go build -o callfrompcap ."
chown "$REAL_USER":"$(id -gn "$REAL_USER")" "$PROJECT_DIR/callfrompcap"
echo "   Binário gerado: $PROJECT_DIR/callfrompcap"

# ── Concluído ─────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Instalação concluída ($BANNER)."
echo ""
echo " Para usar:"
echo "   ./callfrompcap <arquivo.pcap> -o ./output"
echo ""
echo " NOTA: abra um novo terminal ou execute:"
echo "   source /etc/profile.d/go.sh"
echo "════════════════════════════════════════════"
