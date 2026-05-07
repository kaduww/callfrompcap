#!/usr/bin/env bash
set -euo pipefail

GO_MIN_MINOR=22   # requer Go 1.22+

# ── Detecta distro e versão ───────────────────────────────────────────────────
if [ ! -f /etc/os-release ]; then
    echo "ERRO: /etc/os-release não encontrado. Este script é para Ubuntu ou Debian."
    exit 1
fi
. /etc/os-release

case "${ID:-}" in
    ubuntu)
        case "${VERSION_ID}" in
            22.04|24.04|26.04) ;;
            *) echo "AVISO: Ubuntu ${VERSION_ID} não testado. Prosseguindo mesmo assim..." ;;
        esac
        ;;
    debian)
        case "${VERSION_ID}" in
            11|12|13) ;;
            *) echo "AVISO: Debian ${VERSION_ID} não testado. Prosseguindo mesmo assim..." ;;
        esac
        ;;
    *)
        echo "ERRO: sistema detectado como '${ID:-desconhecido}'. Este script é para Ubuntu ou Debian."
        exit 1
        ;;
esac

DISTRO_LABEL="${ID^} ${VERSION_ID} (${VERSION_CODENAME:-?})"

echo "╔══════════════════════════════════════════╗"
printf  "║  callfrompcap — %-26s║\n" "$DISTRO_LABEL"
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
echo "[1/3] Atualizando cache apt e instalando dependências base..."
apt-get update -qq
apt-get install -y curl tar ca-certificates

# ── 2. Go ─────────────────────────────────────────────────────────────────────
echo "[2/3] Verificando Go..."

go_meets_minimum() {
    command -v go &>/dev/null || return 1
    local minor
    minor=$(go version | grep -oE 'go1\.[0-9]+' | grep -oE '[0-9]+$')
    [ "${minor:-0}" -ge "$GO_MIN_MINOR" ]
}

if go_meets_minimum; then
    echo "       $(go version) — OK"
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
if [ "${ID}" = "ubuntu" ]; then
    # Ubuntu: ffmpeg está no repositório universe
    if ! grep -qr "^deb.*universe" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        if command -v add-apt-repository &>/dev/null; then
            add-apt-repository -y universe
        else
            apt-get install -y software-properties-common
            add-apt-repository -y universe
        fi
        apt-get update -qq
    fi
fi
# Debian: ffmpeg está no repositório main — nenhuma fonte extra necessária
if apt-get install -y ffmpeg 2>/dev/null; then
    echo "       $(ffmpeg -version 2>&1 | head -1)"
else
    echo "       AVISO: ffmpeg não instalado."
    echo "              G.729 e G.722 não serão decodificados para WAV."
fi

# ── Compilar ──────────────────────────────────────────────────────────────────
echo ""
echo "Compilando callfrompcap..."
cd "$PROJECT_DIR"
su -s /bin/bash "$REAL_USER" -c "cd '$PROJECT_DIR' && /usr/local/go/bin/go build -o callfrompcap ."
chown "$REAL_USER":"$(id -gn "$REAL_USER")" "$PROJECT_DIR/callfrompcap"
echo "   Binário gerado: $PROJECT_DIR/callfrompcap"

# ── Concluído ─────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Instalação concluída ($DISTRO_LABEL)."
echo ""
echo " Para usar:"
echo "   ./callfrompcap <arquivo.pcap> -o ./output"
echo ""
echo " NOTA: abra um novo terminal ou execute:"
echo "   source /etc/profile.d/go.sh"
echo "════════════════════════════════════════════"
