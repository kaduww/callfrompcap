#!/usr/bin/env bash
set -euo pipefail

GO_MIN_MINOR=22   # requer Go 1.22+

echo "╔══════════════════════════════════════════╗"
echo "║  callfrompcap — instalação macOS         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Homebrew ──────────────────────────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
    echo "[1/3] Instalando Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if [ -f /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        eval "$(/usr/local/bin/brew shellenv)"
    fi
else
    echo "[1/3] Homebrew já instalado — pulando"
fi

# ── Go ────────────────────────────────────────────────────────────────────────
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
    echo "       Instalando Go via Homebrew..."
    brew install go
    echo "       $(go version)"
fi

# ── ffmpeg (opcional — G.729 / G.722) ─────────────────────────────────────────
echo "[3/3] Verificando ffmpeg (opcional)..."
if command -v ffmpeg &>/dev/null; then
    echo "       ffmpeg já instalado — pulando"
else
    if brew install ffmpeg 2>/dev/null; then
        echo "       $(ffmpeg -version 2>&1 | head -1)"
    else
        echo "       AVISO: ffmpeg não instalado."
        echo "              G.729 e G.722 não serão decodificados para WAV."
    fi
fi

# ── Compilar ──────────────────────────────────────────────────────────────────
echo ""
echo "Compilando callfrompcap..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"
go build -o callfrompcap .
echo "   Binário gerado: $PROJECT_DIR/callfrompcap"

# ── Concluído ─────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Instalação concluída."
echo ""
echo " Para usar:"
echo "   ./callfrompcap <arquivo.pcap> -o ./output"
echo "════════════════════════════════════════════"
