#!/usr/bin/env bash
set -euo pipefail

echo "╔══════════════════════════════════════════╗"
echo "║  analise_pcap — instalação macOS         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Homebrew ─────────────────────────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
    echo "[1/4] Instalando Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Adiciona brew ao PATH da sessão atual (Apple Silicon / Intel)
    if [ -f /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        eval "$(/usr/local/bin/brew shellenv)"
    fi
else
    echo "[1/4] Homebrew já instalado — pulando"
fi

# ── tshark ────────────────────────────────────────────────────────────────────
if ! command -v tshark &>/dev/null; then
    echo "[2/4] Instalando wireshark (inclui tshark)..."
    brew install wireshark
else
    echo "[2/4] tshark já instalado ($(tshark --version | head -1)) — pulando"
fi

# ── Python 3 ─────────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[3/4] Instalando Python 3..."
    brew install python
else
    echo "[3/4] Python $(python3 --version) já instalado — pulando"
fi

# ── Virtualenv + dependências Python ─────────────────────────────────────────
echo "[4/4] Criando virtualenv e instalando dependências Python..."
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt

echo ""
echo "════════════════════════════════════════════"
echo " Instalação concluída."
echo ""
echo " Para usar:"
echo "   source .venv/bin/activate"
echo "   python main.py <arquivo.pcap> -o ./output"
echo "════════════════════════════════════════════"
