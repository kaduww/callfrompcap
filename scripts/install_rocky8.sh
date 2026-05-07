#!/usr/bin/env bash
set -euo pipefail

echo "╔══════════════════════════════════════════╗"
echo "║  analise_pcap — instalação Rocky Linux 8 ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Permissão root necessária para dnf ───────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERRO: execute com sudo ou como root."
    echo "  sudo bash $0"
    exit 1
fi

# Preserva o usuário que chamou sudo para criar o venv como não-root
REAL_USER="${SUDO_USER:-$USER}"
INSTALL_DIR="$(pwd)"

# ── Repositório PowerTools (exigido por algumas dependências do wireshark) ───
echo "[1/4] Habilitando repositório PowerTools..."
dnf config-manager --set-enabled powertools 2>/dev/null || \
dnf config-manager --set-enabled crb 2>/dev/null || \
echo "       PowerTools/CRB já habilitado ou não encontrado — continuando"

# ── tshark ────────────────────────────────────────────────────────────────────
echo "[2/4] Instalando wireshark-cli (tshark)..."
dnf install -y wireshark-cli
echo "       tshark: $(tshark --version | head -1)"

# ── Python 3.9 ───────────────────────────────────────────────────────────────
echo "[3/4] Instalando Python 3.9..."
dnf install -y python39 python39-devel

# Garante que pip está disponível para python3.9
python3.9 -m ensurepip --upgrade 2>/dev/null || true
python3.9 -m pip install --upgrade pip --quiet

# ── Virtualenv + dependências Python ─────────────────────────────────────────
echo "[4/4] Criando virtualenv e instalando dependências Python..."
cd "$INSTALL_DIR"
python3.9 -m venv .venv

# Instala as dependências como o usuário real (não root)
su -s /bin/bash "$REAL_USER" -c "
    set -e
    cd '$INSTALL_DIR'
    source .venv/bin/activate
    pip install --upgrade pip --quiet
    pip install -r requirements.txt
"

# Ajusta permissões do venv para o usuário real
chown -R "$REAL_USER":"$(id -gn "$REAL_USER")" .venv

echo ""
echo "════════════════════════════════════════════"
echo " Instalação concluída."
echo ""
echo " Para usar:"
echo "   source .venv/bin/activate"
echo "   python main.py <arquivo.pcap> -o ./output"
echo "════════════════════════════════════════════"
