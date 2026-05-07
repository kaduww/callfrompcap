#!/usr/bin/env bash
set -euo pipefail

# ── Detecta Ubuntu e versão ───────────────────────────────────────────────────
if [ ! -f /etc/os-release ]; then
    echo "ERRO: /etc/os-release não encontrado. Este script é para Ubuntu."
    exit 1
fi
. /etc/os-release

if [ "${ID:-}" != "ubuntu" ]; then
    echo "ERRO: sistema detectado como '$ID'. Este script é para Ubuntu."
    exit 1
fi

UBUNTU_VERSION="${VERSION_ID}"   # ex: "22.04", "24.04", "26.04"
CODENAME="${VERSION_CODENAME:-desconhecido}"

case "$UBUNTU_VERSION" in
    22.04) ;;   # Jammy  — Python 3.10
    24.04) ;;   # Noble  — Python 3.12
    26.04) ;;   # Q*     — Python 3.14+ (não lançado ainda; pacotes compatíveis)
    *)
        echo "AVISO: Ubuntu $UBUNTU_VERSION não testado. Prosseguindo mesmo assim..."
        ;;
esac

echo "╔══════════════════════════════════════════╗"
printf  "║  analise_pcap — Ubuntu %-18s║\n" "$UBUNTU_VERSION ($CODENAME)"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Permissão root necessária para apt ───────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERRO: execute com sudo ou como root."
    echo "  sudo bash $0"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
INSTALL_DIR="$(pwd)"

# ── 1. Atualiza cache apt ─────────────────────────────────────────────────────
echo "[1/5] Atualizando cache apt..."
apt-get update -qq

# ── 2. tshark ─────────────────────────────────────────────────────────────────
echo "[2/5] Instalando tshark..."

# Responde à pergunta interativa do debconf sem exibir prompt:
# "Should non-superusers be able to capture packets?" → false
# (leitura de arquivo pcap não exige permissão de captura)
echo "wireshark-common wireshark-common/install-setuid boolean false" \
    | debconf-set-selections

DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
echo "       $(tshark --version | head -1)"

# ── 3. ffmpeg (opcional — necessário para G.729 / G.722) ─────────────────────
echo "[3/5] Instalando ffmpeg..."
# ffmpeg está no repositório universe; habilita se necessário
if ! grep -qr "^deb.*universe" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    add-apt-repository -y universe
    apt-get update -qq
fi

if apt-get install -y ffmpeg 2>/dev/null; then
    echo "       $(ffmpeg -version 2>&1 | head -1)"
else
    echo "       AVISO: ffmpeg não instalado."
    echo "              G.729 e G.722 não serão decodificados para WAV."
fi

# ── 4. Python 3 + venv ────────────────────────────────────────────────────────
echo "[4/5] Instalando Python 3 e dependências de venv..."
apt-get install -y python3 python3-venv python3-pip
echo "       $(python3 --version)"

# ── 5. Virtualenv + dependências Python ──────────────────────────────────────
echo "[5/5] Criando virtualenv e instalando dependências Python..."
cd "$INSTALL_DIR"
python3 -m venv .venv

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
echo " Instalação concluída (Ubuntu $UBUNTU_VERSION)."
echo ""
echo " Para usar:"
echo "   source .venv/bin/activate"
echo "   python main.py <arquivo.pcap> -o ./output"
echo "════════════════════════════════════════════"
