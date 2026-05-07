# analise_pcap

Ferramenta de linha de comando para analisar capturas de tráfego VoIP em formato PCAP. Para cada chamada encontrada, exporta o trace SIP, os streams RTP e gera um índice CSV. Projetada para operar em modo streaming — suporta arquivos de **44 GB ou mais** sem carregar nada na memória.

## O que é gerado

```
output/
├── index.csv                      ← índice de todas as chamadas
└── <call-id>/
    ├── sip_trace.txt              ← diálogo SIP completo
    ├── rtp_a1b2c3d4.pcap          ← stream RTP (abrível no Wireshark)
    └── rtp_a1b2c3d4.wav           ← áudio decodificado (G.711 PCMU / PCMA)
```

**`index.csv`**
```
call_id,request_user,directory
abc-123@pbx,1001,/output/abc-123_pbx
```

## Requisitos

| Dependência | Versão mínima | Instalação |
|---|---|---|
| Python | 3.8+ | — |
| tshark | qualquer | ver instalação abaixo |
| scapy | 2.5.0+ | `pip install scapy` |
| ffmpeg | qualquer | opcional — necessário para G.729 e G.722 |

> **Áudio (WAV):** G.711 PCMU/PCMA são decodificados nativamente sem dependências extras. G.729 e G.722 requerem `ffmpeg` instalado no sistema. Outros codecs (Opus, AMR, etc.) geram apenas o `.pcap`.

## Instalação

### macOS

```bash
bash install_macos.sh
```

Instala Homebrew (se ausente), `wireshark` (tshark), `ffmpeg`, Python 3 e cria um virtualenv com as dependências.

### Ubuntu 22.04 / 24.04 / 26.04

```bash
sudo bash install_ubuntu.sh
```

Detecta a versão automaticamente. Instala `tshark`, `ffmpeg` (repositório universe) e `python3-venv`. O prompt interativo do tshark sobre captura de pacotes é respondido automaticamente via debconf.

### Rocky Linux 8 / 9

```bash
sudo bash install_rocky.sh
```

Detecta a versão automaticamente e instala `wireshark-cli`, ffmpeg e Python:

| | Rocky Linux 8 | Rocky Linux 9 |
|---|---|---|
| Python | `python39` | `python3` |
| PowerTools | `powertools` | `crb` |
| ffmpeg | EPEL 8 | RPM Fusion |

> **ffmpeg no RL9:** requer [RPM Fusion](https://rpmfusion.org). O script tenta instalar automaticamente; se falhar, apenas G.729/G.722 não serão decodificados para WAV — o restante funciona normalmente.

### Windows 10 / 11

Abra o PowerShell e execute:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install_windows.ps1
```

O script solicita elevação automaticamente. Instala via **winget**: Wireshark (tshark), ffmpeg e Python 3.11.

> **Requisito:** Windows 10 1709+ ou Windows 11 com [App Installer](https://aka.ms/getwinget) (winget).

### Manual

```bash
# macOS
brew install wireshark ffmpeg

# Ubuntu
sudo apt-get install -y tshark ffmpeg python3 python3-venv python3-pip

# Rocky Linux 8
sudo dnf install epel-release wireshark-cli python39 ffmpeg

# Rocky Linux 9
sudo dnf install epel-release wireshark-cli python3
sudo dnf install https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm
sudo dnf install ffmpeg

# Windows (PowerShell)
winget install WiresharkFoundation.Wireshark
winget install Gyan.FFmpeg
winget install Python.Python.3.11

# Dependências Python (macOS / Linux)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Dependências Python (Windows PowerShell)
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

## Uso

### macOS / Linux

```bash
source .venv/bin/activate

# Análise completa (SIP + RTP + WAV)
python main.py captura.pcap -o ./output

# Somente traces SIP (ignora RTP — mais rápido)
python main.py captura.pcap -o ./output --sip-only
```

### Windows

**PowerShell:**
```powershell
.\.venv\Scripts\Activate.ps1

# Análise completa (SIP + RTP + WAV)
python main.py captura.pcap -o .\output

# Somente traces SIP
python main.py captura.pcap -o .\output --sip-only
```

**Prompt de Comando (cmd.exe):**
```cmd
.\.venv\Scripts\activate.bat

python main.py captura.pcap -o .\output
```

> **Dica Windows:** caminhos com espaços devem ser colocados entre aspas:
> `python main.py "C:\Users\carlos\Capturas\arquivo pcap.pcap" -o .\output`

### Opções

| Argumento | Padrão | Descrição |
|---|---|---|
| `pcap` | — | Caminho para o arquivo `.pcap` ou `.pcapng` |
| `-o`, `--output` | `./output` | Diretório de saída |
| `--sip-only` | — | Extrai apenas SIP, ignora RTP (mais rápido) |
| `--two-pass` | — | Lê o arquivo duas vezes (SIP depois RTP); ver abaixo |

### Modos de operação

#### Passe único (padrão)

Lê o arquivo **uma vez** com filtro `sip or rtp`. Processa SIP e RTP na ordem de chegada — metade do I/O em relação ao modo dois-passes.

```
tshark -Y "sip or rtp"  →  SIP? → grava sip_trace.txt, atualiza mapa de endpoints
                         →  RTP? → roteia pelo mapa, grava .pcap e .wav
```

#### Dois-passes (`--two-pass`)

Lê o arquivo **duas vezes**: primeiro SIP, depois RTP. Útil quando a captura começa no meio de chamadas ativas e é necessário inspecionar separadamente o que foi encontrado em cada passe.

```
tshark -Y sip  →  constrói mapa de endpoints (Call-ID → IP:porta RTP)
tshark -Y rtp  →  roteia cada pacote pelo mapa → .pcap e .wav
```

> **Quando usar `--two-pass`:** captura iniciada com chamadas já em curso (RTP visível antes do SDP). Em passe único, esses pacotes iniciais são descartados da mesma forma — a diferença é operacional, não de resultado.

#### Somente SIP (`--sip-only`)

Lê o arquivo uma vez filtrando apenas SIP. Não gera arquivos RTP. Ideal para inspecionar a sinalização rapidamente sem aguardar a extração de mídia.

```
tshark -Y sip  →  sip_trace.txt por chamada  →  index.csv
```

#### Comparativo

| Modo | Leituras do arquivo | Gera RTP/WAV | Quando usar |
|---|---|---|---|
| padrão | 1× | sim | uso geral |
| `--two-pass` | 2× | sim | captura iniciada mid-call |
| `--sip-only` | 1× | não | inspecionar sinalização |

## Capturas grandes (> 1 GB)

Em capturas com muitas chamadas simultâneas, o limite padrão de file descriptors pode ser insuficiente.

**macOS / Linux** — execute antes de rodar:
```bash
ulimit -n 65536
```

**Windows** — não tem limite de file descriptors por processo; nenhuma configuração necessária.

### Estimativa de RAM

| Chamadas no PCAP | RAM necessária |
|---|---|
| até 1.000 | 512 MB |
| 1.000 – 10.000 | 1 GB |
| acima de 10.000 | 2 GB |

O tamanho do arquivo (GB) **não afeta** o consumo de memória — o processamento é inteiramente em streaming via `tshark`.

## Como funciona

O arquivo nunca é carregado em memória. O `tshark` atua como filtro e escreve pacotes na stdout em formato PCAP; o `scapy.PcapReader` lê da pipe um pacote por vez.

### Passe único (padrão)

```
arquivo.pcap
    │
    └─ tshark -Y "sip or rtp" -w -
                │
                ├─ pacote SIP ──→ parse SIP (Call-ID, SDP)
                │                 ├─ cria diretório da chamada
                │                 ├─ atualiza mapa IP:porta → chamada
                │                 └─ grava sip_trace.txt
                │
                └─ pacote RTP ──→ lookup no mapa de endpoints
                                  ├─ grava rtp_<ssrc>.pcap
                                  └─ decodifica e grava rtp_<ssrc>.wav
                                     (G.711 nativo; G.729/G.722 via ffmpeg)
```

### Dois-passes (`--two-pass`)

```
arquivo.pcap
    │
    ├─ tshark -Y sip -w -  ──→  constrói mapa de endpoints
    │
    └─ tshark -Y rtp -w -  ──→  roteia RTP pelo mapa → .pcap e .wav
```

## Estrutura do código

| Arquivo | Responsabilidade |
|---|---|
| `main.py` | CLI: roteia para `analyzer`, `extract_calls`/`extract_rtp` ou `--sip-only` |
| `analyzer.py` | Passe único: `analyze()` combina SIP e RTP em uma leitura |
| `pcap_reader.py` | `sip_stream()`, `rtp_stream()`, `combined_stream()` via pipe do tshark |
| `sip_parser.py` | Parse de bytes SIP brutos (Call-ID, Request-URI, SDP, rtpmap) |
| `sip_extractor.py` | `process_sip_pkt()` + `extract_calls()` (wrapper dois-passes) |
| `rtp_extractor.py` | `process_rtp_pkt()` + `extract_rtp()` (wrapper dois-passes) |
| `audio_decoder.py` | Decode G.711 (nativo), G.729/G.722 (ffmpeg pipe), `WavWriter`, `FfmpegWriter` |
| `exporter.py` | Gera `index.csv` |
| `models.py` | Dataclass `Call` |
