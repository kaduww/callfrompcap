# callfrompcap

Ferramenta de linha de comando para analisar capturas de tráfego VoIP em formato PCAP. Para cada chamada encontrada, exporta o trace SIP, os streams RTP, o áudio decodificado e gera um índice CSV.

Escrita em Go — **binário único, sem dependências de runtime**. Lê o arquivo PCAP diretamente, sem precisar de tshark, Python ou qualquer biblioteca instalada no sistema. Testado com arquivos com ** mais de 40 GB** com uso de memória constante.

## O que é gerado

```
output/
├── index.csv
└── <call-id>/
    ├── sip_trace.txt               ← diálogo SIP completo
    ├── rtp_caller_a1b2c3d4.pcap    ← stream RTP do caller (abrível no Wireshark)
    ├── rtp_caller_a1b2c3d4.wav     ← áudio do caller decodificado
    ├── rtp_callee_e5f6a7b8.pcap    ← stream RTP do callee
    ├── rtp_callee_e5f6a7b8.wav     ← áudio do callee decodificado
    └── rtp_mixed.wav               ← streams mixados (somente com --mix-audio)
```

**`index.csv`**
```
call_id,request_user,final_code,final_reason,duration,mos,jitter_ms,loss_pct,media_flow,directory
abc-123@pbx,1001,200,OK,142,4.32,1.25,0.00,both,/output/abc-123_pbx
def-456@pbx,1002,486,Busy Here,,,,,,/output/def-456_pbx
ghi-789@pbx,1003,200,OK,37,3.71,8.43,1.20,caller-only,/output/ghi-789_pbx
```

| Coluna | Descrição |
|---|---|
| `call_id` | Call-ID SIP |
| `request_user` | Usuário do Request-URI do INVITE (número discado) |
| `final_code` | Último código de resposta final SIP (≥ 200) |
| `final_reason` | Reason phrase do código final |
| `duration` | Duração em segundos (de 200 OK ao INVITE até resposta ao BYE); vazio se a chamada não foi atendida |
| `mos` | MOS mínimo entre os streams (E-model simplificado, mesma fórmula do Wireshark); vazio se sem RTP |
| `jitter_ms` | Jitter médio em ms (RFC 3550); vazio se sem RTP |
| `loss_pct` | Perda de pacotes RTP média em %; vazio se sem RTP |
| `media_flow` | Direção do fluxo de mídia: `both`, `caller-only`, `callee-only`, ou vazio se sem RTP |
| `directory` | Caminho absoluto do diretório da chamada |

## Requisitos

| Dependência | Obrigatório | Finalidade |
|---|---|---|
| nenhuma | — | análise SIP + RTP + G.711 funcionam sem nada instalado |
| `ffmpeg` | opcional | decodificação de G.729 e G.722 para WAV; mixagem com `--mix-audio` |

> **Formato suportado:** `.pcap` (captura com link type Ethernet, Linux cooked ou raw IPv4). Arquivos `.pcapng` precisam ser convertidos antes: `tshark -r entrada.pcapng -w saida.pcap`

## Instalação

### Compilar a partir do código-fonte

Requer [Go 1.22+](https://go.dev/dl/).

```bash
git clone <repositorio>
cd callfrompcap
go build -o callfrompcap .
```

### Compilar binário estático (Linux)

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o callfrompcap .
```

O binário resultante funciona em qualquer Linux x86-64 sem nenhuma lib instalada.

### Cross-compile para Windows (a partir de macOS/Linux)

```bash
GOOS=windows GOARCH=amd64 go build -o callfrompcap.exe .
```

### ffmpeg (opcional — somente para G.729 / G.722)

```bash
# macOS
brew install ffmpeg

# Ubuntu / Debian
sudo apt-get install ffmpeg

# Rocky Linux 9
sudo dnf install https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm
sudo dnf install ffmpeg

# Windows
winget install Gyan.FFmpeg
```

## Uso

```bash
# Análise completa (SIP + RTP + WAV)
./callfrompcap captura.pcap -o ./output

# Múltiplos arquivos (captura fracionada pelo tcpdump)
./callfrompcap captura001.pcap captura002.pcap captura003.pcap -o ./output

# Glob — todos os .pcap de um diretório
./callfrompcap /capturas/*.pcap -o ./output

# Somente traces SIP (mais rápido, sem extrair RTP)
./callfrompcap captura.pcap -o ./output --sip-only

# Somente chamadas INVITE com resposta 200
./callfrompcap captura.pcap -o ./output --method INVITE --sip-code 200

# Chamadas que falharam por ocupado ou sem resposta
./callfrompcap captura.pcap -o ./output --method INVITE --sip-code 486,480,408

# Análise completa com áudio mixado por chamada
./callfrompcap captura.pcap -o ./output --mix-audio
```

### Opções

| Argumento | Padrão | Descrição |
|---|---|---|
| `pcap` | — | Um ou mais arquivos `.pcap`, ou glob (`*.pcap`) |
| `-o`, `--output` | `./output` | Diretório de saída |
| `--sip-only` | — | Extrai apenas SIP, ignora RTP |
| `--two-pass` | — | Lê o arquivo duas vezes (SIP depois RTP) |
| `--method` | todas | Métodos SIP iniciais a incluir, separados por vírgula |
| `--sip-code` | todos | Códigos de resposta final a incluir no CSV, separados por vírgula |
| `--mix-audio` | — | Mixa todos os streams WAV de cada chamada em `rtp_mixed.wav` (requer ffmpeg) |
| `--quiet` | — | Suprime eventos por linha; exibe somente a barra de progresso |

### `--method`

Filtra quais diálogos são processados pelo método da **primeira requisição** do Call-ID.

```bash
--method INVITE            # somente chamadas de voz
--method REGISTER          # somente registros
--method INVITE,SUBSCRIBE  # chamadas e subscriptions
```

Valores case-insensitive. Padrão: todos os métodos.

### `--sip-code`

Filtra quais linhas entram no `index.csv` pelo **último código de resposta final** (≥ 200) visto para cada chamada. Os diretórios e `sip_trace.txt` são gerados normalmente; só a linha do CSV é omitida.

```bash
--sip-code 200             # somente chamadas completadas
--sip-code 200,486         # completadas ou ocupado
--sip-code 404,480,486,503 # vários tipos de falha
```

Chamadas sem resposta final aparecem com `final_code` vazio; `--sip-code` as exclui do CSV.

### `--mix-audio`

Após decodificar todos os streams, mixa os arquivos `rtp_*.wav` de cada chamada em um único `rtp_mixed.wav` usando `ffmpeg amix`. Útil para ouvir a conversa completa sem precisar abrir os dois lados separadamente.

```bash
./callfrompcap captura.pcap -o ./output --mix-audio
```

- Requer `ffmpeg` instalado no PATH
- Sem efeito se a chamada tiver menos de dois streams WAV
- Os arquivos individuais (`rtp_a1b2c3d4.wav`, etc.) são mantidos
- Não compatível com `--sip-only` (nenhum WAV é gerado nesse modo)

### Modos de operação

#### Passe único (padrão)

Lê o arquivo **uma vez**. Processa SIP e RTP na ordem de chegada.

```
arquivo.pcap → leitura direta em Go
    ├─ pacote SIP → parse (Call-ID, SDP, rtpmap) → sip_trace.txt
    └─ pacote RTP → roteamento por mapa de endpoints → .pcap + .wav
```

#### Dois-passes (`--two-pass`)

Lê o arquivo **duas vezes**: primeiro extrai todos os SIPs para montar o mapa de endpoints, depois processa o RTP. Útil quando a captura começa no meio de chamadas ativas.

#### Somente SIP (`--sip-only`)

Lê o arquivo uma vez ignorando pacotes RTP. Ideal para inspecionar sinalização rapidamente.

#### Comparativo

| Modo | Leituras | Gera RTP/WAV | Quando usar |
|---|---|---|---|
| padrão | 1× | sim | uso geral |
| `--two-pass` | 2× | sim | captura iniciada mid-call |
| `--sip-only` | 1× | não | inspecionar sinalização |

## Múltiplos arquivos (captura fracionada)

O tcpdump com `-C` ou `-G` divide a captura em vários arquivos menores. A ferramenta os processa como se fossem um único arquivo — o contexto de chamadas (Call-ID, endpoints SDP, streams RTP) é mantido entre arquivos.

```bash
# tcpdump gera: captura001.pcap, captura002.pcap, ...
./callfrompcap /capturas/*.pcap -o ./output
```

Os arquivos são ordenados alfabeticamente antes do processamento. O padrão de nome gerado pelo tcpdump (`capturaNNN.pcap`) já garante a ordem cronológica correta com ordenação lexicográfica.

Em `--two-pass`, todos os arquivos são lidos duas vezes: primeiro para extrair o SIP e construir o mapa de endpoints, depois para extrair o RTP.

## Capturas grandes (> 1 GB)

Em capturas com muitas chamadas simultâneas, o limite padrão de file descriptors pode ser insuficiente.

**macOS / Linux:**
```bash
ulimit -n 65536
./callfrompcap captura.pcap -o ./output
```

**Windows:** não tem limite de file descriptors por processo; nenhuma configuração necessária.

### Estimativa de RAM

| Chamadas no PCAP | RAM necessária |
|---|---|
| até 1.000 | < 100 MB |
| 1.000 – 10.000 | ~200 MB |
| acima de 10.000 | ~500 MB |

O tamanho do arquivo (GB) **não afeta** o consumo de memória — o processamento é inteiramente em streaming, um pacote por vez.

## Como funciona

O arquivo nunca é carregado em memória. O `PcapReader` lê um pacote por vez com buffer de 1 MB; para cada frame é feito o parse manual do cabeçalho Ethernet → IP → UDP sem nenhuma biblioteca externa.

### Passe único (padrão)

```
arquivo.pcap
    │
    └─ PcapReader.Next() → parseUDP()
                │
                ├─ payload[0] & 0xC0 == 0x80?  →  RTP v2
                │                                   ├─ lookup no mapa de endpoints
                │                                   ├─ identifica caller / callee pelo SDP
                │                                   ├─ grava rtp_<role>_<ssrc>.pcap
                │                                   ├─ decodifica → rtp_<role>_<ssrc>.wav
                │                                   │  (G.711 nativo; G.729/G.722 via ffmpeg)
                │                                   └─ acumula jitter (RFC 3550) + seq loss
                │
                └─ payload[0] printable ASCII?  →  SIP
                                                    ├─ parse (Call-ID, CSeq, método, SDP, rtpmap)
                                                    ├─ atualiza mapa IP:porta → chamada
                                                    ├─ rastreia código de resposta final
                                                    ├─ registra ConnectedAt (200 OK INVITE)
                                                    ├─ registra DisconnectedAt (resp. BYE)
                                                    └─ grava sip_trace.txt
```

### Dois-passes (`--two-pass`)

```
arquivo.pcap
    ├─ 1ª leitura → somente SIP → constrói mapa de endpoints
    └─ 2ª leitura → somente RTP → roteia pelo mapa → .pcap e .wav
```

## Estrutura do código

| Arquivo | Responsabilidade |
|---|---|
| `main.go` | CLI: flags, validação, roteia para os três modos |
| `analyzer.go` | Passe único: lê o arquivo uma vez, processa SIP e RTP |
| `pcap.go` | `PcapReader` + `PcapWriter` — leitura e escrita de `.pcap` puro Go |
| `parse.go` | `parseUDP()` — extrai IP/UDP dos bytes brutos do frame |
| `sipparser.go` | `parseSIP()` → `SIPInfo` (Call-ID, CSeq, método, código, SDP, rtpmap) |
| `sipextractor.go` | `processSIPPkt()`, `extractCalls()`, `_SipFileCache` (LRU 500 handles) |
| `rtpextractor.go` | `processRTPPkt()`, `extractRTP()` — roteamento, escrita e coleta de métricas por SSRC |
| `rtpstats.go` | `rtpStreamState` — jitter RFC 3550, perda de pacotes, MOS (E-model Wireshark) |
| `audio.go` | Tabelas G.711, `WavWriter`, `FfmpegWriter`, `makeWriter()`, `mixCallsAudio()` |
| `exporter.go` | `writeCSV()` — filtro por `--sip-code`, cálculo de duração e métricas RTP |
| `model.go` | `Call`, `Endpoint`, `CodecInfo`, `rtpKey` |
| `progress.go` | Status ao vivo com percentual de progresso (linha `\r` atualizada a cada 2 s) |
