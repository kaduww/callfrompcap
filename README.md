# callfrompcap

Command-line tool for analyzing VoIP traffic captures in PCAP format. For each call found, it exports the SIP trace, RTP streams, decoded audio, and generates a CSV index.

Written in Go — **single binary, no runtime dependencies**. Reads the PCAP file directly without requiring tshark, Python, or any system-installed library. Tested with files **over 40 GB** with constant memory usage.

## What is generated

```
output/
├── index.csv
└── <call-id>/
    ├── sip_trace.txt               ← full SIP dialog
    ├── rtp_caller_a1b2c3d4.pcap    ← caller RTP stream (openable in Wireshark)
    ├── rtp_caller_a1b2c3d4.wav     ← decoded caller audio
    ├── rtp_callee_e5f6a7b8.pcap    ← callee RTP stream
    ├── rtp_callee_e5f6a7b8.wav     ← decoded callee audio
    └── rtp_mixed.wav               ← mixed streams (only with --mix-audio)
```

**`index.csv`**
```
call_id,from_user,request_user,src_ip,dst_ip,final_code,final_reason,duration,mos,jitter_ms,loss_pct,media_flow,directory
abc-123@pbx,1001,1002,192.168.1.10,192.168.1.1,200,OK,142,4.32,1.25,0.00,both,/output/abc-123_pbx
def-456@pbx,1003,1004,192.168.1.11,192.168.1.1,486,Busy Here,,,,,,/output/def-456_pbx
ghi-789@pbx,1005,1006,192.168.1.12,192.168.1.1,200,OK,37,3.71,8.43,1.20,caller-only,/output/ghi-789_pbx
```

| Column | Description |
|---|---|
| `call_id` | SIP Call-ID |
| `from_user` | User part of the From header URI (caller's identity) |
| `request_user` | User part of the INVITE Request-URI (dialed number) |
| `src_ip` | Source IP of the first packet that created the dialog |
| `dst_ip` | Destination IP of the first packet that created the dialog |
| `final_code` | Last final SIP response code (≥ 200) |
| `final_reason` | Reason phrase of the final code |
| `duration` | Duration in seconds (from 200 OK to INVITE until response to BYE); empty if the call was not answered |
| `mos` | Minimum MOS across streams (simplified E-model, same formula as Wireshark); empty if no RTP |
| `jitter_ms` | Average jitter in ms (RFC 3550); empty if no RTP |
| `loss_pct` | Average RTP packet loss in %; empty if no RTP |
| `media_flow` | Media flow direction: `both`, `caller-only`, `callee-only`, or empty if no RTP |
| `directory` | Absolute path to the call directory |

## Requirements

| Dependency | Required | Purpose |
|---|---|---|
| none | — | SIP + RTP + G.711 analysis work with nothing installed |
| `ffmpeg` | optional | G.729 and G.722 decoding to WAV; mixing with `--mix-audio` |

> **Supported format:** `.pcap` (capture with link type Ethernet, Linux cooked, or raw IPv4). `.pcapng` files must be converted first: `tshark -r input.pcapng -w output.pcap`

## Installation

### Build from source

Requires [Go 1.22+](https://go.dev/dl/).

```bash
git clone <repository>
cd callfrompcap
go build -o callfrompcap .
```

### Build static binary (Linux)

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o callfrompcap .
```

The resulting binary works on any x86-64 Linux with no libraries installed.

### Cross-compile for Windows (from macOS/Linux)

```bash
GOOS=windows GOARCH=amd64 go build -o callfrompcap.exe .
```

### ffmpeg (optional — only for G.729 / G.722)

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

## Usage

```bash
# Full analysis (SIP + RTP + WAV)
./callfrompcap capture.pcap -o ./output

# Multiple files (capture split by tcpdump)
./callfrompcap capture001.pcap capture002.pcap capture003.pcap -o ./output

# Glob — all .pcap files in a directory
./callfrompcap /captures/*.pcap -o ./output

# SIP traces only (faster, no RTP extraction)
./callfrompcap capture.pcap -o ./output --sip-only

# Only INVITE calls with 200 response
./callfrompcap capture.pcap -o ./output --method INVITE --sip-code 200

# Calls that failed due to busy or no answer
./callfrompcap capture.pcap -o ./output --method INVITE --sip-code 486,480,408

# Full analysis with mixed audio per call
./callfrompcap capture.pcap -o ./output --mix-audio

# Strip ring-tone from early-media WAVs (e.g. voicemail recordings)
./callfrompcap capture.pcap -o ./output --trim-ring

# WAV only — skip per-SSRC .pcap files
./callfrompcap capture.pcap -o ./output --no-rtp-pcap

# Close idle RTP streams aggressively (low memory; long captures)
./callfrompcap capture.pcap -o ./output --rtp-idle-seconds 30
```

### Options

| Argument | Default | Description |
|---|---|---|
| `pcap` | — | One or more `.pcap` files, or glob (`*.pcap`) |
| `-o`, `--output` | `./output` | Output directory |
| `--sip-only` | — | Extract SIP only, skip RTP |
| `--two-pass` | — | Read the file twice (SIP then RTP) |
| `--method` | all | Initial SIP methods to include, comma-separated |
| `--sip-code` | all | Final response codes to include in CSV, comma-separated |
| `--mix-audio` | — | Mix all WAV streams of each call into `rtp_mixed.wav` (requires ffmpeg) |
| `--trim-ring` | — | Detect and remove ring-tone bursts from early-media audio (G.711 only) |
| `--no-rtp-pcap` | — | Skip per-SSRC RTP `.pcap` files (keep `.wav` only) |
| `--rtp-idle-seconds` | `60` | Close RTP streams after this many seconds of capture-time inactivity (0 = never) |
| `--verbose` | — | Print per-event output; hides the progress bar |

### `--method`

Filters which dialogs are processed based on the **first request method** of the Call-ID.

```bash
--method INVITE            # voice calls only
--method REGISTER          # registrations only
--method INVITE,SUBSCRIBE  # calls and subscriptions
```

Values are case-insensitive. Default: all methods.

### `--sip-code`

Filters which rows appear in `index.csv` based on the **last final response code** (≥ 200) seen for each call. Directories and `sip_trace.txt` are always created; only CSV rows are filtered.

```bash
--sip-code 200             # completed calls only
--sip-code 200,486         # completed or busy
--sip-code 404,480,486,503 # various failure types
```

Calls with no final response appear with an empty `final_code`; `--sip-code` excludes them from the CSV.

### `--mix-audio`

After decoding all streams, mixes the `rtp_*.wav` files of each call into a single `rtp_mixed.wav` using `ffmpeg amix`. Useful for listening to the full conversation without opening both sides separately.

```bash
./callfrompcap capture.pcap -o ./output --mix-audio
```

- Requires `ffmpeg` installed in PATH
- No effect if the call has fewer than two WAV streams
- Individual files (`rtp_a1b2c3d4.wav`, etc.) are preserved
- Not compatible with `--sip-only` (no WAV files are generated in that mode)

### `--trim-ring`

Suppresses ring-tone (ringback) bursts that arrive as early media before the 200 OK. Useful when the callee is a voicemail box: the recording starts with several seconds of ringing before the greeting, and `--trim-ring` removes that prefix while preserving the greeting itself.

```bash
./callfrompcap capture.pcap -o ./output --trim-ring
```

How it works: while the call is not answered (`ConnectedAt == 0`), each RTP frame is buffered together with its RMS energy. When the 200 OK arrives — or when the stream is closed — the buffer is scanned for the characteristic ring-tone cadence (alternating ON bursts of 0.3–3 s with OFF gaps of 0.8–7 s, covering BR/US/EU patterns). Frames belonging to ring cycles are discarded; everything after the last ring-off is written to the WAV.

- Applied only to G.711 (PCMU/PCMA) streams — other codecs are passed through untouched
- No effect on calls without early media (RTP arrives after the 200 OK)
- Safety cap: if more than 30 s of early media accumulates without a 200 OK, the buffer is analyzed and flushed
- With `--verbose`, each trim is logged: `[ring] <Call-ID> <role> ssrc=<hex> trimmed N frames (~X.XXs)`

### `--no-rtp-pcap`

Skips creation of the per-SSRC `rtp_*.pcap` files; only the `.wav` files (plus the SIP trace and `index.csv`) are written. Useful when you only need the decoded audio and want to reduce disk usage.

```bash
./callfrompcap capture.pcap -o ./output --no-rtp-pcap
```

The PCAP writers are never created (not written then deleted), so this also saves I/O time on large captures.

### `--rtp-idle-seconds`

Caps memory usage on long captures by closing RTP stream writers (`.pcap` + `.wav` + jitter/loss state) once they go quiet. After `n` seconds of capture-time inactivity — or once the call's BYE was seen more than 1 s in the past — the stream is finalized, its metrics are recorded onto the call, and its file handles are released.

```bash
./callfrompcap big.pcap -o ./output --rtp-idle-seconds 60   # default
./callfrompcap big.pcap -o ./output --rtp-idle-seconds 30   # more aggressive (low memory)
./callfrompcap big.pcap -o ./output --rtp-idle-seconds 0    # disable idle eviction
```

How it works: every 10 000 RTP packets, the tool sweeps active streams and closes any whose last packet arrived more than `n` seconds ago (capture clock, not wall clock). Closed streams are remembered — any further packets for the same SSRC are silently dropped, so the WAV file is never reopened/truncated. New streams for a call whose BYE is already in the past (plus a 1 s grace) are refused outright.

- Without this, the peak memory footprint scales with **total streams seen in the capture** (each open `WavWriter` holds a 64 KB buffer + file descriptor)
- With this, peak footprint scales with **streams active simultaneously** — typically orders of magnitude smaller
- Tradeoff: very long holds with no RTP (music-on-hold gaps > `n` seconds on the same SSRC) get split prematurely. Raise the value (e.g. `120`) if your traffic does this; set `0` to keep the old behavior

### Operation modes

#### Single-pass (default)

Reads the file **once**. Processes SIP and RTP in arrival order.

```
file.pcap → direct read in Go
    ├─ SIP packet → parse (Call-ID, SDP, rtpmap) → sip_trace.txt
    └─ RTP packet → routing via endpoint map → .pcap + .wav
```

#### Two-pass (`--two-pass`)

Reads the file **twice**: first extracts all SIP to build the endpoint map, then processes RTP. Useful when the capture starts in the middle of active calls.

#### SIP only (`--sip-only`)

Reads the file once ignoring RTP packets. Ideal for quickly inspecting signaling.

#### Comparison

| Mode | Reads | Generates RTP/WAV | When to use |
|---|---|---|---|
| default | 1× | yes | general use |
| `--two-pass` | 2× | yes | capture started mid-call |
| `--sip-only` | 1× | no | inspect signaling |

## Multiple files (split capture)

tcpdump with `-C` or `-G` splits the capture into multiple smaller files. The tool processes them as if they were a single file — call context (Call-ID, SDP endpoints, RTP streams) is maintained across files.

```bash
# tcpdump generates: capture001.pcap, capture002.pcap, ...
./callfrompcap /captures/*.pcap -o ./output
```

Files are sorted alphabetically before processing. The naming pattern generated by tcpdump (`captureNNN.pcap`) already guarantees correct chronological order with lexicographic sorting.

With `--two-pass`, all files are read twice: first to extract SIP and build the endpoint map, then to extract RTP.

## Large captures (> 1 GB)

On captures with many simultaneous calls, the default file descriptor limit may be insufficient.

**macOS / Linux:**
```bash
ulimit -n 65536
./callfrompcap capture.pcap -o ./output
```

**Windows:** has no per-process file descriptor limit; no configuration needed.

### RAM estimate

Each open RTP stream keeps a 64 KB WAV write buffer plus a file descriptor, so peak memory tracks the number of streams that are active **simultaneously** — not the total seen across the whole capture. `--rtp-idle-seconds` (default 60) finalizes and closes streams that go quiet, keeping the working set bounded even on multi-hour captures with hundreds of thousands of short calls.

| Simultaneously active calls | RAM required |
|---|---|
| up to 1,000 | < 100 MB |
| 1,000 – 10,000 | ~200 MB |
| above 10,000 | ~500 MB |

File size (GB) **does not affect** memory usage — processing is entirely streaming, one packet at a time. For very high concurrency, lower `--rtp-idle-seconds` (e.g. `30`) to release idle WAV/pcap handles sooner; set to `0` only if you have spare RAM and want every stream kept open until end-of-file.

## How it works

The file is never loaded into memory. `PcapReader` reads one packet at a time with a 1 MB buffer; for each frame, manual parsing of the Ethernet → IP → UDP headers is done with no external library.

### Single-pass (default)

```
file.pcap
    │
    └─ PcapReader.Next() → parseUDP()
                │
                ├─ payload[0] & 0xC0 == 0x80?  →  RTP v2
                │                                   ├─ lookup in endpoint map
                │                                   ├─ identify caller / callee from SDP
                │                                   ├─ write rtp_<role>_<ssrc>.pcap
                │                                   ├─ decode → rtp_<role>_<ssrc>.wav
                │                                   │  (G.711 natively; G.729/G.722 via ffmpeg)
                │                                   └─ accumulate jitter (RFC 3550) + seq loss
                │
                └─ payload[0] printable ASCII?  →  SIP
                                                    ├─ parse (Call-ID, CSeq, method, SDP, rtpmap)
                                                    ├─ update IP:port → call map
                                                    ├─ track final response code
                                                    ├─ record ConnectedAt (200 OK INVITE)
                                                    ├─ record DisconnectedAt (BYE response)
                                                    └─ write sip_trace.txt
```

### Two-pass (`--two-pass`)

```
file.pcap
    ├─ 1st read → SIP only → build endpoint map
    └─ 2nd read → RTP only → route via map → .pcap and .wav
```

## Code structure

| File | Responsibility |
|---|---|
| `main.go` | CLI: flags, validation, routes to the three modes |
| `analyzer.go` | Single-pass: reads file once, processes SIP and RTP |
| `pcap.go` | `PcapReader` + `PcapWriter` — pure Go PCAP reading and writing |
| `parse.go` | `parseUDP()` — extracts IP/UDP from raw frame bytes |
| `sipparser.go` | `parseSIP()` → `SIPInfo` (Call-ID, CSeq, method, code, SDP, rtpmap) |
| `sipextractor.go` | `processSIPPkt()`, `extractCalls()`, `_SipFileCache` (LRU 500 handles) |
| `rtpextractor.go` | `processRTPPkt()`, `extractRTP()` — routing, writing, and per-SSRC metrics |
| `rtpstats.go` | `rtpStreamState` — RFC 3550 jitter, packet loss, MOS (Wireshark E-model) |
| `audio.go` | G.711 tables, `WavWriter`, `FfmpegWriter`, `makeWriter()`, `mixCallsAudio()`, `RingDetector` (early-media ring-tone trim) |
| `exporter.go` | `writeCSV()` — `--sip-code` filter, duration and RTP metrics calculation |
| `model.go` | `Call`, `Endpoint`, `CodecInfo`, `rtpKey` |
| `progress.go` | Live status with percentage progress (`\r` line updated every 2s) |
