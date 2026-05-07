# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

CLI tool to analyze PCAP files containing VoIP traffic. For each call found, it extracts and exports:
- The full SIP trace (signaling)
- The RTP media streams (audio)
- A CSV index file (`index.csv`) with columns: `call_id`, `request_user`, `directory`

Each call is saved in its own subdirectory under the output path, named after the Call-ID or a sanitized slug of it.

## Stack

- **Language**: Python 3
- **PCAP parsing**: `tshark` subprocess (system binary) — filters packets natively before Python sees them
- **SIP dissection**: raw byte parsing of UDP payload after tshark filters with `-Y sip`
- **RTP extraction**: tshark `-Y rtp -w -` pipe → scapy `PcapReader` → route by SDP-discovered endpoints
- **Output formats**: plain-text SIP trace (`sip_trace.txt`, one message per block), per-SSRC PCAP files (`rtp_<ssrc>.pcap`) opened with Wireshark

## Critical constraint: files up to 44 GB

**Never load the file into memory.** All reading is done via streaming:
- tshark is launched as a subprocess with `-w -` (write pcap to stdout)
- Python reads the pipe through `scapy.utils.PcapReader(proc.stdout)` — one packet at a time
- Two separate passes: Pass 1 = SIP only (small), Pass 2 = RTP only (large)
- SIP trace files are opened/written/closed per packet to avoid hitting OS file-handle limits
- RTP `PcapWriter` handles are kept open (with `sync=False`) and closed at end of Pass 2

## Architecture

```
analise_pcap/
├── main.py              # CLI (argparse): single-pass default, --two-pass, --sip-only
├── analyzer.py          # Single-pass analyze(): combined_stream → process_sip/rtp_pkt
├── pcap_reader.py       # sip_stream(), rtp_stream(), combined_stream() via tshark pipe
├── sip_parser.py        # Parse raw SIP bytes → call_id, request_user, sdp_endpoints, rtpmap
├── sip_extractor.py     # process_sip_pkt() + extract_calls() (two-pass wrapper)
├── rtp_extractor.py     # process_rtp_pkt() + extract_rtp() (two-pass wrapper)
├── audio_decoder.py     # G.711/G.729/G.722 decode + WavWriter/FfmpegWriter
├── exporter.py          # write_index_csv()
└── models.py            # Call dataclass (includes rtpmap field)
```

**Data flow — single-pass (default):**
```
tshark -Y "sip or rtp" -w - │ combined_stream() → SIP? → process_sip_pkt()
                                                → RTP? → process_rtp_pkt()
                                                       → exporter (index.csv)
```

**Data flow — two-pass (`--two-pass`):**
```
tshark -Y sip -w - │ sip_stream() → extract_calls() → {endpoint_map, calls} ┐
                                                                               ├→ exporter
tshark -Y rtp -w - │ rtp_stream() → extract_rtp(endpoint_map) ───────────────┘
```

## CLI Usage

```bash
python main.py <file.pcap> --output ./output
```

Output structure:
```
output/
├── index.csv
└── <call-id-slug>/
    ├── sip_trace.txt
    └── rtp_<ssrc>.pcap   # one file per SSRC, valid PCAP openable in Wireshark
```

## Key Design Rules

- **Call-ID** is the primary key for grouping all SIP messages and RTP streams.
- **`request_user`** = user part of the INVITE Request-URI (e.g., `1234` from `INVITE sip:1234@example.com`). Updated from the first INVITE seen for each Call-ID.
- Directory names are filesystem-safe slugs: `re.sub(r'[^\w\-]', '_', call_id)[:100]`. Collisions resolved by appending `_2`, `_3`, etc.
- RTP endpoint correlation: SDP `c=` line provides IP, `m=audio <port>` provides port. Both `(src_ip, src_port)` and `(dst_ip, dst_port)` are checked against `endpoint_map`.
- Unknown RTP (no matching SDP seen yet) is silently skipped — not written to disk.
- SSRC is extracted manually from RTP header bytes 8–11 (big-endian uint32).
- **Audio decoding** (`audio_decoder.make_writer()`): resolution order: (1) G.711 PCMU/PCMA pure-Python — uses `audioop` on Python ≤ 3.12, lookup tables on 3.13+; (2) dynamic PT from `call.rtpmap` matched against G.711 or ffmpeg tables; (3) static ffmpeg PTs — PT 9 = G.722 (`-f g722`), PT 18 = G.729 (`-f g729`). `FfmpegWriter` pipes raw payloads to `ffmpeg stdin` incrementally — no buffering. Packets written in arrival order (no jitter buffer).
- **Per SSRC stream output**: `rtp_<ssrc>.pcap` always; `rtp_<ssrc>.wav` when codec is G.711 (no deps), G.722 or G.729 (requires `ffmpeg` in PATH).

## Dependencies

```bash
pip install -r requirements.txt   # installs scapy
```

System dependency: `tshark` — `brew install wireshark` (macOS) or `apt install tshark` (Linux).
