# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

CLI tool to analyze PCAP files containing VoIP traffic. For each call found, it extracts and exports:
- Full SIP trace (`sip_trace.txt`) — one block per message, in arrival order
- Per-SSRC RTP streams (`rtp_<ssrc>.pcap`) — valid PCAP openable in Wireshark
- Decoded audio (`rtp_<ssrc>.wav`) — G.711 natively; G.729/G.722 via optional ffmpeg
- CSV index (`index.csv`) — columns: `call_id`, `request_user`, `final_code`, `final_reason`, `directory`

## Stack

- **Language**: Go 1.22 — single static binary, zero runtime dependencies
- **PCAP reading**: pure Go reader (`pcap.go`) — reads `.pcap` directly; pcapng not supported (clear error message)
- **Packet parsing**: manual Ethernet/SLL/raw-IP → IPv4 → UDP extraction (`parse.go`)
- **SIP dissection**: raw string parsing of UDP payload (`sipparser.go`)
- **RTP routing**: SDP-discovered (IP, port) endpoint map → per-SSRC pcap writers (`rtpextractor.go`)
- **Audio decode**: G.711 PCMU/PCMA via pure Go lookup tables; G.729/G.722 via `ffmpeg` subprocess if available (`audio.go`)

## Build

```bash
go build -o callfrompcap .        # local binary
CGO_ENABLED=0 go build -o callfrompcap .   # fully static (Linux)
```

No external Go dependencies — `go mod tidy` not required after cloning.

## Architecture

```
callfrompcap/
├── main.go          # CLI flags: -o, --sip-only, --two-pass, --method, --sip-code
├── analyzer.go      # analyze(): single-pass, routes SIP/RTP in one file read
├── pcap.go          # PcapReader (1 MB bufio) + PcapWriter (64 KB bufio)
├── parse.go         # parseUDP() — handles DLT 1/113/228/12
├── sipparser.go     # parseSIP() → SIPInfo{CallID, Method, StatusCode, StatusReason, …}
├── sipextractor.go  # processSIPPkt(), extractCalls(), _SipFileCache (LRU 500 handles)
├── rtpextractor.go  # processRTPPkt(), extractRTP()
├── audio.go         # ulawTable/alawTable, WavWriter, FfmpegWriter, makeWriter()
├── exporter.go      # writeCSV() — codeFilter applied here, not during processing
├── model.go         # Call{FinalCode, FinalReason, …}, Endpoint, CodecInfo
└── progress.go      # Progress — \r status line, updated every 2s / 10k packets
```

**Data flow — single-pass (default):**
```
pcap file → PcapReader.Next() → parseUDP()
    ├─ byte[0] & 0xC0 == 0x80  →  RTP  → processRTPPkt()
    └─ byte[0] printable ASCII →  SIP  → processSIPPkt() → updates FinalCode/FinalReason
                                                          → writeCSV() (with codeFilter)
```

**Data flow — two-pass (`--two-pass`):**
```
pcap file → extractCalls(methodFilter) → {endpointMap, calls}
pcap file → extractRTP(endpointMap)
            → writeCSV(calls, codeFilter)
```

## CLI

```bash
./callfrompcap <file.pcap> [options]

-o / --output <dir>    output directory (default: ./output)
--sip-only             SIP traces only, no RTP
--two-pass             read file twice (SIP then RTP)
--method <csv>         initial SIP methods to process, e.g. INVITE or INVITE,REGISTER
--sip-code <csv>       final response codes to include in index.csv, e.g. 200 or 200,486
--rtp-idle-seconds <n> close RTP streams after n s of capture-time inactivity (default 60, 0 = never)
```

## Key Design Rules

- **Call-ID** is the primary key for all SIP messages and RTP streams.
- **`request_user`** = user part of the INVITE Request-URI (e.g., `1234` from `INVITE sip:1234@example.com`).
- **`final_code` / `final_reason`**: updated on every SIP response with code ≥ 200; reflects the last final response seen (handles retries and re-INVITEs correctly).
- **`--method` filter**: acts at call-creation time in `processSIPPkt`. Rejected Call-IDs are tracked in `rejectedIDs` to skip all subsequent packets (responses, BYE, etc.) for the same dialog.
- **`--sip-code` filter**: acts only in `writeCSV`. All directories and `sip_trace.txt` files are always created; only CSV rows are filtered. This preserves the streaming architecture (you can't know the final code until the call ends).
- Directory names: `[^A-Za-z0-9_\-]` → `_`, max 100 chars, collisions resolved with `_2`, `_3`, etc.
- RTP endpoint correlation: SDP `c=` (IP) + `m=audio <port>` → `Endpoint{IP, Port}`. Both src and dst checked against `endpointMap`.
- Unknown RTP (no prior SDP seen) is silently skipped.
- SSRC: extracted from RTP header bytes 8–11 (big-endian uint32), formatted as `rtp_0a1b2c3d.pcap`.
- **Audio decode priority** (`makeWriter`): (1) static G.711 PT 0/8; (2) dynamic PT from rtpmap matching PCMU/PCMA/G722/G729; (3) static ffmpeg PTs 9=G.722, 18=G.729.
- **RTP-timestamp gap fill**: silence (zero PCM) is inserted whenever the RTP timestamp advances more than the previous packet's duration — bridging DTX silence-suppression gaps and lost packets. Without it the timeline is compressed and playback sounds accelerated. A single gap is capped at `maxGapSeconds` (30 s) to guard against garbage timestamps.
  - **G.711** (`WavWriter.writePacket`): streamed. The RTP timestamp unit is one 8 kHz sample, so deltas map 1:1 onto output samples; gap silence is written inline as packets arrive.
  - **G.722/G.729** (`FfmpegWriter`): buffered. Encoded payloads + RTP timestamps are collected, then on `close` the stream is split into gap-free segments, each decoded by one ffmpeg call, and the final WAV is assembled with PCM silence between segments. `payloadTicks` maps payload length to 8 kHz ticks per codec (G.722 = 1 byte/tick @ 16 kHz output; G.729 = 80 ticks per 10-byte frame @ 8 kHz output). Buffering is bounded by RTP idle eviction and call-end finalization.
- **`_SipFileCache`**: LRU of 500 open `sip_trace.txt` file handles — avoids open/close per packet, which is the dominant bottleneck for SIP-heavy captures.
- **RTP stream idle eviction** (`sweepIdleStreams` in `rtpextractor.go`): every 10 000 RTP packets, finalizes and closes pcap/wav writers for streams whose `lastSeen` (capture timestamp of last packet) is older than `--rtp-idle-seconds`, or whose call has seen a BYE more than 1 s in the past. Closed `rtpKey`s are tracked in `closedStreams`; late packets for the same SSRC are dropped, and new streams for a call past its BYE+grace are refused. Bounds peak memory in long captures with many short calls.
- **pcapng**: not supported — returns an error with the tshark conversion command.

## Optional dependency

`ffmpeg` in PATH enables WAV output for G.729 and G.722. Without it, those calls produce only `.pcap`.
