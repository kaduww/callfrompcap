"""
Audio decoding and incremental WAV writing for RTP streams.

G.711 PCMU/PCMA: decoded in pure Python (no external deps).
G.729, G.722 and other ffmpeg-supported codecs: decoded via ffmpeg subprocess pipe.

Codec resolution priority (in make_writer):
  1. G.711 via pure Python
  2. Any codec supported by ffmpeg (requires ffmpeg in PATH)
"""
import array
import shutil
import struct
import subprocess
import wave
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple


# ── G.711 lookup tables (built once at import time) ──────────────────────────

def _build_ulaw_table() -> array.array:
    """Expand all 256 μ-law codes to 16-bit linear PCM (matches CPython audioop)."""
    BIAS = 0x84
    t = array.array('h', [0] * 256)
    for i in range(256):
        u = (~i) & 0xFF
        v = ((u & 0x0F) << 3) + BIAS
        v <<= (u & 0x70) >> 4
        t[i] = (BIAS - v) if (u & 0x80) else (v - BIAS)
    return t


def _build_alaw_table() -> array.array:
    """Expand all 256 A-law codes to 16-bit linear PCM (matches CPython audioop)."""
    t = array.array('h', [0] * 256)
    for i in range(256):
        a = i ^ 0x55
        m = (a & 0x0F) << 4
        exp = (a & 0x70) >> 4
        if exp == 0:
            m += 8
        else:
            m += 0x108
            if exp > 1:
                m <<= exp - 1
        t[i] = m if (a & 0x80) else -m
    return t


_ULAW_TABLE = _build_ulaw_table()
_ALAW_TABLE = _build_alaw_table()


def _table_decode(table: array.array, data: bytes) -> bytes:
    return array.array('h', (table[b] for b in data)).tobytes()


# ── G.711 decoders ────────────────────────────────────────────────────────────

try:
    import audioop as _audioop

    def decode_ulaw(data: bytes) -> bytes:
        return _audioop.ulaw2lin(data, 2)

    def decode_alaw(data: bytes) -> bytes:
        return _audioop.alaw2lin(data, 2)

except ImportError:
    # Python 3.13+ removed audioop
    def decode_ulaw(data: bytes) -> bytes:  # type: ignore[misc]
        return _table_decode(_ULAW_TABLE, data)

    def decode_alaw(data: bytes) -> bytes:  # type: ignore[misc]
        return _table_decode(_ALAW_TABLE, data)


# ── Codec tables ──────────────────────────────────────────────────────────────

# G.711 static PTs: PT -> (codec_name, decode_fn, clock_rate)
_G711_STATIC_PT: Dict[int, Tuple[str, Callable, int]] = {
    0: ('PCMU', decode_ulaw, 8000),
    8: ('PCMA', decode_alaw, 8000),
}

# G.711 by name (for dynamic PTs declared in SDP a=rtpmap:)
_G711_NAMED: Dict[str, Tuple[Callable, int]] = {
    'PCMU': (decode_ulaw, 8000),
    'PCMA': (decode_alaw, 8000),
}

# ffmpeg-based codecs: PT -> (ffmpeg_input_format, sample_rate_for_ffmpeg_or_None)
# sample_rate=None means ffmpeg infers it from the format (e.g. G.722 is always 16kHz)
_FFMPEG_STATIC_PT: Dict[int, Tuple[str, Optional[int]]] = {
    9:  ('g722', None),   # G.722 wideband — ffmpeg knows it's 16 kHz
    18: ('g729', 8000),   # G.729 / G.729A / G.729B (annex B DTX supported)
}

# ffmpeg-based codecs by name (for dynamic PTs from SDP)
_FFMPEG_NAMED: Dict[str, Tuple[str, Optional[int]]] = {
    'G722':  ('g722', None),
    'G729':  ('g729', 8000),
    'G729A': ('g729', 8000),
    'G729B': ('g729', 8000),
}


# ── RTP header parsing ────────────────────────────────────────────────────────

def rtp_payload_type(rtp_bytes: bytes) -> int:
    """Return the RTP payload type field (7 bits, marker bit masked out)."""
    return (rtp_bytes[1] & 0x7F) if len(rtp_bytes) >= 2 else -1


def rtp_audio_payload(rtp_bytes: bytes) -> Optional[bytes]:
    """
    Strip the RTP fixed header (12 bytes) plus any CSRC list and extension header.
    Returns the raw codec payload, or None if the packet is malformed.
    """
    if len(rtp_bytes) < 12:
        return None
    cc = rtp_bytes[0] & 0x0F
    offset = 12 + cc * 4
    if rtp_bytes[0] & 0x10:            # extension bit
        if len(rtp_bytes) < offset + 4:
            return None
        ext_words = struct.unpack_from('!H', rtp_bytes, offset + 2)[0]
        offset += 4 + ext_words * 4
    if offset >= len(rtp_bytes):
        return None
    return rtp_bytes[offset:]


# ── Writers ───────────────────────────────────────────────────────────────────

class WavWriter:
    """Decodes G.711 RTP packets to a WAV file incrementally (no external deps)."""

    def __init__(self, path: Path, decode_fn: Callable[[bytes], bytes], clock_rate: int):
        self._decode = decode_fn
        self._wav = wave.open(str(path), 'wb')
        self._wav.setnchannels(1)
        self._wav.setsampwidth(2)
        self._wav.setframerate(clock_rate)

    def write_packet(self, rtp_bytes: bytes) -> None:
        payload = rtp_audio_payload(rtp_bytes)
        if not payload:
            return
        try:
            self._wav.writeframes(self._decode(payload))
        except Exception:
            pass

    def close(self) -> None:
        self._wav.close()


class FfmpegWriter:
    """
    Decodes any ffmpeg-supported codec by piping raw payloads to ffmpeg stdin.

    ffmpeg is started once per SSRC stream and receives payloads as they arrive,
    preserving the streaming design — no buffering of the full stream in memory.
    """

    def __init__(self, path: Path, ffmpeg_format: str, sample_rate: Optional[int]):
        cmd = ['ffmpeg', '-y', '-f', ffmpeg_format]
        if sample_rate is not None:
            cmd += ['-ar', str(sample_rate)]
        cmd += ['-ac', '1', '-i', 'pipe:0', str(path)]

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._dead = False

    def write_packet(self, rtp_bytes: bytes) -> None:
        if self._dead or self._proc.stdin is None:
            return
        payload = rtp_audio_payload(rtp_bytes)
        if not payload:
            return
        try:
            self._proc.stdin.write(payload)
        except BrokenPipeError:
            self._dead = True

    def close(self) -> None:
        if not self._dead and self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait()
        self._dead = True


# ── Public factory ────────────────────────────────────────────────────────────

def ffmpeg_available() -> bool:
    return shutil.which('ffmpeg') is not None


def make_writer(
    path: Path,
    pt: int,
    rtpmap: Dict[int, Tuple[str, int]],
) -> Optional[object]:
    """
    Return the appropriate writer for a given RTP payload type, or None if the
    codec is not supported.

    Resolution order:
      1. G.711 PCMU/PCMA — pure Python, no external deps
      2. Codec name from SDP rtpmap matched against G.711 or ffmpeg tables
      3. Static PT table for ffmpeg codecs (PT 9 = G.722, PT 18 = G.729)

    The returned object exposes:
      write_packet(rtp_bytes: bytes) -> None
      close() -> None
    """
    # ── 1. Static G.711 PTs (0, 8) ──────────────────────────────────────────
    if pt in _G711_STATIC_PT:
        _, decode_fn, clock_rate = _G711_STATIC_PT[pt]
        return WavWriter(path, decode_fn, clock_rate)

    # ── 2. Dynamic PT declared in SDP a=rtpmap: ──────────────────────────────
    if pt in rtpmap:
        codec_name, clock_rate = rtpmap[pt]

        if codec_name in _G711_NAMED:
            decode_fn, _ = _G711_NAMED[codec_name]
            return WavWriter(path, decode_fn, clock_rate)

        if codec_name in _FFMPEG_NAMED and ffmpeg_available():
            ffmpeg_fmt, ffmpeg_ar = _FFMPEG_NAMED[codec_name]
            # Use clock_rate from SDP unless the format overrides it (e.g. G.722)
            ar = ffmpeg_ar if ffmpeg_ar is not None else clock_rate
            return FfmpegWriter(path, ffmpeg_fmt, ar)

    # ── 3. Static ffmpeg PTs (9, 18) ─────────────────────────────────────────
    if pt in _FFMPEG_STATIC_PT and ffmpeg_available():
        ffmpeg_fmt, ffmpeg_ar = _FFMPEG_STATIC_PT[pt]
        return FfmpegWriter(path, ffmpeg_fmt, ffmpeg_ar)

    return None
