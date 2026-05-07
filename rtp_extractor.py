import dpkt
from pathlib import Path
from typing import Dict, Tuple

import audio_decoder
from models import Call
from pcap_reader import rtp_stream
from progress import Progress


class _PcapFileWriter:
    """dpkt-based pcap writer; drop-in replacement for scapy PcapWriter."""

    def __init__(self, path: str, datalink: int = 1) -> None:
        self._f = open(path, 'wb')
        self._writer = dpkt.pcap.Writer(self._f, linktype=datalink)

    def write(self, ts: float, raw: bytes) -> None:
        self._writer.writepkt(raw, ts=ts)

    def close(self) -> None:
        self._f.close()


def _ssrc_from_rtp(udp_payload: bytes) -> int:
    """Extract SSRC from RTP header bytes 8–11 (big-endian). Returns 0 on error."""
    if len(udp_payload) < 12:
        return 0
    return int.from_bytes(udp_payload[8:12], 'big')


def process_rtp_pkt(
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    raw: bytes,
    udp_payload: bytes,
    datalink: int,
    endpoint_map: Dict[Tuple[str, int], Call],
    pcap_writers: Dict[str, '_PcapFileWriter'],
    wav_writers: Dict[str, object],
) -> None:
    """Process one RTP packet: route to call, write pcap and wav."""
    call = endpoint_map.get((src_ip, src_port)) or endpoint_map.get((dst_ip, dst_port))
    if call is None:
        return

    ssrc = _ssrc_from_rtp(udp_payload)
    key = f'{call.call_id}_{ssrc}'

    if key not in pcap_writers:
        pcap_path = call.directory / f'rtp_{ssrc:08x}.pcap'
        pcap_writers[key] = _PcapFileWriter(str(pcap_path), datalink)

        pt = audio_decoder.rtp_payload_type(udp_payload)
        wav_path = call.directory / f'rtp_{ssrc:08x}.wav'
        writer = audio_decoder.make_writer(wav_path, pt, call.rtpmap)
        if writer:
            wav_writers[key] = writer

    pcap_writers[key].write(ts, raw)
    if key in wav_writers:
        wav_writers[key].write_packet(udp_payload)


def extract_rtp(
    pcap_file: str,
    endpoint_map: Dict[Tuple[str, int], Call],
) -> None:
    """Two-pass mode: stream RTP only and write per-SSRC files."""
    pcap_writers: Dict[str, _PcapFileWriter] = {}
    wav_writers: Dict[str, object] = {}
    prog = Progress()

    try:
        for ts, src_ip, src_port, dst_ip, dst_port, raw, udp_payload, datalink in rtp_stream(pcap_file):
            process_rtp_pkt(ts, src_ip, src_port, dst_ip, dst_port, raw, udp_payload, datalink,
                            endpoint_map, pcap_writers, wav_writers)
            prog.tick(streams=len(pcap_writers))
    finally:
        for w in pcap_writers.values():
            w.close()
        for w in wav_writers.values():
            w.close()

    prog.done(streams=len(pcap_writers))
