"""
Single-pass analysis: reads the PCAP file once with filter 'sip or rtp'.

Compared to two-pass mode, this halves disk I/O and keeps CPU busy continuously
(no idle time between passes). Correct for all normal VoIP captures because SDP
always precedes RTP in a SIP signaling flow.

Limitation: RTP packets that arrive before their SDP has been seen (e.g. capture
started mid-call) are silently skipped — same behaviour as two-pass mode.
"""
from pathlib import Path
from typing import Dict, Tuple

from models import Call
from pcap_reader import combined_stream
from progress import Progress
from rtp_extractor import _PcapFileWriter, process_rtp_pkt
from sip_extractor import _SipFileCache, process_sip_pkt


def analyze(pcap_file: str, output_dir: Path) -> Dict[str, Call]:
    """
    Stream every SIP and RTP packet in a single tshark pass and write all output files.

    Returns the calls dict (call_id -> Call) for index.csv generation.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    calls: Dict[str, Call] = {}
    endpoint_map: Dict[Tuple[str, int], Call] = {}
    used_dirnames: set = set()
    pcap_writers: Dict[str, _PcapFileWriter] = {}
    wav_writers: Dict[str, object] = {}
    sip_cache = _SipFileCache()
    prog = Progress()

    try:
        for item in combined_stream(pcap_file):
            if item[0] == 'sip':
                _, sip_pkt = item
                process_sip_pkt(sip_pkt, calls, endpoint_map, used_dirnames, output_dir, sip_cache)
            else:
                _, ts, src_ip, src_port, dst_ip, dst_port, raw, udp_payload, datalink = item
                process_rtp_pkt(ts, src_ip, src_port, dst_ip, dst_port, raw, udp_payload, datalink,
                                endpoint_map, pcap_writers, wav_writers)
            prog.tick(calls=len(calls), streams=len(pcap_writers))
    finally:
        sip_cache.close_all()
        for w in pcap_writers.values():
            w.close()
        for w in wav_writers.values():
            w.close()

    prog.done(calls=len(calls), streams=len(pcap_writers))
    return calls
