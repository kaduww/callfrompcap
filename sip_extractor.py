import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, IO, Set, Tuple

import sip_parser
from models import Call
from pcap_reader import sip_stream
from progress import Progress


class _SipFileCache:
    """LRU cache of open sip_trace.txt handles — avoids open/close per packet."""

    _MAX = 500

    def __init__(self) -> None:
        self._handles: Dict[str, IO] = {}  # path str -> file handle (insertion-ordered)

    def write(self, path: Path, entry: str) -> None:
        key = str(path)
        if key not in self._handles:
            if len(self._handles) >= self._MAX:
                oldest = next(iter(self._handles))
                self._handles.pop(oldest).close()
            self._handles[key] = open(path, 'a', encoding='utf-8')
        self._handles[key].write(entry)

    def close_all(self) -> None:
        for fh in self._handles.values():
            fh.close()
        self._handles.clear()


def _safe_dirname(call_id: str, used: Set[str]) -> str:
    base = re.sub(r'[^\w\-]', '_', call_id)[:100]
    name = base
    counter = 2
    while name in used:
        name = f'{base}_{counter}'
        counter += 1
    used.add(name)
    return name


def _fmt_ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f UTC')


def process_sip_pkt(
    pkt: dict,
    calls: Dict[str, Call],
    endpoint_map: Dict[Tuple[str, int], Call],
    used_dirnames: Set[str],
    output_dir: Path,
    sip_cache: _SipFileCache,
) -> None:
    """Process one SIP packet: update call state, endpoint map, and sip_trace.txt."""
    info = sip_parser.parse(pkt['raw'])
    call_id = info['call_id']
    if not call_id:
        return

    if call_id not in calls:
        dirname = _safe_dirname(call_id, used_dirnames)
        call_dir = output_dir / dirname
        call_dir.mkdir(parents=True, exist_ok=True)
        call = Call(
            call_id=call_id,
            request_user=info['request_user'],
            directory=call_dir,
        )
        calls[call_id] = call
    else:
        call = calls[call_id]
        if info['request_user'] and not call.request_user:
            call.request_user = info['request_user']

    for ip, port in info['sdp_endpoints']:
        if (ip, port) not in call.rtp_endpoints:
            call.rtp_endpoints.add((ip, port))
            endpoint_map[(ip, port)] = call
    call.rtpmap.update(info['rtpmap'])

    ts = _fmt_ts(pkt['timestamp'])
    entry = (
        f"{'=' * 72}\n"
        f"{ts}  {pkt['src_ip']}:{pkt['src_port']} --> {pkt['dst_ip']}:{pkt['dst_port']}\n"
        f"{'=' * 72}\n"
        f"{info['text'].rstrip()}\n\n"
    )
    sip_cache.write(call.directory / 'sip_trace.txt', entry)


def extract_calls(
    pcap_file: str,
    output_dir: Path,
) -> Tuple[Dict[Tuple[str, int], Call], Dict[str, Call]]:
    """Two-pass mode: stream SIP only, return (endpoint_map, calls)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    calls: Dict[str, Call] = {}
    endpoint_map: Dict[Tuple[str, int], Call] = {}
    used_dirnames: Set[str] = set()
    sip_cache = _SipFileCache()
    prog = Progress()

    try:
        for pkt in sip_stream(pcap_file):
            process_sip_pkt(pkt, calls, endpoint_map, used_dirnames, output_dir, sip_cache)
            prog.tick(calls=len(calls))
    finally:
        sip_cache.close_all()

    prog.done(calls=len(calls))
    return endpoint_map, calls
