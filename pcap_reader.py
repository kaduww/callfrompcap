import dpkt
import socket
import subprocess
from typing import Iterator

_DLT_EN10MB = 1
_DLT_LINUX_SLL = 113
_DLT_RAW = 228
_DLT_RAW_BSD = 12


def _parse_ip_udp(raw: bytes, datalink: int):
    """Returns (src_ip, dst_ip, src_port, dst_port, udp_payload) or None."""
    try:
        if datalink == _DLT_EN10MB:
            frame = dpkt.ethernet.Ethernet(raw)
            ip = frame.data
        elif datalink == _DLT_LINUX_SLL:
            frame = dpkt.sll.SLL(raw)
            ip = frame.data
        elif datalink in (_DLT_RAW, _DLT_RAW_BSD):
            ip = dpkt.ip.IP(raw)
        else:
            return None
        if not isinstance(ip, dpkt.ip.IP):
            return None
        if not isinstance(ip.data, dpkt.udp.UDP):
            return None
        udp = ip.data
        return (
            socket.inet_ntoa(ip.src),
            socket.inet_ntoa(ip.dst),
            udp.sport,
            udp.dport,
            bytes(udp.data),
        )
    except Exception:
        return None


def sip_stream(pcap_file: str) -> Iterator[dict]:
    """Yield one dict per SIP packet."""
    cmd = ['tshark', '-r', pcap_file, '-Y', 'sip', '-w', '-']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        reader = dpkt.pcap.Reader(proc.stdout)
        datalink = reader.datalink()
        for ts, raw in reader:
            parsed = _parse_ip_udp(raw, datalink)
            if parsed is None:
                continue
            src_ip, dst_ip, src_port, dst_port, payload = parsed
            yield {
                'timestamp': ts,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'raw': payload,
            }
    except Exception:
        pass
    finally:
        proc.wait()


def rtp_stream(pcap_file: str) -> Iterator[tuple]:
    """Yield (ts, src_ip, src_port, dst_ip, dst_port, raw_pkt, udp_payload, datalink) per RTP packet."""
    cmd = ['tshark', '-r', pcap_file, '-Y', 'rtp', '-w', '-']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        reader = dpkt.pcap.Reader(proc.stdout)
        datalink = reader.datalink()
        for ts, raw in reader:
            parsed = _parse_ip_udp(raw, datalink)
            if parsed is None:
                continue
            src_ip, dst_ip, src_port, dst_port, payload = parsed
            yield ts, src_ip, src_port, dst_ip, dst_port, raw, payload, datalink
    except Exception:
        pass
    finally:
        proc.wait()


def combined_stream(pcap_file: str) -> Iterator[tuple]:
    """
    Single-pass: reads the file ONCE with filter 'sip or rtp'.

    Yields:
        ('sip', sip_dict)
        ('rtp', ts, src_ip, src_port, dst_ip, dst_port, raw_pkt, udp_payload, datalink)

    RTP v2 packets start with bits 7-6 = 10 (mask 0xC0 == 0x80).
    SIP packets start with printable ASCII (method or status line).
    """
    cmd = ['tshark', '-r', pcap_file, '-Y', 'sip or rtp', '-w', '-']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        reader = dpkt.pcap.Reader(proc.stdout)
        datalink = reader.datalink()
        for ts, raw in reader:
            parsed = _parse_ip_udp(raw, datalink)
            if parsed is None:
                continue
            src_ip, dst_ip, src_port, dst_port, payload = parsed
            if not payload:
                continue

            if (payload[0] & 0xC0) == 0x80:  # RTP version 2
                yield 'rtp', ts, src_ip, src_port, dst_ip, dst_port, raw, payload, datalink
            else:  # SIP
                yield 'sip', {
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'raw': payload,
                }
    except Exception:
        pass
    finally:
        proc.wait()
