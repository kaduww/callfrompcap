import re
from typing import List, Tuple


def _header_value(lines: list, name: str) -> str:
    """Return the first value of a header (case-insensitive, compact forms supported)."""
    name_lower = name.lower()
    for line in lines:
        if ':' in line:
            k, _, v = line.partition(':')
            if k.strip().lower() == name_lower:
                return v.strip()
    return ''


def parse(raw: bytes) -> dict:
    """
    Parse raw SIP bytes.

    Returns:
        call_id       – value of the Call-ID header (compact: i)
        request_user  – user part of the INVITE/REFER/ACK Request-URI, empty for responses
        sdp_endpoints – list of (ip, port) tuples from SDP c= / m= lines
        text          – full message decoded as UTF-8 (for writing to trace files)
        first_line    – request-line or status-line
    """
    text = raw.decode('utf-8', errors='replace')

    # Split headers from body (CRLF or LF)
    if '\r\n\r\n' in text:
        header_block, body = text.split('\r\n\r\n', 1)
        header_lines = header_block.split('\r\n')
    elif '\n\n' in text:
        header_block, body = text.split('\n\n', 1)
        header_lines = header_block.split('\n')
    else:
        header_lines = text.split('\n')
        body = ''

    first_line = header_lines[0].strip() if header_lines else ''
    rest = header_lines[1:]

    call_id = _header_value(rest, 'call-id') or _header_value(rest, 'i')

    # Request-URI user — only present in request messages
    request_user = ''
    parts = first_line.split()
    if len(parts) >= 2 and parts[0] not in ('SIP/2.0',):
        # parts[0] is the method, parts[1] is the Request-URI
        m = re.match(r'sips?:([^@>;?\s]+)@', parts[1])
        if m:
            request_user = m.group(1)

    # SDP: walk lines to collect (ip, port) pairs and payload-type → codec mappings
    sdp_endpoints: List[Tuple[str, int]] = []
    rtpmap: dict = {}   # payload_type -> (codec_name, clock_rate)
    current_ip = None
    in_audio = False
    for line in body.replace('\r', '').split('\n'):
        line = line.strip()
        if line.startswith('c='):
            addr = line.split()[-1]
            if addr not in ('0.0.0.0', '::'):
                current_ip = addr
        elif line.startswith('m='):
            in_audio = line.startswith('m=audio')
            if in_audio and current_ip:
                m_parts = line.split()
                if len(m_parts) >= 2:
                    try:
                        port = int(m_parts[1])
                        if port > 0:
                            sdp_endpoints.append((current_ip, port))
                    except ValueError:
                        pass
        elif line.startswith('a=rtpmap:') and in_audio:
            # a=rtpmap:96 opus/48000/2  or  a=rtpmap:0 PCMU/8000
            rest = line[9:]
            pt_str, _, codec_str = rest.partition(' ')
            try:
                pt = int(pt_str)
                parts = codec_str.split('/')
                codec_name = parts[0].upper()
                clock_rate = int(parts[1]) if len(parts) > 1 else 8000
                rtpmap[pt] = (codec_name, clock_rate)
            except (ValueError, IndexError):
                pass

    return {
        'first_line': first_line,
        'call_id': call_id,
        'request_user': request_user,
        'sdp_endpoints': sdp_endpoints,
        'rtpmap': rtpmap,
        'text': text,
    }
