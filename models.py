from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set, Tuple


@dataclass
class Call:
    call_id: str
    request_user: str
    directory: Path
    rtp_endpoints: Set[Tuple[str, int]] = field(default_factory=set)
    # Payload type → (codec_name, clock_rate) — populated from SDP a=rtpmap: lines
    rtpmap: Dict[int, Tuple[str, int]] = field(default_factory=dict)
