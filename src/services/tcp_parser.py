from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class TcpRecord:
    m: Optional[str]
    s: Optional[str]
    p: Optional[str]
    segments: Dict[str, str]


def parse_tcp_message(payload: bytes) -> Optional[TcpRecord]:
    """Parse TCP ASCII payload of the form:
    M-<m>,S-<s>,P-<p>,D-<seg>/<seg>/.../;<EOF>
    where each <seg> is like 'XY<hex>' with XY being id (hex) and value hex string.
    Returns TcpRecord or None if format not matched.
    """
    try:
        text = payload.decode('ascii', errors='ignore').strip()
    except Exception:
        return None
    # Must contain M-,S-,P-,D-
    if 'M-' not in text or 'S-' not in text or 'P-' not in text or 'D-' not in text:
        return None
    # Remove trailing semicolon if present
    if text.endswith(';'):
        text = text[:-1]
    # Split top-level by commas for header
    # Expect format: M-...,S-...,P-...,D-...
    parts = text.split(',')
    m_val = s_val = p_val = None
    d_part = None
    for part in parts:
        part = part.strip()
        if part.startswith('M-'):
            m_val = part[2:]
        elif part.startswith('S-'):
            s_val = part[2:]
        elif part.startswith('P-'):
            p_val = part[2:]
        elif part.startswith('D-'):
            d_part = part[2:]
    if d_part is None:
        return None
    # D part contains segments separated by '/'
    segs: Dict[str, str] = {}
    for seg in d_part.split('/'):
        if not seg:
            continue
        # segment like '0AFFFFFFFFFFFFFFFF' or '0FFFFFFFFFFFFFFFFF'
        # ID is first 1-2 hex chars (we'll take up to first two uppercase hex chars until non-hex), then rest is value
        # More robust: ID are up to 2 ASCII hex chars followed by value hex.
        # We'll take first two chars as id when both are hex; else first one.
        if len(seg) >= 2 and all(c in '0123456789ABCDEFabcdef' for c in seg[:2]):
            seg_id = seg[:2].upper()
            seg_val = seg[2:]
        else:
            seg_id = seg[:1].upper()
            seg_val = seg[1:]
        segs[seg_id] = seg_val.upper()
    return TcpRecord(m=m_val, s=s_val, p=p_val, segments=segs)

