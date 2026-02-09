from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TcpRecord:
    """Strukturovaný TCP záznam podle Egon protokolu."""
    # Základní pole protokolu
    cmd: Optional[str]  # M-XX nebo např. "ACK", "VerifyUser", "user?"
    slave: Optional[str]  # S-YY (dvě hex číslice) nebo None
    parameter: Optional[str]  # P-<PARAM> (hex string) nebo jiný parametr
    data: Optional[str]  # D-<DATA> (včetně bloků oddělených /) jako čistý text bez "D-"
    raw_text: str  # Původní ASCII řetězec zprávy
    segments: Dict[str, str]  # Zachováno pro zpětnou kompatibilitu (D bloky rozdělené podle původní logiky)


def _parse_special_message(text: str) -> Optional[TcpRecord]:
    """Rozpoznání speciálních zpráv protokolu (ACK, VerifyUser, user?)."""
    t = text.strip()

    # :ACK;
    if t == ":ACK;" or t == "ACK" or t == ":ACK":
        return TcpRecord(
            cmd="ACK",
            slave=None,
            parameter=None,
            data=None,
            raw_text=text,
            segments={},
        )

    # >VerifyUser,Name=username,Pass=password;
    if t.startswith(">VerifyUser"):
        return TcpRecord(
            cmd="VerifyUser",
            slave=None,
            parameter=None,
            data=None,
            raw_text=text,
            segments={},
        )

    # >user?;
    if t.startswith(">user?"):
        return TcpRecord(
            cmd="user?",
            slave=None,
            parameter=None,
            data=None,
            raw_text=text,
            segments={},
        )

    # >ACK;
    if t.startswith(">ACK"):
        return TcpRecord(
            cmd=">ACK",
            slave=None,
            parameter=None,
            data=None,
            raw_text=text,
            segments={},
        )

    return None


def parse_tcp_message(payload: bytes) -> Optional[TcpRecord]:
    """Parse TCP ASCII payload dle Egon protokolu.

    Podporuje:
    - Normální zprávy: :M-XX,S-YY[,P-<PARAM>],D-<DATA>;
    - ACK: :ACK;
    - Uživatelské zprávy: >VerifyUser..., >user?;, >ACK;
    """
    try:
        text = payload.decode('ascii', errors='ignore').strip()
    except Exception:
        return None

    if not text:
        return None

    # Nejprve zkusit speciální zprávy
    special = _parse_special_message(text)
    if special is not None:
        return special

    # Normální zprávy musí začínat ':' a obsahovat M- a S-
    if not text.startswith(":"):
        return None

    # Odstranit koncový středník
    if text.endswith(";"):
        text_no_semicolon = text[:-1]
    else:
        text_no_semicolon = text

    # Odstranit počáteční ':'
    header_body = text_no_semicolon[1:]

    # Rozdělit podle čárek
    parts = [p.strip() for p in header_body.split(',') if p.strip()]

    m_val = None
    s_val = None
    p_val = None
    d_raw = None

    for part in parts:
        if part.startswith("M-"):
            m_val = part[2:].upper()
        elif part.startswith("S-"):
            s_val = part[2:].upper()
        elif part.startswith("P-"):
            p_val = part[2:]
        elif part.startswith("D-"):
            d_raw = part[2:]

    if m_val is None or s_val is None:
        # Bez M a S to nepovažujeme za normální Egon zprávu
        return None

    # Rozpad dat na bloky pro zpětnou kompatibilitu (původní "segments")
    segments: Dict[str, str] = {}
    if d_raw:
        for seg in d_raw.split('/'):
            if not seg:
                continue
            # Původní heuristika: první 1-2 hex znaky jsou ID bloku
            if len(seg) >= 2 and all(c in '0123456789ABCDEFabcdef' for c in seg[:2]):
                seg_id = seg[:2].upper()
                seg_val = seg[2:]
            else:
                seg_id = seg[:1].upper()
                seg_val = seg[1:]
            segments[seg_id] = seg_val.upper()

    # Určení typu podle M-XX, jen pro informaci
    special_type = None

    return TcpRecord(
        cmd=m_val,
        slave=s_val,
        parameter=p_val,
        data=d_raw,
        raw_text=text,
        segments=segments,
    )
