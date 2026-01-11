from typing import Sequence

class UartFilter:
    def __init__(self, enabled: bool, mode: str, match_type: str, patterns: Sequence[str]):
        self.enabled = enabled
        self.mode = mode.lower()
        self.match_type = match_type.lower()
        self.patterns = [p.strip().lower() for p in patterns if p and isinstance(p, str)]

    def passes(self, frame: bytes) -> bool:
        if not self.enabled:
            return True
        if not self.patterns:
            return True
        hex_msg = frame.hex()
        def matches(p: str) -> bool:
            if self.match_type == 'exact':
                return hex_msg == p
            return p in hex_msg
        any_match = any(matches(p) for p in self.patterns)
        if self.mode == 'include':
            return any_match
        elif self.mode == 'exclude':
            return not any_match
        return True

