from dataclasses import dataclass
from typing import Optional

@dataclass
class LogEvent:
    ts_ms: int
    source: str  # 'TCP' or 'UART'
    message: str
    raw_data: Optional[bytes] = None  # Raw data for copy operations

