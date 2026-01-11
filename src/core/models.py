from dataclasses import dataclass

@dataclass
class LogEvent:
    ts_ms: int
    source: str  # 'TCP' or 'UART'
    message: str

