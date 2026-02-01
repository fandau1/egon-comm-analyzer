"""
UART message parser for format: 10 (start) + sender_id + receiver_id + data + checksum + 16 (end)

Uses 8-bit SUM checksum: (DST + SRC + all_data_bytes) & 0xFF

Simple protocol - no escaping.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class UartMessage:
    """Parsed UART message."""
    sender_id: int
    receiver_id: int
    data: bytes
    checksum: int
    raw: bytes
    checksum_valid: bool

    def __str__(self) -> str:
        """String representation of the message."""
        chk_status = "✓" if self.checksum_valid else "✗"
        return f"[{self.sender_id:02X}→{self.receiver_id:02X}] {self.data.hex()} CHK:{chk_status}"

    def data_as_string(self) -> str:
        """Try to decode data as ASCII string, fallback to hex."""
        try:
            # Try to decode as ASCII, replace non-printable chars
            return ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in self.data)
        except Exception:
            return self.data.hex()


def parse_uart_message(frame: bytes) -> Optional[UartMessage]:
    """
    Parse UART message in format: 10 DST SRC <data> CHK 16
    where DST = receiver ID, SRC = sender ID, CHK = checksum (8-bit SUM)

    Checksum = (DST + SRC + all_data_bytes) & 0xFF

    Args:
        frame: Raw frame bytes

    Returns:
        UartMessage if valid format, None otherwise
    """

    if len(frame) < 5:  # Minimum: 10 DST SRC CHK 16
        return None

    # Check start and end bytes
    if frame[0] != 0x10 or frame[-1] != 0x16:
        return None

    # Extract sender and receiver IDs
    receiver_id = frame[1]  # DST
    sender_id = frame[2]    # SRC

    # Extract checksum (second to last byte)
    checksum = frame[-2]

    # Extract data (everything between SRC and checksum)
    data = frame[3:-2]

    # Calculate expected checksum: (DST + SRC + all_data_bytes) & 0xFF
    expected_checksum = (receiver_id + sender_id + sum(data)) & 0xFF
    checksum_valid = (checksum == expected_checksum)

    return UartMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        data=data,
        checksum=checksum,
        raw=frame,
        checksum_valid=checksum_valid
    )


# Color palette for different IDs (using pastel colors for better readability)
ID_COLORS = [
    "#FADADD", "#D6ECFF", "#DFF5EA", "#FFF1CC", "#E8DFFF",
    "#FFE0B2", "#E0F2F1", "#F3E5F5", "#E1F5C4", "#EDE7F6",

    "#FFE4C4", "#E3F2FD", "#E8F5E9", "#FFFDE7", "#FCE4EC",
    "#E0F7FA", "#F1F8E9", "#EDE7F6", "#FFF3E0", "#E8EAF6",

    "#F9EBEA", "#EBF5FB", "#E9F7EF", "#FEF9E7", "#FDEDEC",
    "#E8F8F5", "#F4F6F7", "#F6DDCC", "#EBDEF0", "#D5F5E3",

    "#FCF3CF", "#FADBD8", "#D6EAF8", "#D4EFDF", "#FDEBD0",
    "#EAECEE", "#EAF2F8", "#F5EEF8", "#E8F6F3", "#FEF5E7",
]


def get_color_for_id(id_value: int) -> str:
    """Get consistent color for a given ID."""
    return ID_COLORS[id_value % len(ID_COLORS)]

