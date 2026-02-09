"""
UART message parser for formats:
- 0x10 (start) + DST + SRC + CMD + CHK + 0x16 (end)  [short/control messages]
- 0x43 (start) + DST + SRC + CMD + LEN + data[LEN] + CHK + 0x16 (end)  [data messages with length]

where:
  DST = destination/receiver ID (1 byte)
  SRC = sender ID (1 byte)
  CMD = command (1 byte)
  LEN = length of data field (1 byte, only in 0x43 messages)
  CHK = checksum (1 byte)

Checksum calculation:
- 0x10 messages: (DST + SRC + CMD) & 0xFF
- 0x43 messages: (DST + SRC + CMD + LEN + all_data_bytes) & 0xFF
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
    message_type: str  # "control" (0x10) or "data" (0x43)
    command: Optional[int] = None  # For 0x10 and 0x43 messages
    data_length: Optional[int] = None  # Only for 0x43 messages

    def __str__(self) -> str:
        """String representation of the message."""
        chk_status = "✓" if self.checksum_valid else "✗"
        type_marker = "C" if self.message_type == "control" else "D"
        cmd_str = f" CMD:{self.command:02X}" if self.command is not None else ""
        len_str = f" LEN:{self.data_length}" if self.data_length is not None else ""
        return f"[{type_marker}:{self.sender_id:02X}→{self.receiver_id:02X}{cmd_str}{len_str}] {self.data.hex()} CHK:{chk_status}"

    def data_as_string(self) -> str:
        """Try to decode data as ASCII string, fallback to hex."""
        try:
            # Try to decode as ASCII, replace non-printable chars
            return ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in self.data)
        except Exception:
            return self.data.hex()


def parse_uart_message(frame: bytes) -> Optional[UartMessage]:
    """Parse UART message according to supported formats."""

    if len(frame) < 5:  # Minimum: START DST SRC CHK END (for 0x10 without CMD, but we now expect 6 bytes)
        return None

    # Check start and end bytes
    start_byte = frame[0]
    if start_byte not in (0x10, 0x43) or frame[-1] != 0x16:
        return None

    # Extract checksum (second to last byte)
    checksum = frame[-2]

    if start_byte == 0x10:
        # New Format 1: 10 DST SRC CMD CHK 16
        # Exact length must be 6 bytes
        if len(frame) != 6:
            return None

        receiver_id = frame[1]  # DST
        sender_id = frame[2]    # SRC
        command = frame[3]      # CMD

        data = b""  # No data payload for control messages

        # Calculate expected checksum: (DST + SRC + CMD) & 0xFF
        expected_checksum = (receiver_id + sender_id + command) & 0xFF
        checksum_valid = (checksum == expected_checksum)

        return UartMessage(
            sender_id=sender_id,
            receiver_id=receiver_id,
            data=data,
            checksum=checksum,
            raw=frame,
            checksum_valid=checksum_valid,
            message_type="control",
            command=command,
            data_length=None,
        )

    else:  # start_byte == 0x43
        # Format 2: 43 DST SRC CMD LEN <data[LEN]> CHK 16
        # Minimum length: 7 (43 DST SRC CMD LEN CHK 16 - with LEN=0)

        if len(frame) < 7:
            return None

        receiver_id = frame[1]  # DST
        sender_id = frame[2]    # SRC
        command = frame[3]      # CMD
        data_length = frame[4]  # LEN

        # Calculate expected frame length: 1(start) + 1(dst) + 1(src) + 1(cmd) + 1(len) + data_length + 1(chk) + 1(end)
        expected_frame_length = 7 + data_length

        # Validate frame length matches the LEN field
        if len(frame) != expected_frame_length:
            return None

        # Extract data (LEN bytes starting at position 5)
        data = frame[5:5+data_length]

        # Verify we extracted correct amount of data
        if len(data) != data_length:
            return None

        # Calculate expected checksum: (DST + SRC + CMD + LEN + all_data_bytes) & 0xFF
        expected_checksum = (receiver_id + sender_id + command + data_length + sum(data)) & 0xFF
        checksum_valid = (checksum == expected_checksum)

        return UartMessage(
            sender_id=sender_id,
            receiver_id=receiver_id,
            data=data,
            checksum=checksum,
            raw=frame,
            checksum_valid=checksum_valid,
            message_type="data",
            command=command,
            data_length=data_length
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
