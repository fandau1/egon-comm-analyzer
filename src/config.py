"""
Configuration file
"""

# Serial Port Configuration
SERIAL_START_BYTE = 0x10  # Fixed start byte
SERIAL_END_BYTE = 0x16    # Fixed end byte
SERIAL_MAX_MESSAGE_LENGTH = 50
SERIAL_DEFAULT_PORT = "COM4"
SERIAL_DEFAULT_BAUDRATE = 9600

# TCP Configuration
TCP_DEFAULT_PORT = 10001
TCP_DEFAULT_TARGET_IP = "192.168.1.160"

# GUI Configuration
GUI_WIDTH = 1600
GUI_HEIGHT = 900
GUI_FONT = ('Consolas', 9)

# Time pairing threshold (milliseconds)
TIME_PAIRING_THRESHOLD = 1000

# UART filter configuration
UART_FILTER_ENABLED = True
UART_FILTER_MODE = 'include'  # 'include' or 'exclude'
UART_FILTER_MATCH = 'exact'  # 'exact' or 'substring'
UART_FILTER_HEX_PATTERNS: list[str] = [
    "10a0553c3116",
]
