import threading
from PySide6 import QtCore
import serial

class UartReader(QtCore.QObject):
    """
    UART frame reader with simple START/END detection.

    Protocol:
    - START bytes: 0x10 (short/control messages) or 0x43 (data messages)
    - END byte: 0x16 - marks end of frame

    Frame formats:
    - 10 [data...] 16 - short/control frames
    - 43 [data...] 16 - data frames

    Simple parsing:
    - 0x10 or 0x43 starts new frame (discards incomplete previous frame)
    - 0x16 ends current frame
    - No escaping/stuffing
    - Same checksum (SUM8) for both types
    """
    opened = QtCore.Signal(str)  # port
    closed = QtCore.Signal(str)
    frameReceived = QtCore.Signal(bytes)
    frameDropped = QtCore.Signal(bytes, str)  # dropped frame, reason
    rawDataReceived = QtCore.Signal(bytes)  # raw data before any parsing
    errorOccurred = QtCore.Signal(str)

    def __init__(self, port: str, baudrate: int,
                 start_byte: int, end_byte: int, max_len: int):
        super().__init__()
        self.port = port
        self.baudrate = baudrate
        self.start_byte = start_byte  # Primary start byte (0x10)
        self.start_byte_alt = 0x43  # Alternative start byte for data frames
        self.end_byte = end_byte
        self.max_len = max_len
        self._ser: serial.Serial | None = None
        self._rx_thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self):
        if self._rx_thread and self._rx_thread.is_alive():
            return
        self._stop.clear()
        self._rx_thread = threading.Thread(target=self._run, daemon=True)
        self._rx_thread.start()

    def stop(self):
        self._stop.set()
        try:
            if self._ser:
                self._ser.close()
        except Exception:
            pass

    def _run(self):
        try:
            self._ser = serial.Serial(self.port, self.baudrate, timeout=0.2)
            self.opened.emit(self.port)
        except Exception as e:
            self.errorOccurred.emit(f"UART open error: {e}")
            self.closed.emit("open_failed")
            return

        buf = bytearray()
        in_frame = False
        frame_start_byte = None  # Track which START byte began the current frame

        try:
            while not self._stop.is_set():
                try:
                    b = self._ser.read(1)
                    if not b:
                        continue
                    byte = b[0]

                    # Emit raw data before any parsing
                    self.rawDataReceived.emit(b)

                    # Check for START bytes (0x10 or 0x43) - BUT ONLY if we're NOT already in a frame
                    if not in_frame and (byte == self.start_byte or byte == self.start_byte_alt):
                        # START byte - begin new frame
                        buf.clear()
                        buf.append(byte)
                        in_frame = True
                        frame_start_byte = byte  # Remember which START byte we used

                    elif byte == self.end_byte and in_frame:
                        # END byte - complete frame
                        buf.append(byte)
                        frame = bytes(buf)
                        buf.clear()
                        in_frame = False
                        frame_start_byte = None

                        # Validate and emit
                        if 2 <= len(frame) <= self.max_len:
                            self.frameReceived.emit(frame)
                        elif len(frame) < 2:
                            self.frameDropped.emit(frame, "too_short")
                        else:
                            self.frameDropped.emit(frame, "too_long")

                    elif in_frame:
                        # Check if we encountered the SAME start byte again (error - missing END or new frame started)
                        if byte == frame_start_byte and len(buf) > 1:
                            # Same START byte found inside frame - this is an error
                            # Drop the incomplete frame and start a new one
                            self.frameDropped.emit(bytes(buf), "same_start_byte_in_frame")
                            buf.clear()
                            buf.append(byte)
                            frame_start_byte = byte
                            # Stay in_frame = True, we just started a new frame
                        else:
                            # Normal data byte (or opposite START byte which is allowed)
                            buf.append(byte)

                            # Buffer overflow check
                            if len(buf) > self.max_len:
                                self.frameDropped.emit(bytes(buf), "buffer_overflow")
                                buf.clear()
                                in_frame = False
                                frame_start_byte = None

                except Exception as e:
                    self.errorOccurred.emit(f"UART read error: {e}")
                    break
        finally:
            try:
                self._ser.close()
            except Exception:
                pass
            self.closed.emit("stopped")

