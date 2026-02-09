import threading
import time
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
        frame_start_time = None  # Track when frame started for timeout detection
        FRAME_TIMEOUT = 0.5  # 500ms timeout for incomplete frames

        try:
            while not self._stop.is_set():
                try:
                    b = self._ser.read(1)
                    current_time = time.time()

                    # Check for frame timeout - if we're in a frame and too much time passed without END byte
                    if in_frame and frame_start_time and (current_time - frame_start_time) > FRAME_TIMEOUT:
                        # Frame timeout - drop incomplete frame
                        if len(buf) > 0:
                            self.frameDropped.emit(bytes(buf), "incomplete_frame_interrupted")
                        buf.clear()
                        in_frame = False
                        frame_start_byte = None
                        frame_start_time = None

                    if not b:
                        continue
                    byte = b[0]

                    # Emit raw data before any parsing
                    self.rawDataReceived.emit(b)

                    # Check for START bytes (0x10 or 0x43)
                    if byte == self.start_byte or byte == self.start_byte_alt:
                        if in_frame:
                            # We're already in a frame and received another START byte
                            # This means the previous frame was incomplete (missing END byte)
                            # Drop the incomplete frame and start new one
                            if len(buf) > 1:  # Only drop if we had some data
                                self.frameDropped.emit(bytes(buf), "incomplete_frame_interrupted")
                            # Start new frame
                            buf.clear()
                            buf.append(byte)
                            frame_start_byte = byte
                            frame_start_time = current_time
                            in_frame = True
                        else:
                            # Not in frame - start new frame normally
                            buf.clear()
                            buf.append(byte)
                            in_frame = True
                            frame_start_byte = byte
                            frame_start_time = current_time

                    elif byte == self.end_byte:
                        if in_frame:
                            # END byte - complete frame
                            buf.append(byte)
                            frame = bytes(buf)
                            buf.clear()
                            in_frame = False
                            frame_start_byte = None
                            frame_start_time = None

                            # Validate and emit
                            if 2 <= len(frame) <= self.max_len:
                                self.frameReceived.emit(frame)
                            elif len(frame) < 2:
                                self.frameDropped.emit(frame, "too_short")
                            else:
                                self.frameDropped.emit(frame, "too_long")
                        # else: END byte outside of frame - ignore it

                    elif in_frame:
                        # Data byte - add to buffer
                        buf.append(byte)

                        # Buffer overflow check
                        if len(buf) > self.max_len:
                            self.frameDropped.emit(bytes(buf), "buffer_overflow")
                            buf.clear()
                            in_frame = False
                            frame_start_byte = None
                            frame_start_time = None

                except Exception as e:
                    self.errorOccurred.emit(f"UART read error: {e}")
                    break
        finally:
            # Drop any incomplete frame at the end
            if in_frame and len(buf) > 0:
                self.frameDropped.emit(bytes(buf), "incomplete_frame_interrupted")
            try:
                self._ser.close()
            except Exception:
                pass
            self.closed.emit("stopped")

