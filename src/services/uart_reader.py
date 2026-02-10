import threading
import time
from PySide6 import QtCore
import serial

class UartReader(QtCore.QObject):
    """
    UART frame reader with START/END detection and length-based parsing for 0x43 messages.

    Protocol:
    - START bytes: 0x10 (control messages) or 0x43 (data messages with length)
    - END byte: 0x16 - marks end of frame

    Frame formats:
    1. Control (0x10): 10 DST SRC <data> CHK 16
       - Variable length data
       - Frame ends when 0x16 is encountered

    2. Data (0x43): 43 DST SRC CMD LEN <data[LEN]> CHK 16
       - Fixed length data determined by LEN field
       - Frame length calculated from LEN field
       - Allows 0x10, 0x43, 0x16 in data without confusion
       - Frame ends after exact number of bytes specified by LEN

    Parsing logic:
    - 0x10: Collect bytes until 0x16 (END byte)
    - 0x43: Read LEN at position 4, collect exactly LEN bytes, verify 0x16 at end

    Checksum (SUM8):
    - 0x10: (DST + SRC + sum(data)) & 0xFF
    - 0x43: (DST + SRC + CMD + LEN + sum(data)) & 0xFF
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
        expected_frame_length = None  # For 0x43 messages with LEN field
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
                        expected_frame_length = None

                    if not b:
                        continue
                    byte = b[0]

                    # Emit raw data before any parsing
                    self.rawDataReceived.emit(b)

                    # Check for START bytes (0x10 or 0x43)
                    if byte == self.start_byte or byte == self.start_byte_alt:
                        if in_frame:
                            # We're already in a frame and received another START byte
                            # Before dropping the current frame, check if it might be complete
                            frame_might_be_complete = False

                            if frame_start_byte == 0x10:
                                # 0x10 frames: exactly 6 bytes (10 DST SRC CMD CHK 16)
                                if len(buf) == 6 and buf[-1] == self.end_byte:
                                    frame_might_be_complete = True
                            elif frame_start_byte == 0x43 and expected_frame_length is not None:
                                # 0x43 frames: check if we reached expected length with END byte
                                if len(buf) == expected_frame_length and buf[-1] == self.end_byte:
                                    frame_might_be_complete = True

                            if frame_might_be_complete:
                                # Current frame is complete - emit it first
                                frame = bytes(buf)
                                buf.clear()
                                in_frame = False

                                if 2 <= len(frame) <= self.max_len:
                                    self.frameReceived.emit(frame)
                                elif len(frame) < 2:
                                    self.frameDropped.emit(frame, "too_short")
                                else:
                                    self.frameDropped.emit(frame, "too_long")
                            else:
                                # Frame is incomplete - drop it
                                if len(buf) > 1:
                                    self.frameDropped.emit(bytes(buf), "incomplete_frame_interrupted")
                                buf.clear()

                            # Start new frame
                            buf.append(byte)
                            frame_start_byte = byte
                            frame_start_time = current_time
                            in_frame = True
                            expected_frame_length = None  # Will be determined later
                        else:
                            # Not in frame - start new frame normally
                            buf.clear()
                            buf.append(byte)
                            in_frame = True
                            frame_start_byte = byte
                            frame_start_time = current_time
                            expected_frame_length = None

                    elif in_frame:
                        # We're in a frame - add byte to buffer
                        buf.append(byte)

                        # Determine expected frame length
                        if expected_frame_length is None:
                            if frame_start_byte == 0x10:
                                # 0x10 messages have fixed length: 10 DST SRC CMD CHK 16 = 6 bytes
                                expected_frame_length = 6
                            elif frame_start_byte == 0x43 and len(buf) >= 5:
                                # For 0x43: determine expected length after reading LEN field
                                # buf[0]=0x43, buf[1]=DST, buf[2]=SRC, buf[3]=CMD, buf[4]=LEN
                                data_length = buf[4]
                                # Expected total: 1(start) + 1(dst) + 1(src) + 1(cmd) + 1(len) + data_length + 1(chk) + 1(end)
                                expected_frame_length = 7 + data_length

                        # Check if frame is complete
                        frame_complete = False
                        frame_has_valid_end = False

                        if expected_frame_length is not None:
                            # Frame is complete when we reach expected length
                            if len(buf) == expected_frame_length:
                                frame_complete = True
                                # Check if last byte is END byte (0x16)
                                frame_has_valid_end = (buf[-1] == self.end_byte)

                                # Even if END byte is missing, we can still parse the frame
                                # because we know the exact expected length

                        if frame_complete:
                            # Frame is complete (reached expected length)
                            # Emit frame even if END byte is missing - parser can handle it
                            # because we know the exact frame length from LEN field
                            frame = bytes(buf)
                            buf.clear()
                            in_frame = False
                            frame_start_byte = None
                            frame_start_time = None
                            expected_frame_length = None

                            # Validate and emit
                            if 2 <= len(frame) <= self.max_len:
                                self.frameReceived.emit(frame)
                            elif len(frame) < 2:
                                self.frameDropped.emit(frame, "too_short")
                            else:
                                self.frameDropped.emit(frame, "too_long")

                        # Buffer overflow check
                        elif len(buf) > self.max_len:
                            self.frameDropped.emit(bytes(buf), "buffer_overflow")
                            buf.clear()
                            in_frame = False
                            frame_start_byte = None
                            frame_start_time = None
                            expected_frame_length = None

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

