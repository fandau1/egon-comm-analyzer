import threading
from PySide6 import QtCore
import serial

class UartReader(QtCore.QObject):
    """
    UART frame reader with simple START/END detection.

    Protocol:
    - START byte: 0x10 - begins a new frame
    - END byte: 0x16 - marks end of frame

    Frame format: 10 [data...] 16

    Simple parsing:
    - 0x10 starts new frame (discards incomplete previous frame)
    - 0x16 ends current frame
    - No escaping/stuffing
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
        self.start_byte = start_byte
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

        try:
            while not self._stop.is_set():
                try:
                    b = self._ser.read(1)
                    if not b:
                        continue
                    byte = b[0]

                    # Emit raw data before any parsing
                    self.rawDataReceived.emit(b)

                    if byte == self.start_byte:
                        # START byte - begin new frame
                        if in_frame and len(buf) > 0:
                            # Had incomplete frame
                            self.frameDropped.emit(bytes(buf), "incomplete_frame_interrupted")
                        buf.clear()
                        buf.append(byte)
                        in_frame = True

                    elif byte == self.end_byte and in_frame:
                        # END byte - complete frame
                        buf.append(byte)
                        frame = bytes(buf)
                        buf.clear()
                        in_frame = False

                        # Validate and emit
                        if 2 <= len(frame) <= self.max_len:
                            self.frameReceived.emit(frame)
                        elif len(frame) < 2:
                            self.frameDropped.emit(frame, "too_short")
                        else:
                            self.frameDropped.emit(frame, "too_long")

                    elif in_frame:
                        # Data byte
                        buf.append(byte)

                        # Buffer overflow check
                        if len(buf) > self.max_len:
                            self.frameDropped.emit(bytes(buf), "buffer_overflow")
                            buf.clear()
                            in_frame = False

                except Exception as e:
                    self.errorOccurred.emit(f"UART read error: {e}")
                    break
        finally:
            try:
                self._ser.close()
            except Exception:
                pass
            self.closed.emit("stopped")

