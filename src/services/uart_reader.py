import threading
from PySide6 import QtCore
import serial

class UartReader(QtCore.QObject):
    opened = QtCore.Signal(str)  # port
    closed = QtCore.Signal(str)
    frameReceived = QtCore.Signal(bytes)
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
        try:
            while not self._stop.is_set():
                try:
                    b = self._ser.read(1)
                    if not b:
                        continue
                    byte = b[0]
                    if byte == self.start_byte:
                        buf.clear()
                        buf.append(byte)
                    else:
                        if buf:
                            buf.append(byte)
                            if byte == self.end_byte:
                                frame = bytes(buf)
                                buf.clear()
                                if 2 <= len(frame) <= self.max_len:
                                    self.frameReceived.emit(frame)
                            elif len(buf) > self.max_len:
                                buf.clear()
                except Exception as e:
                    self.errorOccurred.emit(f"UART read error: {e}")
                    break
        finally:
            try:
                self._ser.close()
            except Exception:
                pass
            self.closed.emit("stopped")

