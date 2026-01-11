import sys
import time
import socket
import threading
from dataclasses import dataclass

# Try import scapy
try:
    from scapy.all import sniff, TCP, IP  # type: ignore
    from scapy.all import get_if_list, get_if_addr  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
    get_if_list = None  # type: ignore
    get_if_addr = None  # type: ignore

from PySide6 import QtCore, QtWidgets
import serial
import serial.tools.list_ports

import config

@dataclass
class LogEvent:
    ts_ms: int
    source: str  # 'TCP' or 'UART'
    message: str

class TcpClient(QtCore.QObject):
    connected = QtCore.Signal()
    disconnected = QtCore.Signal(str)  # reason
    dataReceived = QtCore.Signal(bytes)
    errorOccurred = QtCore.Signal(str)

    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
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
            if self._sock:
                self._sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _run(self):
        reconnect_delay = 0.5  # seconds
        while not self._stop.is_set():
            # Try to connect, keep retrying until success or stop
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.settimeout(2)
                self._sock.connect((self.host, self.port))
                self._sock.settimeout(0.2)
                self.connected.emit()
            except Exception as e:
                self.errorOccurred.emit(f"TCP connect error: {e}")
                # Wait and retry, do not emit disconnected yet
                try:
                    if self._sock:
                        self._sock.close()
                except Exception:
                    pass
                self._sock = None
                # small sleep before retry
                for _ in range(int(reconnect_delay*10)):
                    if self._stop.is_set():
                        break
                    time.sleep(0.1)
                continue

            # Once connected, read until error/peer close/stop
            try:
                while not self._stop.is_set():
                    try:
                        data = self._sock.recv(4096)
                        if not data:
                            # Peer closed
                            self.disconnected.emit("peer_closed")
                            break
                        self.dataReceived.emit(data)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.errorOccurred.emit(f"TCP recv error: {e}")
                        break
            finally:
                try:
                    if self._sock:
                        self._sock.close()
                except Exception:
                    pass
                self._sock = None
                # If not stopping, go back to connect loop
                if not self._stop.is_set():
                    self.disconnected.emit("reconnect")
        # Final exit
        self.disconnected.emit("stopped")

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

class TcpSniffer(QtCore.QObject):
    connected = QtCore.Signal()  # emitted when capture starts
    disconnected = QtCore.Signal(str)
    dataReceived = QtCore.Signal(bytes)
    errorOccurred = QtCore.Signal(str)

    def __init__(self, port: int, iface: str | None = None, target_ip: str | None = None):
        super().__init__()
        self.port = port
        self.iface = iface
        self.target_ip = target_ip
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self):
        if not SCAPY_AVAILABLE:
            self.errorOccurred.emit("Scapy not available. Install scapy and Npcap on Windows.")
            self.disconnected.emit("no_scapy")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        try:
            bpf_filter = f"tcp port {self.port}"
            if self.target_ip:
                bpf_filter += f" and host {self.target_ip}"
            self.connected.emit()
            def _prn(pkt):
                if self._stop.is_set():
                    return
                try:
                    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                        return
                    ip_layer = pkt[IP]
                    tcp_layer = pkt[TCP]
                    # Filter by target_ip if provided
                    if self.target_ip and (self.target_ip not in [ip_layer.src, ip_layer.dst]):
                        return
                    payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
                    if payload:
                        self.dataReceived.emit(payload)
                except Exception:
                    pass
            sniff(filter=bpf_filter, prn=_prn, store=False, iface=self.iface, stop_filter=lambda x: self._stop.is_set())
        except Exception as e:
            self.errorOccurred.emit(f"Sniffer error: {e}")
        finally:
            self.disconnected.emit("stopped")

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Egon Comunication Analyzer")
        self.resize(config.GUI_WIDTH, config.GUI_HEIGHT)
        font = QtWidgets.QApplication.font()
        font.setFamily(config.GUI_FONT[0])
        font.setPointSize(config.GUI_FONT[1])
        QtWidgets.QApplication.setFont(font)

        # Controls
        self.tcpHostEdit = QtWidgets.QLineEdit(config.TCP_DEFAULT_TARGET_IP)
        self.tcpPortEdit = QtWidgets.QLineEdit(str(config.TCP_DEFAULT_PORT))
        # Interface selection (Scapy)
        self.ifaceCombo = QtWidgets.QComboBox()
        self.ifaceCombo.setEditable(False)
        self.refreshIfaceButton = QtWidgets.QPushButton("Refresh IFs")
        self.refreshIfaceButton.setToolTip("Refresh network interfaces for Scapy")
        ifaceRow = QtWidgets.QHBoxLayout()
        ifaceRow.setContentsMargins(0, 0, 0, 0)
        ifaceRow.addWidget(self.ifaceCombo)
        ifaceRow.addWidget(self.refreshIfaceButton)
        ifaceWidget = QtWidgets.QWidget()
        ifaceWidget.setLayout(ifaceRow)
        if not SCAPY_AVAILABLE:
            self.ifaceCombo.setEnabled(False)
            self.refreshIfaceButton.setEnabled(False)
        # Sniffer mode controls
        self.snifferModeCheck = QtWidgets.QCheckBox("TCP Sniffer mode (Scapy)")
        self.snifferModeCheck.setChecked(True if SCAPY_AVAILABLE else False)
        self.filterByHostCheck = QtWidgets.QCheckBox("Filter by target IP")
        self.filterByHostCheck.setChecked(True)
        self.scapyStatusLabel = QtWidgets.QLabel("Scapy: available" if SCAPY_AVAILABLE else "Scapy: not available")
        self.recheckScapyButton = QtWidgets.QPushButton("Recheck Scapy")
        self.recheckScapyButton.setToolTip("Try to import Scapy again. Ensure Npcap is installed on Windows.")
        scapyRow = QtWidgets.QHBoxLayout()
        scapyRow.addWidget(self.snifferModeCheck)
        scapyRow.addWidget(self.filterByHostCheck)
        scapyRow.addWidget(self.scapyStatusLabel)
        scapyRow.addWidget(self.recheckScapyButton)
        scapyWidget = QtWidgets.QWidget()
        scapyWidget.setLayout(scapyRow)
        # Serial controls
        self.serialPortCombo = QtWidgets.QComboBox()
        self.refreshSerialButton = QtWidgets.QPushButton("Refresh")
        self.refreshSerialButton.setToolTip("Detect available COM ports from this PC")
        sp_widget = QtWidgets.QWidget()
        sp_h = QtWidgets.QHBoxLayout(sp_widget)
        sp_h.setContentsMargins(0, 0, 0, 0)
        sp_h.addWidget(self.serialPortCombo)
        sp_h.addWidget(self.refreshSerialButton)
        self.serialBaudEdit = QtWidgets.QLineEdit(str(config.SERIAL_DEFAULT_BAUDRATE))
        # Buttons
        self.startButton = QtWidgets.QPushButton("Start")
        self.stopButton = QtWidgets.QPushButton("Stop")
        self.stopButton.setEnabled(False)
        # Tables
        self.tcpTable = QtWidgets.QTableWidget(0, 2)
        self.tcpTable.setHorizontalHeaderLabels(["Time", "TCP Event"])
        self.tcpTable.horizontalHeader().setStretchLastSection(True)
        self.tcpTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.tcpTable.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.uartTable = QtWidgets.QTableWidget(0, 2)
        self.uartTable.setHorizontalHeaderLabels(["Time", "UART Event"])
        self.uartTable.horizontalHeader().setStretchLastSection(True)
        self.uartTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.uartTable.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)

        # Form
        topForm = QtWidgets.QFormLayout()
        topForm.addRow("TCP Host", self.tcpHostEdit)
        topForm.addRow("TCP Port", self.tcpPortEdit)
        topForm.addRow("Interface", ifaceWidget)
        topForm.addRow("Mode", scapyWidget)
        topForm.addRow("Serial Port", sp_widget)
        topForm.addRow("Serial Baud", self.serialBaudEdit)

        btns = QtWidgets.QHBoxLayout()
        btns.addWidget(self.startButton)
        btns.addWidget(self.stopButton)

        split = QtWidgets.QSplitter()
        tcpPanel = QtWidgets.QWidget()
        tcpLayout = QtWidgets.QVBoxLayout(tcpPanel)
        tcpLayout.addWidget(QtWidgets.QLabel("TCP Monitor"))
        tcpLayout.addWidget(self.tcpTable)
        uartPanel = QtWidgets.QWidget()
        uartLayout = QtWidgets.QVBoxLayout(uartPanel)
        uartLayout.addWidget(QtWidgets.QLabel("UART Monitor"))
        uartLayout.addWidget(self.uartTable)
        split.addWidget(tcpPanel)
        split.addWidget(uartPanel)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 1)

        top = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(top)
        v.addLayout(topForm)
        v.addLayout(btns)
        v.addWidget(split)
        self.setCentralWidget(top)

        # State
        self.tcp: TcpClient | None = None
        self.tcpSniffer: TcpSniffer | None = None
        self.uart: UartReader | None = None
        self.lastTcpConnectTs: int | None = None
        self._tcpEvents: list[LogEvent] = []
        self._uartEvents: list[LogEvent] = []
        self._synchronizingSelection = False  # prevent recursion

        # Wire up
        self.startButton.clicked.connect(self.onStart)
        self.stopButton.clicked.connect(self.onStop)
        self.tcpTable.itemSelectionChanged.connect(self._onTcpSelectionChanged)
        self.uartTable.itemSelectionChanged.connect(self._onUartSelectionChanged)
        # Refresh button wiring and initial population
        self.refreshSerialButton.clicked.connect(self.refresh_serial_ports)
        self.refreshIfaceButton.clicked.connect(self.refresh_ifaces)
        self.recheckScapyButton.clicked.connect(self._recheck_scapy)
        # Populate interfaces initially
        self.refresh_ifaces()

    def refresh_serial_ports(self):
        """Detect COM ports on the PC and populate the serialPortCombo."""
        # Keep signals blocked to avoid accidental triggers while updating
        self.serialPortCombo.blockSignals(True)
        self.serialPortCombo.clear()
        # Add default from config as first/fallback entry (if set)
        if getattr(config, "SERIAL_DEFAULT_PORT", ""):
            self.serialPortCombo.addItem(config.SERIAL_DEFAULT_PORT)
        # Detect available ports and add them (avoid duplicates)
        existing = {self.serialPortCombo.itemText(i) for i in range(self.serialPortCombo.count())}
        for p in serial.tools.list_ports.comports():
            if p.device not in existing:
                self.serialPortCombo.addItem(p.device)
        # Select first real detected port if available (prefer non-default if present)
        if self.serialPortCombo.count() > 0:
            self.serialPortCombo.setCurrentIndex(0)
        self.serialPortCombo.blockSignals(False)

    def refresh_ifaces(self):
        self.ifaceCombo.blockSignals(True)
        self.ifaceCombo.clear()
        if SCAPY_AVAILABLE and get_if_list:
            try:
                names = list(get_if_list())  # type: ignore
                # Prefer non-loopback first
                names_sorted = sorted(names, key=lambda n: ("loopback" in n.lower(), n.lower()))
                for name in names_sorted:
                    ip = ""
                    try:
                        if get_if_addr:
                            ip = get_if_addr(name)  # type: ignore
                    except Exception:
                        ip = ""
                    label = f"{name}{f' ({ip})' if ip else ''}"
                    self.ifaceCombo.addItem(label, userData=name)
                if self.ifaceCombo.count() > 0:
                    self.ifaceCombo.setCurrentIndex(0)
            except Exception as e:
                self._onError("TCP", f"Failed to list interfaces: {e}")
        self.ifaceCombo.blockSignals(False)

    def _fmt_ts(self, ts_ms: int) -> str:
        return time.strftime('%H:%M:%S', time.localtime(ts_ms / 1000)) + f".{ts_ms % 1000:03d}"

    def _append_to_table(self, table: QtWidgets.QTableWidget, ev: LogEvent):
        row = table.rowCount()
        table.insertRow(row)
        table.setItem(row, 0, QtWidgets.QTableWidgetItem(self._fmt_ts(ev.ts_ms)))
        table.setItem(row, 1, QtWidgets.QTableWidgetItem(ev.message))
        table.scrollToBottom()

    def appendLog(self, ev: LogEvent):
        # ...existing code replaced by table logging...
        if ev.source == "TCP":
            self._tcpEvents.append(ev)
            self._append_to_table(self.tcpTable, ev)
        else:
            self._uartEvents.append(ev)
            self._append_to_table(self.uartTable, ev)

    def _recheck_scapy(self):
        global SCAPY_AVAILABLE, sniff, TCP, IP, get_if_list, get_if_addr
        try:
            from scapy.all import sniff as _sniff, TCP as _TCP, IP as _IP, get_if_list as _gil, get_if_addr as _gia  # type: ignore
            sniff, TCP, IP, get_if_list, get_if_addr = _sniff, _TCP, _IP, _gil, _gia
            SCAPY_AVAILABLE = True
            self.scapyStatusLabel.setText("Scapy: available")
            self.ifaceCombo.setEnabled(True)
            self.refreshIfaceButton.setEnabled(True)
            if not self.snifferModeCheck.isChecked():
                self.snifferModeCheck.setChecked(True)
            self.refresh_ifaces()
        except Exception as e:
            SCAPY_AVAILABLE = False
            self.scapyStatusLabel.setText("Scapy: not available")
            self.ifaceCombo.setEnabled(False)
            self.refreshIfaceButton.setEnabled(False)
            self._onError("TCP", f"Scapy import failed: {e}. Install scapy and Npcap on Windows.")

    def onStart(self):
        host = self.tcpHostEdit.text().strip()
        port = int(self.tcpPortEdit.text().strip())
        ser_port = self.serialPortCombo.currentText().strip()
        baud = int(self.serialBaudEdit.text().strip())

        # Reset tables/events
        self.tcpTable.setRowCount(0)
        self.uartTable.setRowCount(0)
        self._tcpEvents.clear()
        self._uartEvents.clear()

        # Use sniffer if available and enabled, else fallback to TcpClient
        use_sniffer = self.snifferModeCheck.isChecked() and SCAPY_AVAILABLE
        if use_sniffer:
            iface_name = None
            if self.ifaceCombo.count() > 0:
                iface_name = self.ifaceCombo.currentData()
            filter_host = host if self.filterByHostCheck.isChecked() and host else None
            bpf = f"tcp port {port}" + (f" and host {filter_host}" if filter_host else "")
            self.appendLog(LogEvent(int(time.time()*1000), "TCP", f"starting sniffer on iface='{iface_name or 'default'}' filter='{bpf}'"))
            self.tcpSniffer = TcpSniffer(port=port, iface=iface_name, target_ip=filter_host)
            self.tcpSniffer.connected.connect(lambda: self._onTcpConnected())
            self.tcpSniffer.disconnected.connect(lambda reason: self._onTcpDisconnected(reason))
            self.tcpSniffer.dataReceived.connect(lambda data: self._onTcpData(data))
            self.tcpSniffer.errorOccurred.connect(lambda msg: self._onError("TCP", msg))
        else:
            if self.snifferModeCheck.isChecked() and not SCAPY_AVAILABLE:
                self._onError("TCP", "Scapy not available. Falling back to TCP client (active).")
            self.tcp = TcpClient(host, port)
            self.tcp.connected.connect(lambda: self._onTcpConnected())
            self.tcp.disconnected.connect(lambda reason: self._onTcpDisconnected(reason))
            self.tcp.dataReceived.connect(lambda data: self._onTcpData(data))
            self.tcp.errorOccurred.connect(lambda msg: self._onError("TCP", msg))

        # UART
        self.uart = UartReader(
            ser_port, baud,
            config.SERIAL_START_BYTE,
            config.SERIAL_END_BYTE,
            config.SERIAL_MAX_MESSAGE_LENGTH,
        )
        self.uart.opened.connect(lambda p: self.appendLog(LogEvent(int(time.time()*1000), "UART", f"opened {p}")))
        self.uart.closed.connect(lambda r: self.appendLog(LogEvent(int(time.time()*1000), "UART", f"closed ({r})")))
        self.uart.frameReceived.connect(lambda frame: self._onUartFrame(frame))
        self.uart.errorOccurred.connect(lambda msg: self._onError("UART", msg))
        # Start
        if use_sniffer and self.tcpSniffer:
            self.tcpSniffer.start()
        elif self.tcp:
            self.tcp.start()
        self.uart.start()
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def onStop(self):
        if self.tcp:
            self.tcp.stop()
        if self.tcpSniffer:
            self.tcpSniffer.stop()
        if self.uart:
            self.uart.stop()
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)

    # Handlers
    def _onTcpConnected(self):
        ts = int(time.time()*1000)
        self.lastTcpConnectTs = ts
        self.appendLog(LogEvent(ts, "TCP", "connected"))

    def _onTcpDisconnected(self, reason: str):
        self.appendLog(LogEvent(int(time.time()*1000), "TCP", f"disconnected ({reason})"))

    def _onTcpData(self, data: bytes):
        preview = data[:32]
        self.appendLog(LogEvent(int(time.time()*1000), "TCP", f"rx {len(data)} bytes: {preview.hex()}..."))

    def _onUartFrame(self, frame: bytes):
        ts = int(time.time()*1000)
        msg = f"frame {len(frame)} bytes: {frame.hex()}"
        if self.lastTcpConnectTs is not None and (ts - self.lastTcpConnectTs) <= config.TIME_PAIRING_THRESHOLD:
            msg += " [paired after TCP connect]"
        self.appendLog(LogEvent(ts, "UART", msg))

    def _onError(self, src: str, msg: str):
        self.appendLog(LogEvent(int(time.time()*1000), src, f"ERROR: {msg}"))

    # Selection sync
    def _select_nearest_in(self, target_table: QtWidgets.QTableWidget, target_events: list[LogEvent], ts_ms: int):
        # Find nearest event within threshold
        best_idx = None
        best_delta = None
        for i, ev in enumerate(target_events):
            d = abs(ev.ts_ms - ts_ms)
            if best_delta is None or d < best_delta:
                best_delta = d
                best_idx = i
        if best_idx is not None and best_delta is not None and best_delta <= config.TIME_PAIRING_THRESHOLD:
            target_table.selectRow(best_idx)
            target_table.scrollToItem(target_table.item(best_idx, 0))

    def _onTcpSelectionChanged(self):
        if self._synchronizingSelection:
            return
        selected = self.tcpTable.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        if row < 0 or row >= len(self._tcpEvents):
            return
        ts_ms = self._tcpEvents[row].ts_ms
        try:
            self._synchronizingSelection = True
            self._select_nearest_in(self.uartTable, self._uartEvents, ts_ms)
        finally:
            self._synchronizingSelection = False

    def _onUartSelectionChanged(self):
        if self._synchronizingSelection:
            return
        selected = self.uartTable.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        if row < 0 or row >= len(self._uartEvents):
            return
        ts_ms = self._uartEvents[row].ts_ms
        try:
            self._synchronizingSelection = True
            self._select_nearest_in(self.tcpTable, self._tcpEvents, ts_ms)
        finally:
            self._synchronizingSelection = False


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
