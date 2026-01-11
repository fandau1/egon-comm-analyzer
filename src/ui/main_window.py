import time
from PySide6 import QtWidgets
from PySide6 import QtGui

from src import config
from src.core.models import LogEvent
from src.services.tcp_sniffer import TcpSniffer
from src.services.uart_reader import UartReader
from src.services.filters import UartFilter
from src.services.tcp_parser import parse_tcp_message
from scapy.all import get_if_list, get_if_addr

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None

class UartFilterDialog(QtWidgets.QDialog):
    """Dialog pro nastavení UART filtrů."""
    def __init__(self, parent=None, initial: UartFilter | None = None):
        super().__init__(parent)
        self.setWindowTitle("UART Filter Settings")
        self.setModal(True)
        self.resize(480, 180)

        self.enableCheck = QtWidgets.QCheckBox("Enable UART Filter")
        self.modeCombo = QtWidgets.QComboBox()
        self.modeCombo.addItems(["include", "exclude"])
        self.matchCombo = QtWidgets.QComboBox()
        self.matchCombo.addItems(["exact", "substring"])
        self.patternsEdit = QtWidgets.QLineEdit()
        self.patternsEdit.setPlaceholderText("Hex patterns separated by comma, e.g., 10a0553c3116,1001ff")

        if initial:
            self.enableCheck.setChecked(initial.enabled)
            self.modeCombo.setCurrentText(initial.mode)
            self.matchCombo.setCurrentText(initial.match_type)
            self.patternsEdit.setText(
                ",".join(initial.patterns)
            )
        else:
            self.enableCheck.setChecked(getattr(config, 'UART_FILTER_ENABLED', True))
            self.modeCombo.setCurrentText(getattr(config, 'UART_FILTER_MODE', 'include'))
            self.matchCombo.setCurrentText(getattr(config, 'UART_FILTER_MATCH', 'exact'))
            self.patternsEdit.setText(
                ",".join(getattr(config, 'UART_FILTER_HEX_PATTERNS', []))
            )

        form = QtWidgets.QFormLayout()
        form.addRow(self.enableCheck)
        form.addRow("Mode:", self.modeCombo)
        form.addRow("Match:", self.matchCombo)
        form.addRow("Patterns:", self.patternsEdit)

        btnBox = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btnBox.accepted.connect(self.accept)
        btnBox.rejected.connect(self.reject)

        v = QtWidgets.QVBoxLayout(self)
        v.addLayout(form)
        v.addWidget(btnBox)

    def get_filter(self) -> UartFilter:
        return UartFilter(
            enabled=self.enableCheck.isChecked(),
            mode=self.modeCombo.currentText(),
            match_type=self.matchCombo.currentText(),
            patterns=[p.strip().lower() for p in self.patternsEdit.text().split(',') if p.strip()],
        )


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Egon Communication Analyzer")
        self.resize(config.GUI_WIDTH, config.GUI_HEIGHT)
        font = QtWidgets.QApplication.font()
        font.setFamily(config.GUI_FONT[0])
        font.setPointSize(config.GUI_FONT[1])
        QtWidgets.QApplication.setFont(font)

        # Controls (compact top form)
        self.tcpHostEdit = QtWidgets.QLineEdit(config.TCP_DEFAULT_TARGET_IP)
        self.tcpHostEdit.setPlaceholderText("Target IP")
        self.tcpPortEdit = QtWidgets.QLineEdit(str(config.TCP_DEFAULT_PORT))
        self.tcpPortEdit.setFixedWidth(80)
        self.tcpPortEdit.setPlaceholderText("Port")
        # Interface selection (Scapy)
        self.ifaceCombo = QtWidgets.QComboBox()
        self.ifaceCombo.setEditable(False)
        # Use a small icon-only toolbutton for refresh
        self.refreshIfaceButton = QtWidgets.QToolButton()
        self.refreshIfaceButton.setToolTip("Refresh network interfaces for Scapy")
        self.refreshIfaceButton.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_BrowserReload))
        self.refreshIfaceButton.setAutoRaise(True)
        self.refreshIfaceButton.setFixedSize(24, 24)
        ifaceRow = QtWidgets.QHBoxLayout()
        ifaceRow.setContentsMargins(0, 0, 0, 0)
        ifaceRow.addWidget(self.ifaceCombo, stretch=1)
        ifaceRow.addWidget(self.refreshIfaceButton)
        ifaceWidget = QtWidgets.QWidget()
        ifaceWidget.setLayout(ifaceRow)
        # Filter by target IP
        self.filterByHostCheck = QtWidgets.QCheckBox("Filter by target IP")
        self.filterByHostCheck.setChecked(True)
        # Serial controls
        self.serialPortCombo = QtWidgets.QComboBox()
        # Small icon-only toolbutton for serial refresh
        self.refreshSerialButton = QtWidgets.QToolButton()
        self.refreshSerialButton.setToolTip("Detect available COM ports from this PC")
        self.refreshSerialButton.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_BrowserReload))
        self.refreshSerialButton.setAutoRaise(True)
        self.refreshSerialButton.setFixedSize(24, 24)
        sp_widget = QtWidgets.QWidget()
        sp_h = QtWidgets.QHBoxLayout(sp_widget)
        sp_h.setContentsMargins(0, 0, 0, 0)
        sp_h.addWidget(self.serialPortCombo, stretch=1)
        sp_h.addWidget(self.refreshSerialButton)
        # Baud edit stays full width
        self.serialBaudEdit = QtWidgets.QLineEdit(str(config.SERIAL_DEFAULT_BAUDRATE))
        self.serialBaudEdit.setFixedWidth(100)
        self.serialBaudEdit.setPlaceholderText("Baud")

        # Buttons
        self.startButton = QtWidgets.QPushButton("Start")
        self.stopButton = QtWidgets.QPushButton("Stop")
        self.stopButton.setEnabled(False)

        # Tables (main communication panels)
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

        # Top bar restructured into two compact rows
        topBar = QtWidgets.QWidget()
        topGrid = QtWidgets.QGridLayout(topBar)
        topGrid.setContentsMargins(0, 0, 0, 0)
        topGrid.setHorizontalSpacing(8)
        topGrid.setVerticalSpacing(6)
        # Row 0: IP, Port, Interface, FilterByIP
        row0 = QtWidgets.QHBoxLayout()
        row0.setContentsMargins(0, 0, 0, 0)
        row0.addWidget(QtWidgets.QLabel("IP:"))
        row0.addWidget(self.tcpHostEdit, stretch=1)
        row0.addSpacing(6)
        row0.addWidget(QtWidgets.QLabel("Port:"))
        row0.addWidget(self.tcpPortEdit)
        row0.addSpacing(12)
        row0.addWidget(QtWidgets.QLabel("Interface:"))
        row0.addWidget(ifaceWidget, stretch=1)
        row0.addSpacing(12)
        row0.addWidget(self.filterByHostCheck)
        row0Widget = QtWidgets.QWidget()
        row0Widget.setLayout(row0)
        topGrid.addWidget(row0Widget, 0, 0)

        # Row 1: Serial Port, Baud, Start/Stop
        row1 = QtWidgets.QHBoxLayout()
        row1.setContentsMargins(0, 0, 0, 0)
        row1.addWidget(QtWidgets.QLabel("Serial:"))
        row1.addWidget(sp_widget, stretch=1)
        row1.addSpacing(12)
        row1.addWidget(QtWidgets.QLabel("Baud:"))
        row1.addWidget(self.serialBaudEdit)
        row1.addStretch(1)
        row1.addWidget(self.startButton)
        row1.addWidget(self.stopButton)
        row1Widget = QtWidgets.QWidget()
        row1Widget.setLayout(row1)
        topGrid.addWidget(row1Widget, 1, 0)

        # Main splitter occupies most of the window
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

        # Central layout
        container = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(container)
        v.setContentsMargins(8, 8, 8, 8)
        v.setSpacing(8)
        v.addWidget(topBar)
        v.addWidget(split, stretch=1)
        self.setCentralWidget(container)

        # Menu bar: Settings -> UART Filter
        settingsMenu = self.menuBar().addMenu("Settings")
        self.uartFilterAction = settingsMenu.addAction("UART Filter…")
        self.uartFilterAction.triggered.connect(self._open_uart_filter_dialog)

        # Status bar
        self.statusBar().showMessage("Ready")

        # State
        self.tcpSniffer: TcpSniffer | None = None
        self.uart: UartReader | None = None
        self.lastTcpConnectTs: int | None = None
        self._tcpEvents: list[LogEvent] = []
        self._uartEvents: list[LogEvent] = []
        self._synchronizingSelection = False  # prevent recursion
        self._uartFilter = UartFilter(
            enabled=getattr(config, 'UART_FILTER_ENABLED', True),
            mode=getattr(config, 'UART_FILTER_MODE', 'include'),
            match_type=getattr(config, 'UART_FILTER_MATCH', 'exact'),
            patterns=getattr(config, 'UART_FILTER_HEX_PATTERNS', []),
        )

        # Wire up
        self.startButton.clicked.connect(self.onStart)
        self.stopButton.clicked.connect(self.onStop)
        self.tcpTable.itemSelectionChanged.connect(self._onTcpSelectionChanged)
        self.uartTable.itemSelectionChanged.connect(self._onUartSelectionChanged)
        self.refreshSerialButton.clicked.connect(self.refresh_serial_ports)
        self.refreshIfaceButton.clicked.connect(self.refresh_ifaces)
        # Populate initially
        self.refresh_ifaces()
        self.refresh_serial_ports()

    def _open_uart_filter_dialog(self):
        dlg = UartFilterDialog(self, self._uartFilter)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            self._uartFilter = dlg.get_filter()
            self.statusBar().showMessage("UART filter updated", 3000)

    def refresh_serial_ports(self):
        self.serialPortCombo.blockSignals(True)
        self.serialPortCombo.clear()
        # Add default from config
        if getattr(config, "SERIAL_DEFAULT_PORT", ""):
            self.serialPortCombo.addItem(config.SERIAL_DEFAULT_PORT)
        existing = {self.serialPortCombo.itemText(i) for i in range(self.serialPortCombo.count())}
        import serial.tools.list_ports
        for p in serial.tools.list_ports.comports():
            if p.device not in existing:
                self.serialPortCombo.addItem(p.device)
        if self.serialPortCombo.count() > 0:
            self.serialPortCombo.setCurrentIndex(0)
        self.serialPortCombo.blockSignals(False)

    def refresh_ifaces(self):
        self.ifaceCombo.blockSignals(True)
        self.ifaceCombo.clear()
        entries = []
        try:
            # Primárně Windows detailní seznam
            if get_windows_if_list:
                win_ifaces = get_windows_if_list()

                # Vyřadit prázdné/filtrační/virt adaptéry bez IP
                def is_noise(name: str) -> bool:
                    nl = name.lower()
                    return any(tok in nl for tok in [
                        "wfp", "npcap packet driver", "virtual switch extension", "extension filter",
                        "lightweight filter", "wan miniport", "pseudo-interface", "hyper-v virtual"
                    ])

                for it in win_ifaces:
                    name = it.get("name") or it.get("description") or ""
                    if not name or is_noise(name):
                        continue
                    ips = it.get("ips") or []
                    # Preferovat záznamy s IPv4
                    ipv4 = next((ip for ip in ips if "." in ip), "")
                    ipv6 = next((ip for ip in ips if ":" in ip and ip != "::1"), "")
                    if not ipv4 and not ipv6:
                        continue
                    label_ip = ipv4 or ipv6
                    entries.append((name, label_ip))
            # Fallback: klasický seznam jmen
            if not entries:
                names = list(get_if_list())
                for name in sorted(names, key=lambda n: ("loopback" in n.lower(), n.lower())):
                    ip = ""
                    try:
                        ip = get_if_addr(name)
                    except Exception:
                        ip = ""
                    if not ip and "loopback" in name.lower():
                        continue
                    entries.append((name, ip))
            # Naplnit combo
            for name, ip in entries:
                label = f"{name}{f' ({ip})' if ip else ''}"
                self.ifaceCombo.addItem(label, userData=name)
            if self.ifaceCombo.count() > 0:
                # Preferovat ne-loopback s IPv4
                preferred = 0
                for i in range(self.ifaceCombo.count()):
                    text = self.ifaceCombo.itemText(i).lower()
                    if "(" in text and "127.0.0.1" not in text and "loopback" not in text:
                        preferred = i
                        break
                self.ifaceCombo.setCurrentIndex(preferred)
            else:
                self._onError("TCP",
                              "Nenalezena žádná síťová rozhraní. Spusťte jako Administrator a zkontrolujte Npcap.")
        except Exception as e:
            self._onError("TCP", f"Chyba při výpisu rozhraní: {e}")
        finally:
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
        if ev.source == "TCP":
            self._tcpEvents.append(ev)
            self._append_to_table(self.tcpTable, ev)
        else:
            self._uartEvents.append(ev)
            self._append_to_table(self.uartTable, ev)

    def onStart(self):
        host = self.tcpHostEdit.text().strip()
        port = int(self.tcpPortEdit.text().strip())
        ser_port = self.serialPortCombo.currentText().strip()
        baud = int(self.serialBaudEdit.text().strip())

        self.tcpTable.setRowCount(0)
        self.uartTable.setRowCount(0)
        self._tcpEvents.clear()
        self._uartEvents.clear()

        iface_name = None
        if self.ifaceCombo.count() > 0:
            iface_name = self.ifaceCombo.currentData()
        filter_host = host if self.filterByHostCheck.isChecked() and host else None
        bpf = f"tcp port {port}" + (f" and host {filter_host}" if filter_host else "")
        self.appendLog(LogEvent(int(time.time()*1000), "TCP", f"starting sniffer on iface='{iface_name or 'default'}' filter='{bpf}'"))
        self.tcpSniffer = TcpSniffer(port=port, iface=iface_name, target_ip=filter_host)
        self.tcpSniffer.connected.connect(lambda: self._onTcpConnected())
        self.tcpSniffer.disconnected.connect(lambda reason: self._onTcpDisconnected(reason))
        # Use directional signal
        self.tcpSniffer.dataReceivedDir.connect(lambda data, direction: self._onTcpDataDir(data, direction))
        self.tcpSniffer.errorOccurred.connect(lambda msg: self._onError("TCP", msg))

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

        self.tcpSniffer.start()
        self.uart.start()
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def onStop(self):
        if self.tcpSniffer:
            self.tcpSniffer.stop()
        if self.uart:
            self.uart.stop()
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)

    def _onTcpConnected(self):
        ts = int(time.time()*1000)
        self.lastTcpConnectTs = ts
        self.appendLog(LogEvent(ts, "TCP", "connected"))

    def _onTcpDisconnected(self, reason: str):
        self.appendLog(LogEvent(int(time.time()*1000), "TCP", f"disconnected ({reason})"))

    def _onTcpDataDir(self, data: bytes, direction: str):
        rec = parse_tcp_message(data)
        ts_ms = int(time.time() * 1000)
        if rec is not None:
            seg_count = len(rec.segments)
            header = f"M={rec.m or ''} S={rec.s or ''} P={rec.p or ''}"
            segments_full = ", ".join(f"{sid}:{sval}" for sid, sval in rec.segments.items())
            msg = f"{direction} | TCP parsed: {header} | segments={seg_count}{(' | ' + segments_full) if segments_full else ''}"
        else:
            msg = f"{direction} | {len(data)} bytes: {data}"
        ev = LogEvent(ts_ms, "TCP", msg)
        # append and colorize row
        prev_rows = self.tcpTable.rowCount()
        self.appendLog(ev)
        color = QtGui.QColor("#e7f7e7") if direction.upper() == "RX" else QtGui.QColor("#ffe9e6")
        for col in range(self.tcpTable.columnCount()):
            item = self.tcpTable.item(prev_rows, col)
            if item:
                item.setBackground(QtGui.QBrush(color))

    def _onUartFrame(self, frame: bytes):
        if not self._uartFilter.passes(frame):
            return
        ts = int(time.time()*1000)
        msg = f"frame {len(frame)} bytes: {frame.hex()}"
        if self.lastTcpConnectTs is not None and (ts - self.lastTcpConnectTs) <= config.TIME_PAIRING_THRESHOLD:
            msg += " [paired after TCP connect]"
        self.appendLog(LogEvent(ts, "UART", msg))

    def _onError(self, src: str, msg: str):
        self.appendLog(LogEvent(int(time.time()*1000), src, f"ERROR: {msg}"))

    def _select_nearest_in(self, target_table: QtWidgets.QTableWidget, target_events: list[LogEvent], ts_ms: int):
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
