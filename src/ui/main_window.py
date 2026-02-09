import time
from PySide6 import QtWidgets
from PySide6 import QtGui

from src import config
from src.core.models import LogEvent
from src.services.tcp_sniffer import TcpSniffer
from src.services.uart_reader import UartReader
from src.services.filters import UartFilter
from src.services.tcp_parser import parse_tcp_message
from src.services.uart_parser import parse_uart_message, get_color_for_id
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


class ChecksumCalculatorDialog(QtWidgets.QDialog):
    """Dialog for calculating UART checksum from hex input."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("UART Checksum Calculator")
        self.setMinimumWidth(500)

        # Input field
        self.inputLabel = QtWidgets.QLabel("Zadejte data v HEX formátu (např. A0 55 49 nebo A05549):")
        self.inputEdit = QtWidgets.QLineEdit()
        self.inputEdit.setPlaceholderText("A0 55 49 nebo A05549")
        self.inputEdit.textChanged.connect(self._calculate)

        # Results
        self.resultLabel = QtWidgets.QLabel("Výsledek:")
        self.resultLabel.setStyleSheet("font-weight: bold;")

        self.checksumLabel = QtWidgets.QLabel("Checksum: -")
        self.checksumLabel.setStyleSheet("font-size: 14pt; color: #0066cc;")

        self.detailsLabel = QtWidgets.QLabel("")
        self.detailsLabel.setWordWrap(True)
        self.detailsLabel.setStyleSheet("color: #666;")

        self.frameLabel = QtWidgets.QLabel("")
        self.frameLabel.setWordWrap(True)
        self.frameLabel.setStyleSheet("font-family: monospace; background-color: #f0f0f0; padding: 8px;")

        # Copy button
        self.copyButton = QtWidgets.QPushButton("Kopírovat checksum")
        self.copyButton.clicked.connect(self._copy_checksum)
        self.copyButton.setEnabled(False)

        # Close button
        closeButton = QtWidgets.QPushButton("Zavřít")
        closeButton.clicked.connect(self.accept)

        # Layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.inputLabel)
        layout.addWidget(self.inputEdit)
        layout.addSpacing(10)
        layout.addWidget(self.resultLabel)
        layout.addWidget(self.checksumLabel)
        layout.addWidget(self.detailsLabel)
        layout.addWidget(self.frameLabel)
        layout.addSpacing(10)

        btnLayout = QtWidgets.QHBoxLayout()
        btnLayout.addWidget(self.copyButton)
        btnLayout.addStretch()
        btnLayout.addWidget(closeButton)
        layout.addLayout(btnLayout)

        self._last_checksum = None

    def _calculate(self):
        """Calculate checksum from input."""
        text = self.inputEdit.text().strip()

        if not text:
            self.checksumLabel.setText("Checksum: -")
            self.detailsLabel.setText("")
            self.frameLabel.setText("")
            self.copyButton.setEnabled(False)
            self._last_checksum = None
            return

        try:
            # Remove spaces and convert to bytes
            hex_str = text.replace(" ", "").replace("0x", "").lower()

            # Validate hex
            if not all(c in '0123456789abcdef' for c in hex_str):
                raise ValueError("Neplatné HEX znaky")

            # Must be even length
            if len(hex_str) % 2 != 0:
                raise ValueError("Lichý počet HEX znaků")

            # Convert to bytes
            data = bytes.fromhex(hex_str)

            if len(data) == 0:
                raise ValueError("Prázdná data")

            # Calculate checksum: sum of all bytes & 0xFF
            checksum = sum(data) & 0xFF
            self._last_checksum = checksum

            # Display result
            self.checksumLabel.setText(f"Checksum: 0x{checksum:02X} ({checksum})")
            self.checksumLabel.setStyleSheet("font-size: 14pt; color: #00cc00;")

            # Details
            byte_list = " + ".join([f"0x{b:02X}" for b in data])
            total = sum(data)
            self.detailsLabel.setText(
                f"Výpočet: {byte_list} = {total} (0x{total:X})\n"
                f"Checksum = {total} & 0xFF = {checksum} (0x{checksum:02X})"
            )

            # Complete frame example (assuming format: 10 <data> CHK 16)
            frame_hex = f"10 {hex_str} {checksum:02x} 16"
            frame_formatted = " ".join([frame_hex[i:i+2] for i in range(0, len(frame_hex.replace(' ', '')), 2)])
            self.frameLabel.setText(f"Kompletní frame:\n{frame_formatted.upper()}")

            self.copyButton.setEnabled(True)

        except ValueError as e:
            self.checksumLabel.setText(f"Chyba: {e}")
            self.checksumLabel.setStyleSheet("font-size: 14pt; color: #cc0000;")
            self.detailsLabel.setText("")
            self.frameLabel.setText("")
            self.copyButton.setEnabled(False)
            self._last_checksum = None

    def _copy_checksum(self):
        """Copy checksum to clipboard."""
        if self._last_checksum is not None:
            QtWidgets.QApplication.clipboard().setText(f"{self._last_checksum:02X}")
            self.copyButton.setText("✓ Zkopírováno!")
            QtWidgets.QTimer.singleShot(2000, lambda: self.copyButton.setText("Kopírovat checksum"))


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
        self.tcpTable.setWordWrap(True)
        self.tcpTable.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.ResizeToContents)

        self.uartTable = QtWidgets.QTableWidget(0, 9)
        self.uartTable.setHorizontalHeaderLabels(["Time", "Type", "From", "To", "CMD", "LEN", "Data (Hex)", "Data (String)", "CHK"])
        self.uartTable.horizontalHeader().setStretchLastSection(True)
        self.uartTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.uartTable.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.uartTable.setWordWrap(True)
        self.uartTable.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        # Set column widths
        self.uartTable.setColumnWidth(0, 100)  # Time
        self.uartTable.setColumnWidth(1, 50)   # Type
        self.uartTable.setColumnWidth(2, 60)   # From
        self.uartTable.setColumnWidth(3, 60)   # To
        self.uartTable.setColumnWidth(4, 60)   # CMD
        self.uartTable.setColumnWidth(5, 50)   # LEN
        self.uartTable.setColumnWidth(6, 200)  # Data (Hex)
        self.uartTable.setColumnWidth(7, 200)  # Data (String)
        self.uartTable.setColumnWidth(8, 70)   # CHK

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

        # TCP Panel with tabs for parsed/raw view
        tcpPanel = QtWidgets.QWidget()
        tcpLayout = QtWidgets.QVBoxLayout(tcpPanel)
        tcpLayout.setContentsMargins(0, 0, 0, 0)
        tcpLayout.addWidget(QtWidgets.QLabel("TCP Monitor"))

        # Create tab widget for TCP views
        self.tcpTabWidget = QtWidgets.QTabWidget()

        # Parsed view tab
        tcpParsedTab = QtWidgets.QWidget()
        tcpParsedLayout = QtWidgets.QVBoxLayout(tcpParsedTab)
        tcpParsedLayout.setContentsMargins(0, 0, 0, 0)
        tcpParsedLayout.addWidget(self.tcpTable)
        self.tcpTabWidget.addTab(tcpParsedTab, "Parsed")

        # RAW view tab
        tcpRawTab = QtWidgets.QWidget()
        tcpRawLayout = QtWidgets.QVBoxLayout(tcpRawTab)
        tcpRawLayout.setContentsMargins(0, 0, 0, 0)
        self.tcpRawTable = QtWidgets.QTableWidget(0, 3)
        self.tcpRawTable.setHorizontalHeaderLabels(["Time", "Direction", "Raw Data"])
        self.tcpRawTable.horizontalHeader().setStretchLastSection(True)
        self.tcpRawTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.tcpRawTable.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tcpRawTable.setWordWrap(True)
        self.tcpRawTable.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        self.tcpRawTable.setColumnWidth(0, 100)  # Time
        self.tcpRawTable.setColumnWidth(1, 60)   # Direction
        tcpRawLayout.addWidget(self.tcpRawTable)

        self.tcpTabWidget.addTab(tcpRawTab, "RAW")

        tcpLayout.addWidget(self.tcpTabWidget)
        # TCP search bar (works for both Parsed and RAW tabs)
        tcpSearchLayout = QtWidgets.QHBoxLayout()
        tcpSearchLayout.addWidget(QtWidgets.QLabel("Search:"))
        self.tcpSearchEdit = QtWidgets.QLineEdit()
        self.tcpSearchEdit.setPlaceholderText("Enter text to search...")
        self.tcpSearchButton = QtWidgets.QPushButton("Search")
        self.tcpSearchButton.setStyleSheet("font-weight: bold;")
        self.tcpSearchPrevButton = QtWidgets.QPushButton("◄ Prev")
        self.tcpSearchNextButton = QtWidgets.QPushButton("Next ►")
        self.tcpSearchClearButton = QtWidgets.QPushButton("Clear")
        tcpSearchLayout.addWidget(self.tcpSearchEdit)
        tcpSearchLayout.addWidget(self.tcpSearchButton)
        tcpSearchLayout.addWidget(self.tcpSearchPrevButton)
        tcpSearchLayout.addWidget(self.tcpSearchNextButton)
        tcpSearchLayout.addWidget(self.tcpSearchClearButton)
        tcpLayout.addLayout(tcpSearchLayout)
        # TCP buttons
        tcpButtonsLayout = QtWidgets.QHBoxLayout()
        self.tcpClearButton = QtWidgets.QPushButton("Clear Log")
        self.tcpCopyAllButton = QtWidgets.QPushButton("Copy All")
        self.tcpCopyRawButton = QtWidgets.QPushButton("Copy Row")
        tcpButtonsLayout.addWidget(self.tcpClearButton)
        tcpButtonsLayout.addWidget(self.tcpCopyAllButton)
        tcpButtonsLayout.addWidget(self.tcpCopyRawButton)
        tcpButtonsLayout.addStretch()
        tcpLayout.addLayout(tcpButtonsLayout)

        # UART Panel with tabs for parsed/raw view
        uartPanel = QtWidgets.QWidget()
        uartLayout = QtWidgets.QVBoxLayout(uartPanel)
        uartLayout.setContentsMargins(0, 0, 0, 0)
        uartLayout.addWidget(QtWidgets.QLabel("UART Monitor"))

        # Create tab widget for UART views
        self.uartTabWidget = QtWidgets.QTabWidget()

        # Parsed view tab
        parsedTab = QtWidgets.QWidget()
        parsedLayout = QtWidgets.QVBoxLayout(parsedTab)
        parsedLayout.setContentsMargins(0, 0, 0, 0)
        parsedLayout.addWidget(self.uartTable)
        self.uartTabWidget.addTab(parsedTab, "Parsed")

        # RAW hex view tab
        rawTab = QtWidgets.QWidget()
        rawLayout = QtWidgets.QVBoxLayout(rawTab)
        rawLayout.setContentsMargins(0, 0, 0, 0)
        self.uartRawTable = QtWidgets.QTableWidget(0, 2)
        self.uartRawTable.setHorizontalHeaderLabels(["Time", "Raw Data (Hex)"])
        self.uartRawTable.horizontalHeader().setStretchLastSection(True)
        self.uartRawTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.uartRawTable.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.uartRawTable.setWordWrap(True)
        self.uartRawTable.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        self.uartRawTable.setColumnWidth(0, 100)  # Time
        rawLayout.addWidget(self.uartRawTable)

        self.uartTabWidget.addTab(rawTab, "RAW Hex")

        uartLayout.addWidget(self.uartTabWidget)
        # UART search bar (works for both Parsed and RAW tabs)
        uartSearchLayout = QtWidgets.QHBoxLayout()
        uartSearchLayout.addWidget(QtWidgets.QLabel("Search:"))
        self.uartSearchEdit = QtWidgets.QLineEdit()
        self.uartSearchEdit.setPlaceholderText("Enter text to search...")
        self.uartSearchButton = QtWidgets.QPushButton("Search")
        self.uartSearchButton.setStyleSheet("font-weight: bold;")
        self.uartSearchPrevButton = QtWidgets.QPushButton("◄ Prev")
        self.uartSearchNextButton = QtWidgets.QPushButton("Next ►")
        self.uartSearchClearButton = QtWidgets.QPushButton("Clear")
        uartSearchLayout.addWidget(self.uartSearchEdit)
        uartSearchLayout.addWidget(self.uartSearchButton)
        uartSearchLayout.addWidget(self.uartSearchPrevButton)
        uartSearchLayout.addWidget(self.uartSearchNextButton)
        uartSearchLayout.addWidget(self.uartSearchClearButton)
        uartLayout.addLayout(uartSearchLayout)
        # UART buttons
        uartButtonsLayout = QtWidgets.QHBoxLayout()
        self.uartClearButton = QtWidgets.QPushButton("Clear Log")
        self.uartCopyAllButton = QtWidgets.QPushButton("Copy All")
        self.uartCopyRawButton = QtWidgets.QPushButton("Copy Row")
        uartButtonsLayout.addWidget(self.uartClearButton)
        uartButtonsLayout.addWidget(self.uartCopyAllButton)
        uartButtonsLayout.addWidget(self.uartCopyRawButton)
        uartButtonsLayout.addStretch()
        uartLayout.addLayout(uartButtonsLayout)

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
        settingsMenu.addSeparator()
        self.checksumCalcAction = settingsMenu.addAction("Calculate Checksum…")
        self.checksumCalcAction.triggered.connect(self._open_checksum_calculator)

        # Status bar
        self.statusBar().showMessage("Ready")

        # State
        self.tcpSniffer: TcpSniffer | None = None
        self.uart: UartReader | None = None
        self.lastTcpConnectTs: int | None = None
        self._tcpEvents: list[LogEvent] = []
        self._uartEvents: list[LogEvent] = []
        self._tcpRawEvents: list[LogEvent] = []  # For TCP RAW view
        self._tcpRawBuffer: bytearray = bytearray()  # Buffer for raw TCP bytes
        self._tcpRawDirection: str = ""  # Last direction (RX/TX)
        self._uartRawEvents: list[LogEvent] = []  # For RAW hex view
        self._uartRawBuffer: bytearray = bytearray()  # Buffer for raw bytes
        self._uartRawLastFlush: float = 0  # Last time we flushed raw buffer
        self._synchronizingSelection = False  # prevent recursion
        self._tcpSearchResults: list[int] = []  # List of matching row indices
        self._tcpSearchIndex: int = -1  # Current position in search results
        self._uartSearchResults: list[int] = []
        self._uartSearchIndex: int = -1
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
        # Log management buttons
        self.tcpClearButton.clicked.connect(self._onClearTcpLog)
        self.tcpCopyAllButton.clicked.connect(self._onCopyAllTcp)
        self.tcpCopyRawButton.clicked.connect(self._onCopyRawTcp)
        self.uartClearButton.clicked.connect(self._onClearUartLog)
        self.uartCopyAllButton.clicked.connect(self._onCopyAllUart)
        self.uartCopyRawButton.clicked.connect(self._onCopyRawUart)
        # Search functionality
        self.tcpSearchEdit.returnPressed.connect(self._onTcpSearch)
        self.tcpSearchButton.clicked.connect(self._onTcpSearch)
        self.tcpSearchNextButton.clicked.connect(self._onTcpSearchNext)
        self.tcpSearchPrevButton.clicked.connect(self._onTcpSearchPrev)
        self.tcpSearchClearButton.clicked.connect(self._onTcpSearchClear)
        self.uartSearchEdit.returnPressed.connect(self._onUartSearch)
        self.uartSearchButton.clicked.connect(self._onUartSearch)
        self.uartSearchNextButton.clicked.connect(self._onUartSearchNext)
        self.uartSearchPrevButton.clicked.connect(self._onUartSearchPrev)
        self.uartSearchClearButton.clicked.connect(self._onUartSearchClear)
        # Populate initially
        self.refresh_ifaces()
        self.refresh_serial_ports()

    def _open_uart_filter_dialog(self):
        dlg = UartFilterDialog(self, self._uartFilter)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            self._uartFilter = dlg.get_filter()
            self.statusBar().showMessage("UART filter updated", 3000)

    def _open_checksum_calculator(self):
        """Open dialog to calculate UART checksum for user input."""
        dlg = ChecksumCalculatorDialog(self)
        dlg.exec()

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

    def _append_uart_to_table(self, ev: LogEvent, frame: bytes):
        """Append UART frame with parsed formatting."""
        row = self.uartTable.rowCount()
        self.uartTable.insertRow(row)

        # Time column
        time_item = QtWidgets.QTableWidgetItem(self._fmt_ts(ev.ts_ms))
        self.uartTable.setItem(row, 0, time_item)

        # Try to parse the message
        parsed = parse_uart_message(frame)

        if parsed:
            # Type column
            type_text = "C" if parsed.message_type == "control" else "D"
            type_item = QtWidgets.QTableWidgetItem(type_text)
            # Color code: Control = light blue, Data = light green
            type_color = "#BBDEFB" if parsed.message_type == "control" else "#C8E6C9"
            type_item.setBackground(QtGui.QBrush(QtGui.QColor(type_color)))
            type_item.setToolTip("Control (0x10)" if parsed.message_type == "control" else "Data (0x43)")
            self.uartTable.setItem(row, 1, type_item)

            # Check for SAME start byte in data (warning sign)
            # For 0x43 messages with length field, this should NOT happen anymore
            start_byte = parsed.raw[0]
            has_start_in_data = start_byte in parsed.data if parsed.message_type == "control" else False

            # From column (sender ID)
            from_item = QtWidgets.QTableWidgetItem(f"0x{parsed.sender_id:02X}")
            from_color = get_color_for_id(parsed.sender_id)
            from_item.setBackground(QtGui.QBrush(QtGui.QColor(from_color)))
            self.uartTable.setItem(row, 2, from_item)

            # To column (receiver ID)
            to_item = QtWidgets.QTableWidgetItem(f"0x{parsed.receiver_id:02X}")
            to_color = get_color_for_id(parsed.receiver_id)
            to_item.setBackground(QtGui.QBrush(QtGui.QColor(to_color)))
            self.uartTable.setItem(row, 3, to_item)

            # CMD column (only for 0x43 messages)
            if parsed.command is not None:
                cmd_item = QtWidgets.QTableWidgetItem(f"0x{parsed.command:02X}")
                cmd_item.setBackground(QtGui.QBrush(QtGui.QColor("#E8F5E9")))  # Light green
                self.uartTable.setItem(row, 4, cmd_item)
            else:
                # Empty for control messages
                self.uartTable.setItem(row, 4, QtWidgets.QTableWidgetItem("-"))

            # LEN column (only for 0x43 messages)
            if parsed.data_length is not None:
                len_item = QtWidgets.QTableWidgetItem(str(parsed.data_length))
                len_item.setBackground(QtGui.QBrush(QtGui.QColor("#E8F5E9")))  # Light green
                # Add tooltip showing if length matches actual data
                actual_len = len(parsed.data)
                if actual_len == parsed.data_length:
                    len_item.setToolTip(f"Length matches: {actual_len} bytes")
                else:
                    len_item.setToolTip(f"⚠ Length mismatch! Expected: {parsed.data_length}, Actual: {actual_len}")
                    len_item.setBackground(QtGui.QBrush(QtGui.QColor("#FFE4B5")))  # Warning color
                self.uartTable.setItem(row, 5, len_item)
            else:
                # Empty for control messages
                self.uartTable.setItem(row, 5, QtWidgets.QTableWidgetItem("-"))

            # Data (Hex) column - add warning if contains START bytes (only for control messages)
            hex_text = parsed.data.hex().upper()
            if has_start_in_data:
                hex_text += " ⚠"
            hex_item = QtWidgets.QTableWidgetItem(hex_text)
            if has_start_in_data:
                hex_item.setBackground(QtGui.QBrush(QtGui.QColor("#FFE4B5")))  # Moccasin - warning
            self.uartTable.setItem(row, 6, hex_item)

            # Data (String) column
            string_text = parsed.data_as_string()
            if has_start_in_data:
                string_text += f" (contains 0x{start_byte:02X})"
            string_item = QtWidgets.QTableWidgetItem(string_text)
            self.uartTable.setItem(row, 7, string_item)

            # Checksum column with validation indicator
            chk_text = f"0x{parsed.checksum:02X}"

            if parsed.checksum_valid:
                chk_text += " ✓"
                chk_item = QtWidgets.QTableWidgetItem(chk_text)
                chk_item.setBackground(QtGui.QBrush(QtGui.QColor("#D4EDDA")))  # Light green
            else:
                chk_text += " ✗"
                chk_item = QtWidgets.QTableWidgetItem(chk_text)
                chk_item.setBackground(QtGui.QBrush(QtGui.QColor("#F8D7DA")))  # Light red
            self.uartTable.setItem(row, 8, chk_item)
        else:
            # Unparsed or invalid message – try to diagnose the problem in more detail
            start_ok = (len(frame) > 0 and frame[0] in (0x10, 0x43))
            end_ok = (len(frame) > 0 and frame[-1] == 0x16)

            # Základní informace
            problems: list[str] = []
            if not start_ok:
                problems.append("chybí/špatný START (0x10/0x43)")
            if not end_ok:
                problems.append("chybí/špatný END (0x16)")

            # Délka rámce vs očekávání podle start bytu
            if start_ok:
                if frame[0] == 0x10:
                    # 10 DST SRC CMD CHK 16 -> přesně 6 bytů
                    if len(frame) != 6:
                        problems.append(f"neočekávaná délka pro 0x10 (len={len(frame)}, oček. 6)")
                elif frame[0] == 0x43:
                    # Pokud máme aspoň do LEN bajtu, zkusíme spočítat očekávanou délku
                    if len(frame) < 5:
                        problems.append(f"příliš krátké pro 0x43 (len={len(frame)}, min 7)")
                    else:
                        data_len = frame[4]
                        expected_len = 7 + data_len
                        if len(frame) < 7:
                            problems.append(f"příliš krátké pro 0x43 (len={len(frame)}, min 7)")
                        elif len(frame) != expected_len:
                            problems.append(f"délka neodpovídá LEN (len={len(frame)}, LEN={data_len}, oček. {expected_len})")

            if not problems:
                problems.append("nevalidní formát rámce")

            problem = "⚠ " + "; ".join(problems)

            # Type column – označíme chybový rámec
            type_item = QtWidgets.QTableWidgetItem("!")
            type_item.setToolTip("Chyba parsování UART rámce")
            self.uartTable.setItem(row, 1, type_item)

            # Ostatní hlavičkové sloupce necháme prázdné, ať je jasné, že se je nepodařilo zjistit
            for col in range(2, 6):
                self.uartTable.setItem(row, col, QtWidgets.QTableWidgetItem("-"))

            # Data (Hex)
            hex_item = QtWidgets.QTableWidgetItem(frame.hex().upper())
            self.uartTable.setItem(row, 6, hex_item)

            # Data (String) – tady dáme text chyby
            problem_item = QtWidgets.QTableWidgetItem(problem)
            self.uartTable.setItem(row, 7, problem_item)

            # CHK – neznámé
            chk_item = QtWidgets.QTableWidgetItem("-")
            self.uartTable.setItem(row, 8, chk_item)

            # Barevné zvýraznění celého řádku jako varování
            warning_color = QtGui.QColor("#FFF4CC")  # světle žlutá
            for col in range(self.uartTable.columnCount()):
                item = self.uartTable.item(row, col)
                if item:
                    item.setBackground(QtGui.QBrush(warning_color))

        self.uartTable.scrollToBottom()

    def appendLog(self, ev: LogEvent, frame: bytes = None):
        if ev.source == "TCP":
            self._tcpEvents.append(ev)
            self._append_to_table(self.tcpTable, ev)
        else:
            # Store raw frame data in the event
            if frame is not None and ev.raw_data is None:
                ev.raw_data = frame
            self._uartEvents.append(ev)

            # Add to parsed table
            if frame is not None:
                self._append_uart_to_table(ev, frame)
            else:
                # Fallback for non-frame UART events (e.g., status messages)
                self._append_to_table(self.uartTable, ev)

    def onStart(self):
        host = self.tcpHostEdit.text().strip()
        port = int(self.tcpPortEdit.text().strip())
        ser_port = self.serialPortCombo.currentText().strip()
        baud = int(self.serialBaudEdit.text().strip())

        self.tcpTable.setRowCount(0)
        self.tcpRawTable.setRowCount(0)
        self.uartTable.setRowCount(0)
        self.uartRawTable.setRowCount(0)
        self._tcpEvents.clear()
        self._tcpRawEvents.clear()
        self._tcpRawBuffer.clear()
        self._tcpRawDirection = ""
        self._uartEvents.clear()
        self._uartRawEvents.clear()
        self._uartRawBuffer.clear()
        self._uartRawLastFlush = 0

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
        self.uart.frameDropped.connect(lambda frame, reason: self._onUartFrameDropped(frame, reason))
        self.uart.rawDataReceived.connect(lambda data: self._onUartRawData(data))
        self.uart.errorOccurred.connect(lambda msg: self._onError("UART", msg))

        self.tcpSniffer.start()
        self.uart.start()
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)

    def onStop(self):
        # Flush any remaining raw data
        if hasattr(self, '_tcpRawBuffer') and len(self._tcpRawBuffer) > 0:
            self._flushTcpRawBuffer()
        if hasattr(self, '_uartRawBuffer') and len(self._uartRawBuffer) > 0:
            self._flushRawBuffer()

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
        # Store direction for potential incomplete message flush
        self._tcpRawDirection = direction

        # Handle RAW TCP data buffering (messages terminated by \r\n)
        self._tcpRawBuffer.extend(data)

        # Process all complete messages (ending with \r\n)
        while b'\r\n' in self._tcpRawBuffer:
            idx = self._tcpRawBuffer.index(b'\r\n')
            message = bytes(self._tcpRawBuffer[:idx])  # Extract message without \r\n
            self._tcpRawBuffer = self._tcpRawBuffer[idx + 2:]  # Remove processed message + \r\n

            if message:  # Only process non-empty messages
                ts_ms = int(time.time() * 1000)

                # Add to RAW table
                raw_ev = LogEvent(ts_ms, "TCP", f"{len(message)} bytes")
                raw_ev.raw_data = message
                self._tcpRawEvents.append(raw_ev)

                row = self.tcpRawTable.rowCount()
                self.tcpRawTable.insertRow(row)

                # Time column
                time_item = QtWidgets.QTableWidgetItem(self._fmt_ts(ts_ms))
                self.tcpRawTable.setItem(row, 0, time_item)

                # Direction column
                dir_item = QtWidgets.QTableWidgetItem(direction)
                # Color code: RX = green, TX = orange
                dir_color = QtGui.QColor("#e7f7e7") if direction.upper() == "RX" else QtGui.QColor("#ffe9e6")
                dir_item.setBackground(QtGui.QBrush(dir_color))
                self.tcpRawTable.setItem(row, 1, dir_item)

                # Raw data column - decode as ASCII if possible
                try:
                    raw_text = message.decode('ascii', errors='ignore')
                except Exception:
                    raw_text = message.hex()

                raw_item = QtWidgets.QTableWidgetItem(raw_text)
                self.tcpRawTable.setItem(row, 2, raw_item)
                self.tcpRawTable.scrollToBottom()

        # Process parsed data
        rec = parse_tcp_message(data)
        ts_ms = int(time.time() * 1000)
        if rec is not None:
            seg_count = len(rec.segments)
            header = f"M={rec.m or ''} S={rec.s or ''} P={rec.p or ''}"
            segments_full = ", ".join(f"{sid}:{sval}" for sid, sval in rec.segments.items())
            msg = f"{direction} | TCP parsed: {header} | D={(' | ' + segments_full) if segments_full else ''}"
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
        self.appendLog(LogEvent(ts, "UART", msg), frame=frame)

    def _onUartFrameDropped(self, frame: bytes, reason: str):
        """Handle dropped/invalid UART frames."""
        ts = int(time.time()*1000)
        reason_map = {
            "too_short": "příliš krátká",
            "too_long": "příliš dlouhá",
            "buffer_overflow": "přetečení bufferu",
            "incomplete_frame_interrupted": "nekompletní frame přerušen",
            "same_start_byte_in_frame": "stejný START byte uvnitř zprávy"
        }
        reason_text = reason_map.get(reason, reason)
        msg = f"⚠ DROPPED frame ({reason_text}): {len(frame)} bytes: {frame.hex()}"

        # Create event and add to log
        ev = LogEvent(ts, "UART", msg)
        ev.raw_data = frame

        # Add unparsed entry to parsed table with all columns marked as invalid
        row = self.uartTable.rowCount()
        self.uartTable.insertRow(row)

        # Time column
        time_item = QtWidgets.QTableWidgetItem(self._fmt_ts(ts))
        self.uartTable.setItem(row, 0, time_item)

        # Mark all data columns as invalid (9 columns now: Time, Type, From, To, CMD, LEN, Data(Hex), Data(String), CHK)
        self.uartTable.setItem(row, 1, QtWidgets.QTableWidgetItem("✗"))
        self.uartTable.setItem(row, 2, QtWidgets.QTableWidgetItem("✗"))
        self.uartTable.setItem(row, 3, QtWidgets.QTableWidgetItem("✗"))
        self.uartTable.setItem(row, 4, QtWidgets.QTableWidgetItem("✗"))
        self.uartTable.setItem(row, 5, QtWidgets.QTableWidgetItem("✗"))
        self.uartTable.setItem(row, 6, QtWidgets.QTableWidgetItem(frame.hex()))
        self.uartTable.setItem(row, 7, QtWidgets.QTableWidgetItem(f"⚠ {reason_text}"))
        self.uartTable.setItem(row, 8, QtWidgets.QTableWidgetItem("✗"))

        # Color the entire row red to indicate error
        error_color = QtGui.QColor("#FFD6D6")  # Light red
        for col in range(self.uartTable.columnCount()):
            item = self.uartTable.item(row, col)
            if item:
                item.setBackground(QtGui.QBrush(error_color))

        self.uartTable.scrollToBottom()
        self._uartEvents.append(ev)

    def _onUartRawData(self, data: bytes):
        """Handle raw UART data without any frame parsing."""
        import time as time_module

        # Add to buffer
        self._uartRawBuffer.extend(data)

        current_time = time_module.time()

        # Flush buffer if:
        # 1. We have 32+ bytes (one line), OR
        # 2. 100ms passed since last flush
        should_flush = (
            len(self._uartRawBuffer) >= 32 or
            (self._uartRawLastFlush > 0 and (current_time - self._uartRawLastFlush) > 0.1)
        )

        if should_flush and len(self._uartRawBuffer) > 0:
            self._flushRawBuffer()

    def _flushRawBuffer(self):
        """Flush accumulated raw data to the RAW table."""
        import time as time_module

        if len(self._uartRawBuffer) == 0:
            return

        ts = int(time.time() * 1000)
        raw_data = bytes(self._uartRawBuffer)

        # Apply filter if enabled
        if self._uartFilter.enabled:
            # For raw data, we need to check if any part matches
            # This is tricky - let's just show everything in RAW mode when filter is enabled
            # User can use search to find specific patterns
            pass

        # Create event
        raw_ev = LogEvent(ts, "UART", f"{len(raw_data)} bytes")
        raw_ev.raw_data = raw_data
        self._uartRawEvents.append(raw_ev)

        # Add to table
        row = self.uartRawTable.rowCount()
        self.uartRawTable.insertRow(row)

        # Time column
        time_item = QtWidgets.QTableWidgetItem(self._fmt_ts(ts))
        self.uartRawTable.setItem(row, 0, time_item)

        # Raw hex data with proper formatting
        hex_str = raw_data.hex().upper()
        # Add spaces every 2 characters for readability
        formatted_hex = ' '.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
        raw_item = QtWidgets.QTableWidgetItem(formatted_hex)

        # Highlight START (0x10) and END (0x16) bytes with color
        # Check if data contains these markers
        has_start = 0x10 in raw_data
        has_end = 0x16 in raw_data

        if has_start and has_end:
            # Contains both markers - light cyan
            raw_item.setBackground(QtGui.QBrush(QtGui.QColor("#E0F7FA")))
        elif has_start or has_end:
            # Contains one marker - light yellow
            raw_item.setBackground(QtGui.QBrush(QtGui.QColor("#FFF9C4")))
        # else: no special color (white background)

        self.uartRawTable.setItem(row, 1, raw_item)
        self.uartRawTable.scrollToBottom()

        # Clear buffer and update timestamp
        self._uartRawBuffer.clear()
        self._uartRawLastFlush = time_module.time()

    def _flushTcpRawBuffer(self):
        """Flush any remaining TCP raw data (incomplete message without \r\n)."""
        if len(self._tcpRawBuffer) == 0:
            return

        ts = int(time.time() * 1000)
        raw_data = bytes(self._tcpRawBuffer)

        # Create event
        raw_ev = LogEvent(ts, "TCP", f"{len(raw_data)} bytes (incomplete)")
        raw_ev.raw_data = raw_data
        self._tcpRawEvents.append(raw_ev)

        row = self.tcpRawTable.rowCount()
        self.tcpRawTable.insertRow(row)

        # Time column
        time_item = QtWidgets.QTableWidgetItem(self._fmt_ts(ts))
        self.tcpRawTable.setItem(row, 0, time_item)

        # Direction column (use last known direction)
        dir_item = QtWidgets.QTableWidgetItem(self._tcpRawDirection or "?")
        # Incomplete message - light yellow warning
        dir_item.setBackground(QtGui.QBrush(QtGui.QColor("#FFF9C4")))
        self.tcpRawTable.setItem(row, 1, dir_item)

        # Raw data column
        try:
            raw_text = raw_data.decode('ascii', errors='ignore') + " (incomplete)"
        except Exception:
            raw_text = raw_data.hex() + " (incomplete)"

        raw_item = QtWidgets.QTableWidgetItem(raw_text)
        raw_item.setBackground(QtGui.QBrush(QtGui.QColor("#FFF9C4")))  # Warning yellow
        self.tcpRawTable.setItem(row, 2, raw_item)
        self.tcpRawTable.scrollToBottom()

        # Clear buffer
        self._tcpRawBuffer.clear()

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

    # TCP Log Management
    def _onClearTcpLog(self):
        """Clear both TCP Parsed and RAW logs."""
        # Clear Parsed tab
        self.tcpTable.setRowCount(0)
        self._tcpEvents.clear()

        # Clear RAW tab
        self.tcpRawTable.setRowCount(0)
        self._tcpRawEvents.clear()
        self._tcpRawBuffer.clear()
        self._tcpRawDirection = ""

        self.statusBar().showMessage("TCP log cleared (Parsed + RAW)", 2000)

    def _onCopyAllTcp(self):
        """Copy all TCP log entries to clipboard based on active tab."""
        current_tab = self.tcpTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            lines = []
            for ev in self._tcpEvents:
                lines.append(f"{self._fmt_ts(ev.ts_ms)} | {ev.message}")
            text = "\n".join(lines)
            QtWidgets.QApplication.clipboard().setText(text)
            self.statusBar().showMessage(f"Copied {len(self._tcpEvents)} TCP parsed entries to clipboard", 2000)
        else:  # RAW tab
            lines = []
            for row in range(self.tcpRawTable.rowCount()):
                time_item = self.tcpRawTable.item(row, 0)
                dir_item = self.tcpRawTable.item(row, 1)
                data_item = self.tcpRawTable.item(row, 2)
                if time_item and dir_item and data_item:
                    lines.append(f"{time_item.text()} | {dir_item.text()} | {data_item.text()}")
            text = "\n".join(lines)
            QtWidgets.QApplication.clipboard().setText(text)
            self.statusBar().showMessage(f"Copied {len(lines)} TCP RAW entries to clipboard", 2000)

    def _onCopyRawTcp(self):
        """Copy selected TCP row based on active tab."""
        current_tab = self.tcpTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            selected = self.tcpTable.selectionModel().selectedRows()
            if not selected:
                self.statusBar().showMessage("No TCP entry selected", 2000)
                return
            row = selected[0].row()
            if row < 0 or row >= len(self._tcpEvents):
                return
            ev = self._tcpEvents[row]
            # Copy the raw message
            QtWidgets.QApplication.clipboard().setText(ev.message)
            self.statusBar().showMessage(f"Copied TCP parsed entry to clipboard", 2000)
        else:  # RAW tab
            selected = self.tcpRawTable.selectionModel().selectedRows()
            if not selected:
                self.statusBar().showMessage("No TCP RAW entry selected", 2000)
                return
            row = selected[0].row()
            if row < 0 or row >= self.tcpRawTable.rowCount():
                return

            # Copy the raw data from the selected row
            data_item = self.tcpRawTable.item(row, 2)
            if data_item:
                QtWidgets.QApplication.clipboard().setText(data_item.text())
                self.statusBar().showMessage(f"Copied TCP RAW entry to clipboard", 2000)

    # UART Log Management
    def _onClearUartLog(self):
        """Clear both UART Parsed and RAW logs."""
        # Clear Parsed tab
        self.uartTable.setRowCount(0)
        self._uartEvents.clear()

        # Clear RAW tab
        self.uartRawTable.setRowCount(0)
        self._uartRawEvents.clear()
        self._uartRawBuffer.clear()
        self._uartRawLastFlush = 0

        self.statusBar().showMessage("UART log cleared (Parsed + RAW)", 2000)

    def _onCopyAllUart(self):
        """Copy all UART log entries to clipboard based on active tab."""
        current_tab = self.uartTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            lines = []
            for ev in self._uartEvents:
                # Try to parse the frame to get checksum status
                chk_status = ""
                if ev.raw_data:
                    parsed = parse_uart_message(ev.raw_data)
                    if parsed is not None:
                        chk_status = "✓" if parsed.checksum_valid else "✗"
                        lines.append(f"{self._fmt_ts(ev.ts_ms)} | {ev.message} | CHK: {chk_status}")
                    else:
                        # Nezparsovatelný rámec – přidáme stručnou diagnostiku i do exportu
                        start_ok = (len(ev.raw_data) > 0 and ev.raw_data[0] in (0x10, 0x43))
                        end_ok = (len(ev.raw_data) > 0 and ev.raw_data[-1] == 0x16)
                        problems = []
                        if not start_ok:
                            problems.append("bad START")
                        if not end_ok:
                            problems.append("bad END")
                        if not problems:
                            problems.append("invalid format")
                        lines.append(f"{self._fmt_ts(ev.ts_ms)} | {ev.message} | PARSE_ERR: {', '.join(problems)} | RAW: {ev.raw_data.hex()}")
                else:
                    lines.append(f"{self._fmt_ts(ev.ts_ms)} | {ev.message}")
            text = "\n".join(lines)
            QtWidgets.QApplication.clipboard().setText(text)
            self.statusBar().showMessage(f"Copied {len(self._uartEvents)} UART parsed entries to clipboard", 2000)
        else:  # RAW tab
            lines = []
            for row in range(self.uartRawTable.rowCount()):
                time_item = self.uartRawTable.item(row, 0)
                data_item = self.uartRawTable.item(row, 1)
                if time_item and data_item:
                    lines.append(f"{time_item.text()} | {data_item.text()}")
            text = "\n".join(lines)
            QtWidgets.QApplication.clipboard().setText(text)
            self.statusBar().showMessage(f"Copied {len(lines)} UART RAW entries to clipboard", 2000)

    def _onCopyRawUart(self):
        """Copy selected UART row based on active tab."""
        current_tab = self.uartTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            selected = self.uartTable.selectionModel().selectedRows()
            if not selected:
                self.statusBar().showMessage("No UART entry selected", 2000)
                return
            row = selected[0].row()
            if row < 0 or row >= len(self._uartEvents):
                return
            ev = self._uartEvents[row]

            # Try to get raw data first, then fallback to parsing message
            if ev.raw_data is not None:
                hex_data = ev.raw_data.hex()
                QtWidgets.QApplication.clipboard().setText(hex_data)
                self.statusBar().showMessage(f"Copied raw UART data ({len(ev.raw_data)} bytes) to clipboard", 2000)
            else:
                # Extract hex from message (format: "frame N bytes: HEXDATA")
                msg = ev.message
                if " bytes: " in msg:
                    hex_data = msg.split(" bytes: ")[1].split()[0]  # Get hex part before any additional text
                    QtWidgets.QApplication.clipboard().setText(hex_data)
                    self.statusBar().showMessage(f"Copied raw UART data to clipboard", 2000)
                else:
                    QtWidgets.QApplication.clipboard().setText(msg)
                    self.statusBar().showMessage(f"Copied UART entry to clipboard", 2000)
        else:  # RAW tab
            selected = self.uartRawTable.selectionModel().selectedRows()
            if not selected:
                self.statusBar().showMessage("No UART RAW entry selected", 2000)
                return
            row = selected[0].row()
            if row < 0 or row >= self.uartRawTable.rowCount():
                return

            # Copy the raw hex data from the selected row
            data_item = self.uartRawTable.item(row, 1)
            if data_item:
                # Remove spaces for clean hex string
                hex_data = data_item.text().replace(" ", "")
                QtWidgets.QApplication.clipboard().setText(hex_data)
                self.statusBar().showMessage(f"Copied UART RAW entry to clipboard", 2000)

    # TCP Search functionality
    def _onTcpSearch(self):
        """Perform search in active TCP tab (triggered by Search button or Enter key)."""
        current_tab = self.tcpTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            self._performTcpParsedSearch()
        else:  # RAW tab
            self._performTcpRawSearch()

    def _performTcpParsedSearch(self):
        """Perform search and highlight all matches in TCP Parsed table."""
        search_text = self.tcpSearchEdit.text().lower()
        self._tcpSearchResults.clear()
        self._tcpSearchIndex = -1

        if not search_text:
            # Clear all highlighting
            for row in range(self.tcpTable.rowCount()):
                for col in range(self.tcpTable.columnCount()):
                    item = self.tcpTable.item(row, col)
                    if item:
                        # Get original background color based on direction
                        text = item.text()
                        if "RX" in text:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#e7f7e7")))
                        elif "TX" in text:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffe9e6")))
                        else:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
            return

        # Search through all rows
        for row in range(self.tcpTable.rowCount()):
            match_found = False
            for col in range(self.tcpTable.columnCount()):
                item = self.tcpTable.item(row, col)
                if item and search_text in item.text().lower():
                    match_found = True
                    break

            if match_found:
                self._tcpSearchResults.append(row)
                # Highlight the row with yellow background
                for col in range(self.tcpTable.columnCount()):
                    item = self.tcpTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#FFFF99")))  # Bright yellow
            else:
                # Restore original color
                for col in range(self.tcpTable.columnCount()):
                    item = self.tcpTable.item(row, col)
                    if item:
                        text = item.text()
                        if "RX" in text:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#e7f7e7")))
                        elif "TX" in text:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffe9e6")))
                        else:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))

        # Update status
        if self._tcpSearchResults:
            self.statusBar().showMessage(f"Found {len(self._tcpSearchResults)} matches in TCP Parsed log", 3000)
        else:
            self.statusBar().showMessage("No matches found in TCP Parsed log", 3000)

    def _performTcpRawSearch(self):
        """Perform search and highlight all matches in TCP RAW table."""
        search_text = self.tcpSearchEdit.text().lower()
        self._tcpSearchResults.clear()
        self._tcpSearchIndex = -1

        if not search_text:
            # Clear all highlighting
            for row in range(self.tcpRawTable.rowCount()):
                for col in range(self.tcpRawTable.columnCount()):
                    item = self.tcpRawTable.item(row, col)
                    if item:
                        # Restore original color based on direction
                        if col == 1:  # Direction column
                            dir_text = item.text().upper()
                            if dir_text == "RX":
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#e7f7e7")))
                            elif dir_text == "TX":
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#ffe9e6")))
                            else:
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
                        else:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
            return

        # Search through all rows
        for row in range(self.tcpRawTable.rowCount()):
            match_found = False
            for col in range(self.tcpRawTable.columnCount()):
                item = self.tcpRawTable.item(row, col)
                if item and search_text in item.text().lower():
                    match_found = True
                    break

            if match_found:
                self._tcpSearchResults.append(row)
                # Highlight the row with yellow background
                for col in range(self.tcpRawTable.columnCount()):
                    item = self.tcpRawTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#FFFF99")))  # Bright yellow
            else:
                # Restore original color
                for col in range(self.tcpRawTable.columnCount()):
                    item = self.tcpRawTable.item(row, col)
                    if item:
                        if col == 1:  # Direction column
                            dir_text = item.text().upper()
                            if dir_text == "RX":
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#e7f7e7")))
                            elif dir_text == "TX":
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#ffe9e6")))
                            else:
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
                        else:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))

        # Update status
        if self._tcpSearchResults:
            self.statusBar().showMessage(f"Found {len(self._tcpSearchResults)} matches in TCP RAW log", 3000)
        else:
            self.statusBar().showMessage("No matches found in TCP RAW log", 3000)

    def _onTcpSearchNext(self):
        """Navigate to next search result in active TCP tab."""
        if not self._tcpSearchResults:
            self._onTcpSearch()
            if not self._tcpSearchResults:
                return

        current_tab = self.tcpTabWidget.currentIndex()
        table = self.tcpTable if current_tab == 0 else self.tcpRawTable

        self._tcpSearchIndex = (self._tcpSearchIndex + 1) % len(self._tcpSearchResults)
        row = self._tcpSearchResults[self._tcpSearchIndex]
        table.selectRow(row)
        table.scrollToItem(table.item(row, 0))
        self.statusBar().showMessage(f"Match {self._tcpSearchIndex + 1} of {len(self._tcpSearchResults)}", 2000)

    def _onTcpSearchPrev(self):
        """Navigate to previous search result in active TCP tab."""
        if not self._tcpSearchResults:
            self._onTcpSearch()
            if not self._tcpSearchResults:
                return

        current_tab = self.tcpTabWidget.currentIndex()
        table = self.tcpTable if current_tab == 0 else self.tcpRawTable

        self._tcpSearchIndex = (self._tcpSearchIndex - 1) % len(self._tcpSearchResults)
        row = self._tcpSearchResults[self._tcpSearchIndex]
        table.selectRow(row)
        table.scrollToItem(table.item(row, 0))
        self.statusBar().showMessage(f"Match {self._tcpSearchIndex + 1} of {len(self._tcpSearchResults)}", 2000)

    def _onTcpSearchClear(self):
        """Clear search in active TCP tab."""
        self.tcpSearchEdit.clear()
        self._tcpSearchResults.clear()
        self._tcpSearchIndex = -1

        current_tab = self.tcpTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            # Clear all highlighting
            for row in range(self.tcpTable.rowCount()):
                for col in range(self.tcpTable.columnCount()):
                    item = self.tcpTable.item(row, col)
                    if item:
                        text = item.text()
                        if "RX" in text:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#e7f7e7")))
                        elif "TX" in text:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffe9e6")))
                        else:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
        else:  # RAW tab
            for row in range(self.tcpRawTable.rowCount()):
                for col in range(self.tcpRawTable.columnCount()):
                    item = self.tcpRawTable.item(row, col)
                    if item:
                        if col == 1:  # Direction column
                            dir_text = item.text().upper()
                            if dir_text == "RX":
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#e7f7e7")))
                            elif dir_text == "TX":
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#ffe9e6")))
                            else:
                                item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
                        else:
                            item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))

    # UART Search functionality
    def _onUartSearch(self):
        """Perform search in active UART tab (triggered by Search button or Enter key)."""
        current_tab = self.uartTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            self._performUartParsedSearch()
        else:  # RAW tab
            self._performUartRawSearch()

    def _performUartParsedSearch(self):
        """Perform search and highlight all matches in UART Parsed table."""
        search_text = self.uartSearchEdit.text().lower()
        self._uartSearchResults.clear()
        self._uartSearchIndex = -1

        if not search_text:
            # Clear all highlighting - restore original colors
            for row in range(self.uartTable.rowCount()):
                for col in range(self.uartTable.columnCount()):
                    item = self.uartTable.item(row, col)
                    if item:
                        # Try to restore original background (this is simplified)
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
            return

        # Search through all rows
        for row in range(self.uartTable.rowCount()):
            match_found = False
            for col in range(self.uartTable.columnCount()):
                item = self.uartTable.item(row, col)
                if item and search_text in item.text().lower():
                    match_found = True
                    break

            if match_found:
                self._uartSearchResults.append(row)
                # Highlight the row with yellow background
                for col in range(self.uartTable.columnCount()):
                    item = self.uartTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#FFFF99")))  # Bright yellow
            else:
                # Restore to white (simplified - original colors may vary)
                for col in range(self.uartTable.columnCount()):
                    item = self.uartTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))

        # Update status
        if self._uartSearchResults:
            self.statusBar().showMessage(f"Found {len(self._uartSearchResults)} matches in UART Parsed log", 3000)
        else:
            self.statusBar().showMessage("No matches found in UART Parsed log", 3000)

    def _performUartRawSearch(self):
        """Perform search and highlight all matches in UART RAW table."""
        search_text = self.uartSearchEdit.text().replace(" ", "").lower()
        self._uartSearchResults.clear()
        self._uartSearchIndex = -1

        if not search_text:
            # Clear all highlighting
            for row in range(self.uartRawTable.rowCount()):
                for col in range(self.uartRawTable.columnCount()):
                    item = self.uartRawTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
            return

        # Search through all rows
        for row in range(self.uartRawTable.rowCount()):
            match_found = False
            for col in range(self.uartRawTable.columnCount()):
                item = self.uartRawTable.item(row, col)
                if item:
                    # Remove spaces from item text for hex comparison
                    item_text = item.text().replace(" ", "").lower()
                    if search_text in item_text:
                        match_found = True
                        break

            if match_found:
                self._uartSearchResults.append(row)
                # Highlight the row with yellow background
                for col in range(self.uartRawTable.columnCount()):
                    item = self.uartRawTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#FFFF99")))  # Bright yellow
            else:
                # Restore to white
                for col in range(self.uartRawTable.columnCount()):
                    item = self.uartRawTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))

        # Update status
        if self._uartSearchResults:
            self.statusBar().showMessage(f"Found {len(self._uartSearchResults)} matches in UART RAW log", 3000)
        else:
            self.statusBar().showMessage("No matches found in UART RAW log", 3000)

    def _onUartSearchNext(self):
        """Navigate to next search result in active UART tab."""
        if not self._uartSearchResults:
            self._onUartSearch()
            if not self._uartSearchResults:
                return

        current_tab = self.uartTabWidget.currentIndex()
        table = self.uartTable if current_tab == 0 else self.uartRawTable

        self._uartSearchIndex = (self._uartSearchIndex + 1) % len(self._uartSearchResults)
        row = self._uartSearchResults[self._uartSearchIndex]
        table.selectRow(row)
        table.scrollToItem(table.item(row, 0))
        self.statusBar().showMessage(f"Match {self._uartSearchIndex + 1} of {len(self._uartSearchResults)}", 2000)

    def _onUartSearchPrev(self):
        """Navigate to previous search result in active UART tab."""
        if not self._uartSearchResults:
            self._onUartSearch()
            if not self._uartSearchResults:
                return

        current_tab = self.uartTabWidget.currentIndex()
        table = self.uartTable if current_tab == 0 else self.uartRawTable

        self._uartSearchIndex = (self._uartSearchIndex - 1) % len(self._uartSearchResults)
        row = self._uartSearchResults[self._uartSearchIndex]
        table.selectRow(row)
        table.scrollToItem(table.item(row, 0))
        self.statusBar().showMessage(f"Match {self._uartSearchIndex + 1} of {len(self._uartSearchResults)}", 2000)

    def _onUartSearchClear(self):
        """Clear search in active UART tab."""
        self.uartSearchEdit.clear()
        self._uartSearchResults.clear()
        self._uartSearchIndex = -1

        current_tab = self.uartTabWidget.currentIndex()

        if current_tab == 0:  # Parsed tab
            # Clear all highlighting
            for row in range(self.uartTable.rowCount()):
                for col in range(self.uartTable.columnCount()):
                    item = self.uartTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))
        else:  # RAW tab
            for row in range(self.uartRawTable.rowCount()):
                for col in range(self.uartRawTable.columnCount()):
                    item = self.uartRawTable.item(row, col)
                    if item:
                        item.setBackground(QtGui.QBrush(QtGui.QColor("#ffffff")))

