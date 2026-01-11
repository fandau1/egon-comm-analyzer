from PySide6 import QtCore
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
import threading

class TcpSniffer(QtCore.QObject):
    connected = QtCore.Signal()  # emitted when capture starts
    disconnected = QtCore.Signal(str)
    errorOccurred = QtCore.Signal(str)
    dataReceived = QtCore.Signal(bytes)
    dataReceivedDir = QtCore.Signal(bytes, str)  # payload, direction: "RX" or "TX"

    def __init__(self, port: int, iface: str | None = None, target_ip: str | None = None):
        super().__init__()
        self.port = port
        self.iface = iface
        self.target_ip = target_ip
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self):
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
                    if not payload:
                        return
                    # Derive direction
                    direction = "RX"
                    try:
                        if self.target_ip:
                            direction = "RX" if ip_layer.src == self.target_ip else ("TX" if ip_layer.dst == self.target_ip else "RX")
                        else:
                            # Heuristic: dport == monitored port => RX (incoming to monitored service), else TX
                            direction = "RX" if tcp_layer.dport == self.port else "TX"
                    except Exception:
                        direction = "RX"
                    # Emit both generic and directional signals for backward compatibility
                    self.dataReceived.emit(payload)
                    self.dataReceivedDir.emit(payload, direction)
                except Exception:
                    pass
            sniff(filter=bpf_filter, prn=_prn, store=False, iface=self.iface, stop_filter=lambda x: self._stop.is_set())
        except Exception as e:
            self.errorOccurred.emit(f"Sniffer error: {e}")
        finally:
            self.disconnected.emit("stopped")

