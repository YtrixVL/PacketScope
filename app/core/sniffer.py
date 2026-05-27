import threading
from typing import Callable, Optional

from scapy.all import sniff


class PacketSniffer:
    """
    Класс отвечает за захват сетевых пакетов.
    Захват выполняется в отдельном потоке, чтобы интерфейс приложения не зависал.
    """

    def __init__(self):
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self.packets = []
        self.packet_callback: Optional[Callable] = None
        self.error_callback: Optional[Callable] = None

    def start_capture(
        self,
        interface: str | None = None,
        packet_callback: Callable | None = None,
        error_callback: Callable | None = None,
        bpf_filter: str | None = None
    ):
        if self.is_running:
            return

        self.is_running = True
        self.packet_callback = packet_callback
        self.error_callback = error_callback

        self.thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, bpf_filter),
            daemon=True
        )
        self.thread.start()

    def stop_capture(self):
        self.is_running = False

    def _capture_packets(self, interface: str | None, bpf_filter: str | None):
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=False,
                filter=bpf_filter if bpf_filter else None,
                stop_filter=lambda packet: not self.is_running
            )
        except Exception as error:
            self.is_running = False

            if self.error_callback:
                self.error_callback(str(error))
            else:
                print(f"Ошибка захвата пакетов: {error}")

    def _process_packet(self, packet):
        self.packets.append(packet)

        if self.packet_callback:
            self.packet_callback(packet)

    def get_packets(self):
        return self.packets

    def clear_packets(self):
        self.packets.clear()