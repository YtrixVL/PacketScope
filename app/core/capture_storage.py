from scapy.utils import wrpcap, rdpcap, PcapNgWriter


class CaptureStorage:
    """
    Класс отвечает за сохранение и загрузку файлов захвата.
    Поддерживаются форматы PCAP и PCAPNG.
    """

    def save_to_pcap(self, packets, file_path: str):
        if not packets:
            raise ValueError("Нет пакетов для сохранения")

        wrpcap(file_path, packets)

    def save_to_pcapng(self, packets, file_path: str):
        if not packets:
            raise ValueError("Нет пакетов для сохранения")

        writer = PcapNgWriter(file_path)

        try:
            for packet in packets:
                writer.write(packet)
        finally:
            writer.close()

    def load_capture(self, file_path: str):
        return list(rdpcap(file_path))