from scapy.all import IP, TCP, Ether

from app.core.capture_storage import CaptureStorage


def test_save_and_load_pcap(tmp_path):
    storage = CaptureStorage()

    packets = [
        Ether() / IP(src="192.168.0.10", dst="8.8.8.8") / TCP(sport=50000, dport=443),
        Ether() / IP(src="192.168.0.11", dst="1.1.1.1") / TCP(sport=50001, dport=80),
    ]

    file_path = tmp_path / "test_capture.pcap"

    storage.save_to_pcap(packets, str(file_path))

    loaded_packets = storage.load_capture(str(file_path))

    assert file_path.exists()
    assert len(loaded_packets) == 2