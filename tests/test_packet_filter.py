from app.core.packet_filter import PacketFilter
from app.models.packet_info import PacketInfo


def test_filter_packet_infos_by_protocol():
    packet_filter = PacketFilter()

    packets = [
        PacketInfo(1, "12:00:01", "192.168.0.10", "8.8.8.8", "DNS", 74, "DNS query: example.com"),
        PacketInfo(2, "12:00:02", "192.168.0.10", "1.1.1.1", "HTTPS", 120, "HTTPS TCP 50000 → 443"),
        PacketInfo(3, "12:00:03", "192.168.0.10", "192.168.0.1", "ARP", 60, "ARP packet"),
    ]

    result = packet_filter.filter_packet_infos(packets, "HTTPS")

    assert len(result) == 1
    assert result[0].protocol == "HTTPS"


def test_filter_packet_infos_by_ip():
    packet_filter = PacketFilter()

    packets = [
        PacketInfo(1, "12:00:01", "192.168.0.10", "8.8.8.8", "DNS", 74, "DNS query: google.com"),
        PacketInfo(2, "12:00:02", "192.168.0.15", "1.1.1.1", "HTTPS", 120, "HTTPS TCP 50000 → 443"),
    ]

    result = packet_filter.filter_packet_infos(packets, "8.8.8.8")

    assert len(result) == 1
    assert result[0].destination == "8.8.8.8"