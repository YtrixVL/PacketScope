from app.core.traffic_statistics import TrafficStatistics
from app.models.packet_info import PacketInfo


def test_calculate_traffic_statistics():
    statistics = TrafficStatistics()

    packets = [
        PacketInfo(1, "12:00:01", "192.168.0.10", "8.8.8.8", "DNS", 100, "DNS query: google.com"),
        PacketInfo(2, "12:00:02", "192.168.0.10", "1.1.1.1", "HTTPS", 200, "HTTPS TCP 50000 → 443"),
        PacketInfo(3, "12:00:03", "192.168.0.20", "8.8.8.8", "DNS", 300, "DNS query: github.com"),
    ]

    result = statistics.calculate(packets)

    assert result["total_packets"] == 3
    assert result["total_size"] == 600
    assert result["average_size"] == 200
    assert result["protocols"]["DNS"] == 2
    assert result["protocols"]["HTTPS"] == 1
    assert len(result["top_ips"]) > 0
    assert len(result["dns_domains"]) == 2