from app.core.security_analyzer import SecurityAnalyzer
from app.models.packet_info import PacketInfo


def test_security_analyzer_detects_suspicious_port():
    analyzer = SecurityAnalyzer()

    packets = [
        PacketInfo(1, "12:00:01", "192.168.0.10", "10.0.0.1", "TCP", 60, "TCP 50000 → 4444 Flags=S"),
        PacketInfo(2, "12:00:02", "192.168.0.10", "10.0.0.1", "TCP", 60, "TCP 50001 → 4444 Flags=S"),
        PacketInfo(3, "12:00:03", "192.168.0.10", "10.0.0.1", "TCP", 60, "TCP 50002 → 4444 Flags=S"),
    ]

    warnings = analyzer.analyze(packets)

    assert any("4444" in warning for warning in warnings)