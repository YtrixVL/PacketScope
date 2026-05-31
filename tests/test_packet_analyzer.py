from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether

from app.core.packet_analyzer import PacketAnalyzer


def test_detect_https_protocol():
    analyzer = PacketAnalyzer()

    packet = Ether() / IP(src="192.168.0.10", dst="8.8.8.8") / TCP(sport=50000, dport=443)

    protocol = analyzer.get_protocol(packet)

    assert protocol == "HTTPS"


def test_detect_dns_protocol_and_query():
    analyzer = PacketAnalyzer()

    packet = (
        Ether()
        / IP(src="192.168.0.10", dst="8.8.8.8")
        / UDP(sport=50000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    protocol = analyzer.get_protocol(packet)
    info = analyzer.get_info(packet)

    assert protocol == "DNS"
    assert "example.com" in info