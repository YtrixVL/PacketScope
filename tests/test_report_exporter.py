from app.core.report_exporter import ReportExporter
from app.models.packet_info import PacketInfo


def test_export_to_csv(tmp_path):
    exporter = ReportExporter()

    packets = [
        PacketInfo(1, "12:00:01", "192.168.0.10", "8.8.8.8", "DNS", 74, "DNS query: google.com"),
        PacketInfo(2, "12:00:02", "192.168.0.10", "1.1.1.1", "HTTPS", 120, "HTTPS TCP 50000 → 443"),
    ]

    file_path = tmp_path / "report.csv"

    exporter.export_to_csv(packets, str(file_path))

    assert file_path.exists()

    content = file_path.read_text(encoding="utf-8")

    assert "Number" in content
    assert "DNS" in content
    assert "HTTPS" in content