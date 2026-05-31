from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit


class StatisticsPanel(QWidget):
    def __init__(self):
        super().__init__()

        self.title_label = QLabel("Статистика")
        self.total_packets_label = QLabel("Всего пакетов: 0")
        self.total_size_label = QLabel("Общий размер: 0 bytes")
        self.average_size_label = QLabel("Средний размер: 0 bytes")
        self.protocols_label = QLabel("Протоколы: -")

        self.top_ips_label = QLabel("Топ IP-адресов:")
        self.top_ips_text = QTextEdit()
        self.top_ips_text.setReadOnly(True)
        self.top_ips_text.setMaximumHeight(90)

        self.dns_domains_label = QLabel("DNS-домены:")
        self.dns_domains_text = QTextEdit()
        self.dns_domains_text.setReadOnly(True)
        self.dns_domains_text.setMaximumHeight(120)

        self.security_label = QLabel("Анализ безопасности:")
        self.security_text = QTextEdit()
        self.security_text.setReadOnly(True)
        self.security_text.setMaximumHeight(160)

        layout = QVBoxLayout()

        layout.addWidget(self.title_label)
        layout.addWidget(self.total_packets_label)
        layout.addWidget(self.total_size_label)
        layout.addWidget(self.average_size_label)
        layout.addWidget(self.protocols_label)

        layout.addWidget(self.top_ips_label)
        layout.addWidget(self.top_ips_text)

        layout.addWidget(self.dns_domains_label)
        layout.addWidget(self.dns_domains_text)

        layout.addWidget(self.security_label)
        layout.addWidget(self.security_text)

        self.setLayout(layout)

    def update_statistics(self, statistics, security_warnings):
        self.total_packets_label.setText(
            f"Всего пакетов: {statistics['total_packets']}"
        )

        self.total_size_label.setText(
            f"Общий размер: {statistics['total_size']} bytes"
        )

        self.average_size_label.setText(
            f"Средний размер: {statistics['average_size']:.2f} bytes"
        )

        protocols = statistics["protocols"]

        if not protocols:
            self.protocols_label.setText("Протоколы: -")
        else:
            protocol_text = " | ".join(
                f"{protocol}: {count}"
                for protocol, count in sorted(protocols.items())
            )
            self.protocols_label.setText(f"Протоколы: {protocol_text}")

        self.update_top_ips(statistics["top_ips"])
        self.update_dns_domains(statistics["dns_domains"])
        self.update_security_warnings(security_warnings)

    def update_top_ips(self, top_ips):
        if not top_ips:
            self.top_ips_text.setText("Нет данных")
            return

        lines = []

        for ip_address, count in top_ips:
            lines.append(f"{ip_address}: {count}")

        self.top_ips_text.setText("\n".join(lines))

    def update_dns_domains(self, dns_domains):
        if not dns_domains:
            self.dns_domains_text.setText("DNS-домены не найдены")
            return

        lines = []

        for domain, count in dns_domains:
            lines.append(f"{domain}: {count}")

        self.dns_domains_text.setText("\n".join(lines))

    def update_security_warnings(self, warnings):
        if not warnings:
            self.security_text.setText("Нет данных")
            return

        self.security_text.setText("\n".join(f"- {warning}" for warning in warnings))