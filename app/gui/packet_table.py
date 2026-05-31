from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush


class PacketTable(QTableWidget):
    def __init__(self):
        super().__init__()

        self.setColumnCount(7)
        self.setHorizontalHeaderLabels([
            "№",
            "Время",
            "Источник",
            "Назначение",
            "Протокол",
            "Размер",
            "Информация"
        ])

        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(False)

        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)

        self.setColumnWidth(0, 60)
        self.setColumnWidth(1, 120)
        self.setColumnWidth(2, 160)
        self.setColumnWidth(3, 160)
        self.setColumnWidth(4, 110)
        self.setColumnWidth(5, 80)
        self.setColumnWidth(6, 450)

    def add_packets_batch(self, packet_infos):
        if not packet_infos:
            return

        self.setUpdatesEnabled(False)

        for packet_info in packet_infos:
            self.add_packet_row(packet_info)

        self.setUpdatesEnabled(True)

    def set_packets(self, packet_infos):
        self.setUpdatesEnabled(False)
        self.setRowCount(0)

        for packet_info in packet_infos:
            self.add_packet_row(packet_info)

        self.setUpdatesEnabled(True)

    def add_packet_row(self, packet_info):
        row = self.rowCount()
        self.insertRow(row)

        values = [
            packet_info.number,
            packet_info.timestamp,
            packet_info.source,
            packet_info.destination,
            packet_info.protocol,
            packet_info.length,
            packet_info.info
        ]

        background_color = self.get_protocol_color(packet_info.protocol)
        text_color = QColor("#000000")

        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item.setBackground(QBrush(background_color))
            item.setForeground(QBrush(text_color))
            self.setItem(row, column, item)

    def get_protocol_color(self, protocol: str) -> QColor:
        colors = {
            "TCP": QColor("#D7E8FF"),
            "UDP": QColor("#DFF7DF"),
            "DNS": QColor("#FFF4B8"),
            "ICMP": QColor("#FFD6D6"),
            "ARP": QColor("#FFE0B8"),
            "HTTP": QColor("#E9D8FF"),
            "HTTPS": QColor("#CFEFFF"),
            "SSH": QColor("#D8F3DC"),
            "FTP": QColor("#FDE2E4"),
            "FTP-DATA": QColor("#FDE2E4"),
            "TELNET": QColor("#FFCCD5"),
            "SMTP": QColor("#E2F0CB"),
            "SMTPS": QColor("#E2F0CB"),
            "POP3": QColor("#CCE5FF"),
            "POP3S": QColor("#CCE5FF"),
            "IMAP": QColor("#CCE5FF"),
            "IMAPS": QColor("#CCE5FF"),
            "RDP": QColor("#FBC4AB"),
            "NTP": QColor("#E5D4EF"),
            "DHCP": QColor("#D0F4DE"),
            "MDNS": QColor("#FFF4B8"),
            "SSDP": QColor("#FFF4B8"),
            "MYSQL": QColor("#BDE0FE"),
            "POSTGRESQL": QColor("#BDE0FE"),
            "REDIS": QColor("#FFC8DD"),
            "IP": QColor("#E6E6E6"),
            "OTHER": QColor("#F0F0F0")
        }

        return colors.get(protocol, QColor("#FFFFFF"))

    def clear_packets(self):
        self.setRowCount(0)