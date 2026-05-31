from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QComboBox,
    QFileDialog,
    QMessageBox,
    QSplitter,
    QLineEdit,
    QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer

from app.core.sniffer import PacketSniffer
from app.core.packet_analyzer import PacketAnalyzer
from app.core.capture_storage import CaptureStorage
from app.core.packet_filter import PacketFilter
from app.core.traffic_statistics import TrafficStatistics
from app.core.security_analyzer import SecurityAnalyzer
from app.core.report_exporter import ReportExporter

from app.gui.packet_table import PacketTable
from app.gui.packet_details import PacketDetails
from app.gui.statistics_panel import StatisticsPanel

from app.utils.network_interfaces import get_network_interfaces


class MainWindow(QMainWindow):
    packet_captured = pyqtSignal(object)
    capture_error = pyqtSignal(str)

    MAX_VISIBLE_PACKETS = 3000

    def __init__(self):
        super().__init__()

        self.setWindowTitle("PacketScope — анализатор сетевого трафика")
        self.setMinimumSize(1300, 820)

        self.sniffer = PacketSniffer()
        self.analyzer = PacketAnalyzer()
        self.storage = CaptureStorage()
        self.packet_filter = PacketFilter()
        self.statistics = TrafficStatistics()
        self.security_analyzer = SecurityAnalyzer()
        self.report_exporter = ReportExporter()

        self.packet_counter = 0

        self.raw_packets = []
        self.packet_infos = []

        self.filtered_raw_packets = []
        self.filtered_packet_infos = []

        self.pending_raw_packets = []
        self.pending_packet_infos = []

        self.init_ui()
        self.connect_signals()
        self.load_interfaces()

        self.ui_update_timer = QTimer()
        self.ui_update_timer.setInterval(500)
        self.ui_update_timer.timeout.connect(self.flush_pending_packets)
        self.ui_update_timer.start()

    def init_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        capture_layout = QHBoxLayout()

        self.interface_label = QLabel("Интерфейс:")
        self.interface_combo = QComboBox()

        self.bpf_filter_label = QLabel("BPF-фильтр:")
        self.bpf_filter_input = QLineEdit()
        self.bpf_filter_input.setPlaceholderText(
            "tcp, udp, web, dns, http, https, port 53, host 8.8.8.8"
        )

        self.autoscroll_checkbox = QCheckBox("Автопрокрутка")
        self.autoscroll_checkbox.setChecked(True)

        self.start_button = QPushButton("Старт")
        self.stop_button = QPushButton("Стоп")
        self.clear_button = QPushButton("Очистить")

        self.stop_button.setEnabled(False)

        capture_layout.addWidget(self.interface_label)
        capture_layout.addWidget(self.interface_combo)
        capture_layout.addWidget(self.bpf_filter_label)
        capture_layout.addWidget(self.bpf_filter_input)
        capture_layout.addWidget(self.autoscroll_checkbox)
        capture_layout.addWidget(self.start_button)
        capture_layout.addWidget(self.stop_button)
        capture_layout.addWidget(self.clear_button)

        file_layout = QHBoxLayout()

        self.open_button = QPushButton("Открыть PCAP/PCAPNG")
        self.save_pcap_button = QPushButton("Сохранить PCAP")
        self.save_pcapng_button = QPushButton("Сохранить PCAPNG")
        self.export_csv_button = QPushButton("Экспорт CSV")
        self.export_txt_button = QPushButton("Экспорт TXT")

        file_layout.addWidget(self.open_button)
        file_layout.addWidget(self.save_pcap_button)
        file_layout.addWidget(self.save_pcapng_button)
        file_layout.addWidget(self.export_csv_button)
        file_layout.addWidget(self.export_txt_button)

        filter_layout = QHBoxLayout()

        self.display_filter_label = QLabel("Фильтр отображения:")
        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText(
            "TCP, HTTPS, DNS, SSH, RDP, 192.168.0.1, 443, google"
        )

        self.apply_filter_button = QPushButton("Применить")
        self.reset_filter_button = QPushButton("Сбросить")

        filter_layout.addWidget(self.display_filter_label)
        filter_layout.addWidget(self.display_filter_input)
        filter_layout.addWidget(self.apply_filter_button)
        filter_layout.addWidget(self.reset_filter_button)

        self.packet_table = PacketTable()
        self.packet_details = PacketDetails()
        self.statistics_panel = StatisticsPanel()

        right_panel = QWidget()
        right_panel_layout = QVBoxLayout()
        right_panel_layout.addWidget(self.statistics_panel)
        right_panel_layout.addStretch()
        right_panel.setLayout(right_panel_layout)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self.packet_table)
        top_splitter.addWidget(right_panel)
        top_splitter.setSizes([950, 350])

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(self.packet_details)
        main_splitter.setSizes([520, 300])

        main_layout.addLayout(capture_layout)
        main_layout.addLayout(file_layout)
        main_layout.addLayout(filter_layout)
        main_layout.addWidget(main_splitter)

        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def connect_signals(self):
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_packets)

        self.open_button.clicked.connect(self.open_capture)
        self.save_pcap_button.clicked.connect(self.save_pcap)
        self.save_pcapng_button.clicked.connect(self.save_pcapng)

        self.export_csv_button.clicked.connect(self.export_csv)
        self.export_txt_button.clicked.connect(self.export_txt)

        self.apply_filter_button.clicked.connect(self.apply_display_filter)
        self.reset_filter_button.clicked.connect(self.reset_display_filter)
        self.display_filter_input.returnPressed.connect(self.apply_display_filter)

        self.packet_captured.connect(self.handle_packet_captured)
        self.capture_error.connect(self.handle_capture_error)
        self.packet_table.cellClicked.connect(self.show_packet_details)

    def load_interfaces(self):
        interfaces = get_network_interfaces()

        if not interfaces:
            self.interface_combo.addItem("Интерфейсы не найдены")
            self.start_button.setEnabled(False)
            return

        self.interface_combo.addItems(interfaces)

    def start_capture(self):
        interface = self.interface_combo.currentText()
        bpf_filter = self.normalize_bpf_filter(
            self.bpf_filter_input.text().strip()
        )

        if not interface or interface == "Интерфейсы не найдены":
            QMessageBox.warning(self, "Ошибка", "Выберите сетевой интерфейс")
            return

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.interface_combo.setEnabled(False)
        self.bpf_filter_input.setEnabled(False)

        self.sniffer.start_capture(
            interface=interface,
            packet_callback=self.emit_packet_signal,
            error_callback=self.emit_capture_error,
            bpf_filter=bpf_filter if bpf_filter else None
        )

        self.statusBar().showMessage("Захват запущен")

    def normalize_bpf_filter(self, bpf_filter: str) -> str:
        if not bpf_filter:
            return ""

        aliases = {
            "http": "tcp port 80",
            "https": "tcp port 443",
            "dns": "port 53",
            "tls": "tcp port 443",
            "web": "tcp and (port 80 or port 443)",
            "http/https": "tcp and (port 80 or port 443)",
            "http https": "tcp and (port 80 or port 443)",
            "ssh": "tcp port 22",
            "rdp": "tcp port 3389",
            "ntp": "udp port 123",
            "dhcp": "udp and (port 67 or port 68)",
        }

        normalized = bpf_filter.lower().strip()

        if normalized in aliases:
            return aliases[normalized]

        if "," in bpf_filter:
            parts = [
                part.strip()
                for part in bpf_filter.split(",")
                if part.strip()
            ]

            return " or ".join(parts)

        return bpf_filter

    def stop_capture(self):
        self.sniffer.stop_capture()

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.bpf_filter_input.setEnabled(True)

        self.statusBar().showMessage("Захват остановлен")

    def emit_packet_signal(self, packet):
        self.packet_captured.emit(packet)

    def emit_capture_error(self, error_text: str):
        self.capture_error.emit(error_text)

    def handle_capture_error(self, error_text: str):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.bpf_filter_input.setEnabled(True)

        QMessageBox.critical(
            self,
            "Ошибка захвата пакетов",
            (
                "Не удалось запустить захват.\n\n"
                f"Ошибка:\n{error_text}\n\n"
                "Проверь BPF-фильтр. Примеры:\n"
                "tcp\n"
                "udp\n"
                "tcp port 443\n"
                "tcp and (port 80 or port 443)\n"
                "port 53\n"
                "host 8.8.8.8"
            )
        )

    def handle_packet_captured(self, packet):
        self.packet_counter += 1

        packet_info = self.analyzer.analyze(packet, self.packet_counter)

        self.raw_packets.append(packet)
        self.packet_infos.append(packet_info)

        self.pending_raw_packets.append(packet)
        self.pending_packet_infos.append(packet_info)

    def flush_pending_packets(self):
        if not self.pending_packet_infos:
            return

        current_filter = self.display_filter_input.text().strip()

        if current_filter:
            self.apply_display_filter()
        else:
            batch_infos = self.pending_packet_infos[:]
            batch_raw = self.pending_raw_packets[:]

            self.filtered_packet_infos.extend(batch_infos)
            self.filtered_raw_packets.extend(batch_raw)

            self.packet_table.add_packets_batch(batch_infos)
            self.limit_visible_packets()

            if self.autoscroll_checkbox.isChecked():
                self.packet_table.scrollToBottom()

            self.update_statistics_panel()

        self.pending_packet_infos.clear()
        self.pending_raw_packets.clear()

        self.statusBar().showMessage(
            f"Захвачено: {len(self.packet_infos)} | "
            f"Отображается: {self.packet_table.rowCount()}"
        )

    def limit_visible_packets(self):
        while self.packet_table.rowCount() > self.MAX_VISIBLE_PACKETS:
            self.packet_table.removeRow(0)

    def apply_display_filter(self):
        query = self.display_filter_input.text().strip()

        self.filtered_packet_infos = self.packet_filter.filter_packet_infos(
            self.packet_infos,
            query
        )

        filtered_numbers = {
            packet_info.number
            for packet_info in self.filtered_packet_infos
        }

        self.filtered_raw_packets = [
            raw_packet
            for raw_packet, packet_info in zip(self.raw_packets, self.packet_infos)
            if packet_info.number in filtered_numbers
        ]

        visible_infos = self.filtered_packet_infos[-self.MAX_VISIBLE_PACKETS:]
        self.packet_table.set_packets(visible_infos)

        self.update_statistics_panel()

        self.statusBar().showMessage(
            f"Фильтр: '{query}' | Найдено: {len(self.filtered_packet_infos)}"
        )

    def reset_display_filter(self):
        self.display_filter_input.clear()

        self.filtered_packet_infos = self.packet_infos[:]
        self.filtered_raw_packets = self.raw_packets[:]

        visible_infos = self.filtered_packet_infos[-self.MAX_VISIBLE_PACKETS:]
        self.packet_table.set_packets(visible_infos)

        self.update_statistics_panel()

        self.statusBar().showMessage("Фильтр сброшен")

    def show_packet_details(self, row, column):
        visible_rows = self.packet_table.rowCount()
        total_filtered = len(self.filtered_raw_packets)

        first_visible_index = max(0, total_filtered - visible_rows)
        packet_index = first_visible_index + row

        if packet_index < 0 or packet_index >= len(self.filtered_raw_packets):
            return

        packet = self.filtered_raw_packets[packet_index]

        structure = self.analyzer.get_structure_details(packet)
        ascii_view = self.analyzer.get_ascii_view(packet)
        hex_view = self.analyzer.get_hex_view(packet)
        raw_view = self.analyzer.get_raw_view(packet)

        self.packet_details.show_details(
            structure=structure,
            ascii_view=ascii_view,
            hex_view=hex_view,
            raw_view=raw_view
        )

    def update_statistics_panel(self):
        statistics = self.statistics.calculate(self.filtered_packet_infos)
        security_warnings = self.security_analyzer.analyze(self.filtered_packet_infos)

        self.statistics_panel.update_statistics(
            statistics=statistics,
            security_warnings=security_warnings
        )

    def clear_packets(self):
        self.packet_counter = 0

        self.raw_packets.clear()
        self.packet_infos.clear()

        self.filtered_raw_packets.clear()
        self.filtered_packet_infos.clear()

        self.pending_raw_packets.clear()
        self.pending_packet_infos.clear()

        self.sniffer.clear_packets()
        self.packet_table.clear_packets()
        self.packet_details.clear_details()

        self.update_statistics_panel()
        self.statusBar().showMessage("Очищено")

    def open_capture(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Открыть файл захвата",
            "captures",
            "Capture files (*.pcap *.pcapng)"
        )

        if not file_path:
            return

        try:
            packets = self.storage.load_capture(file_path)
        except Exception as error:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть файл:\n{error}")
            return

        self.clear_packets()

        for packet in packets:
            self.packet_counter += 1
            packet_info = self.analyzer.analyze(packet, self.packet_counter)

            self.raw_packets.append(packet)
            self.packet_infos.append(packet_info)

        self.filtered_raw_packets = self.raw_packets[:]
        self.filtered_packet_infos = self.packet_infos[:]

        visible_infos = self.filtered_packet_infos[-self.MAX_VISIBLE_PACKETS:]
        self.packet_table.set_packets(visible_infos)

        self.update_statistics_panel()

        self.statusBar().showMessage(
            f"Файл открыт: {file_path} | Пакетов: {len(self.packet_infos)}"
        )

    def save_pcap(self):
        if not self.raw_packets:
            QMessageBox.warning(self, "Ошибка", "Нет пакетов для сохранения")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить PCAP",
            "captures/capture.pcap",
            "PCAP files (*.pcap)"
        )

        if not file_path:
            return

        try:
            self.storage.save_to_pcap(self.raw_packets, file_path)
            QMessageBox.information(self, "Готово", "Файл PCAP успешно сохранён")
        except Exception as error:
            QMessageBox.critical(self, "Ошибка", str(error))

    def save_pcapng(self):
        if not self.raw_packets:
            QMessageBox.warning(self, "Ошибка", "Нет пакетов для сохранения")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить PCAPNG",
            "captures/capture.pcapng",
            "PCAPNG files (*.pcapng)"
        )

        if not file_path:
            return

        try:
            self.storage.save_to_pcapng(self.raw_packets, file_path)
            QMessageBox.information(self, "Готово", "Файл PCAPNG успешно сохранён")
        except Exception as error:
            QMessageBox.critical(self, "Ошибка", str(error))

    def export_csv(self):
        if not self.filtered_packet_infos:
            QMessageBox.warning(self, "Ошибка", "Нет данных для экспорта")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт CSV",
            "captures/report.csv",
            "CSV files (*.csv)"
        )

        if not file_path:
            return

        try:
            self.report_exporter.export_to_csv(
                self.filtered_packet_infos,
                file_path
            )
            QMessageBox.information(self, "Готово", "CSV-отчёт сохранён")
        except Exception as error:
            QMessageBox.critical(self, "Ошибка", str(error))

    def export_txt(self):
        if not self.filtered_packet_infos:
            QMessageBox.warning(self, "Ошибка", "Нет данных для экспорта")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Экспорт TXT",
            "captures/report.txt",
            "Text files (*.txt)"
        )

        if not file_path:
            return

        try:
            statistics = self.statistics.calculate(self.filtered_packet_infos)
            security_warnings = self.security_analyzer.analyze(
                self.filtered_packet_infos
            )

            self.report_exporter.export_to_txt(
                self.filtered_packet_infos,
                statistics,
                security_warnings,
                file_path
            )

            QMessageBox.information(self, "Готово", "TXT-отчёт сохранён")
        except Exception as error:
            QMessageBox.critical(self, "Ошибка", str(error))