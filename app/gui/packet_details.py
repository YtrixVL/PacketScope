from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QTabWidget


class PacketDetails(QWidget):
    """
    Панель подробного просмотра пакета.
    Содержит вкладки: структура, ASCII, HEX, Raw.
    """

    def __init__(self):
        super().__init__()

        self.tabs = QTabWidget()

        self.structure_text = QTextEdit()
        self.ascii_text = QTextEdit()
        self.hex_text = QTextEdit()
        self.raw_text = QTextEdit()

        self.text_widgets = [
            self.structure_text,
            self.ascii_text,
            self.hex_text,
            self.raw_text
        ]

        for widget in self.text_widgets:
            widget.setReadOnly(True)
            widget.setPlaceholderText("Выберите пакет в таблице...")

        self.tabs.addTab(self.structure_text, "Структура")
        self.tabs.addTab(self.ascii_text, "ASCII")
        self.tabs.addTab(self.hex_text, "HEX")
        self.tabs.addTab(self.raw_text, "Raw Scapy")

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)

        self.setLayout(layout)

    def show_details(self, structure: str, ascii_view: str, hex_view: str, raw_view: str):
        self.structure_text.setText(structure)
        self.ascii_text.setText(ascii_view)
        self.hex_text.setText(hex_view)
        self.raw_text.setText(raw_view)

    def clear_details(self):
        for widget in self.text_widgets:
            widget.clear()