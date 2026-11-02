"""SNI 嗅探日志区：等宽字体、只读、自动滚动、上限 5000 行。"""

from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QPlainTextEdit, QWidget

MAX_LINES = 5000


class LogPanel(QPlainTextEdit):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(MAX_LINES)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setPlaceholderText("等待嗅探到 SNI 域名…")
        self.setObjectName("LogPanel")

        font = QFont("Consolas")
        font.setStyleHint(QFont.Monospace)
        font.setPointSize(10)
        self.setFont(font)

    def append_lines(self, lines: list[str]) -> None:
        """批量追加，减少重绘次数；appendPlainText 会自动滚动到底。"""
        if not lines:
            return
        self.appendPlainText("\n".join(lines))
