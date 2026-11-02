"""SNI 嗅探日志区：富文本渲染、只读、自动滚动、上限 5000 行、主题重染。"""

from __future__ import annotations

import html
from collections import deque

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QPlainTextEdit, QWidget

from . import theme

MAX_LINES = 5000


class LogPanel(QPlainTextEdit):
    """SNI 嗅探日志面板。

    基于 QPlainTextEdit + appendHtml 实现「时间戳弱化、域名青色」的
    终端风富文本日志；maximumBlockCount 保证最多保留 MAX_LINES 行。
    内部保留原始条目队列，主题切换时 ``retheme()`` 可整板重染。
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(MAX_LINES)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setPlaceholderText("等待嗅探到 SNI 域名…")
        self.setObjectName("LogPanel")

        self._entries: deque[tuple[str, str]] = deque(maxlen=MAX_LINES)

        font = QFont("Consolas")
        font.setStyleHint(QFont.Monospace)
        font.setPointSize(10)
        self.setFont(font)

    def append_lines(self, lines: list[str]) -> None:
        """批量追加日志行；每行格式为 ``"HH:MM:SS domain"``。

        逐行 appendHtml 上色（时间戳弱化 / 域名强调色），
        appendHtml 会自动滚动到底部。
        """
        for line in lines:
            ts, sep, domain = line.partition(" ")
            if not sep:
                ts, domain = "", line
            self._entries.append((ts, domain))
            self._append_colored(ts, domain)

    def retheme(self) -> None:
        """主题切换后整板重染（保留条目与顺序，不触发逐行滚动动画）。"""
        self._entries = deque(self._entries, maxlen=MAX_LINES)
        self.setUpdatesEnabled(False)
        try:
            self.clear()
            for ts, domain in self._entries:
                self._append_colored(ts, domain)
        finally:
            self.setUpdatesEnabled(True)

    def _append_colored(self, ts: str, domain: str) -> None:
        """按当前主题色追加单行富文本。"""
        t = theme.current()
        text = ""
        if ts:
            text += f"<span style='color: {t.dim};'>{html.escape(ts)}</span>&nbsp;&nbsp;"
        text += f"<span style='color: {t.cyan};'>{html.escape(domain)}</span>"
        self.appendHtml(text)
