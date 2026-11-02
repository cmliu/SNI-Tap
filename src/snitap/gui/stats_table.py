"""域名统计表：域名 / ASCII 条形 / 次数 三列，终端风只读表，双击复制域名。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from . import theme

_BAR_MAX_LEN = 10  # 条形最大长度（▮ 个数）
_BAR_COLUMN_WIDTH = 120
_COUNT_COLUMN_WIDTH = 64


class StatsTable(QTableWidget):
    """域名统计表：域名（青色、等宽、省略号截断）/ 条形（绿色 ▮）/ 次数（绿色右对齐）。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, 3, parent)
        self.setHorizontalHeaderLabels(["域名", "条形", "次数"])
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setTextElideMode(Qt.ElideRight)
        self.setObjectName("StatsTable")

        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setFixedHeight(26)
        self.setColumnWidth(1, _BAR_COLUMN_WIDTH)
        self.setColumnWidth(2, _COUNT_COLUMN_WIDTH)

        bars_header = self.horizontalHeaderItem(1)
        count_header = self.horizontalHeaderItem(2)
        if bars_header is not None:
            bars_header.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        if count_header is not None:
            count_header.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.cellDoubleClicked.connect(self._copy_domain)

    def set_domains(self, domains: tuple[tuple[str, int], ...]) -> None:
        """全量刷新（数据源已按次数降序）；每秒至多一次，量级很小。

        条形列渲染 ASCII 字符 ``"▮" * n``，``n = round(count / max_count * 10)``
        （至少为 1，避免低频域名条形为空）。
        """
        max_count = max((count for _, count in domains), default=1) or 1
        t = theme.current()
        self.setUpdatesEnabled(False)
        try:
            self.setRowCount(len(domains))
            for row, (domain, count) in enumerate(domains):
                name_item = QTableWidgetItem(domain)
                name_item.setToolTip(domain)
                name_item.setForeground(QBrush(QColor(t.cyan)))

                bar_len = max(1, round(count / max_count * _BAR_MAX_LEN))
                bar_item = QTableWidgetItem("▮" * bar_len)
                bar_item.setForeground(QBrush(QColor(t.green)))

                count_item = QTableWidgetItem(str(count))
                count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                count_item.setForeground(QBrush(QColor(t.green)))

                # 终端风只读：条形 / 次数列去掉可编辑标志
                for item in (bar_item, count_item):
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)

                self.setItem(row, 0, name_item)
                self.setItem(row, 1, bar_item)
                self.setItem(row, 2, count_item)
        finally:
            self.setUpdatesEnabled(True)

    def _copy_domain(self, row: int, _column: int) -> None:
        """双击任意单元格：复制该行域名。"""
        item = self.item(row, 0)
        if item is not None:
            QApplication.clipboard().setText(item.text())
