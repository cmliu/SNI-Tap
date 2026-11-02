"""域名统计表：两列（域名 / 次数），只读，按次数降序，双击复制。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

_COUNT_COLUMN_WIDTH = 72


class StatsTable(QTableWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, 2, parent)
        self.setHorizontalHeaderLabels(["域名", "次数"])
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setObjectName("StatsTable")

        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setFixedHeight(28)
        self.setColumnWidth(1, _COUNT_COLUMN_WIDTH)

        name_header = self.horizontalHeaderItem(0)
        count_header = self.horizontalHeaderItem(1)
        if name_header is not None:
            name_header.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        if count_header is not None:
            count_header.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self.cellDoubleClicked.connect(self._copy_cell)

    def set_domains(self, domains: tuple[tuple[str, int], ...]) -> None:
        """全量刷新（数据源已按次数降序）；每秒至多一次，量级很小。"""
        self.setUpdatesEnabled(False)
        try:
            self.setRowCount(len(domains))
            for row, (domain, count) in enumerate(domains):
                name_item = QTableWidgetItem(domain)
                name_item.setToolTip(domain)
                count_item = QTableWidgetItem(str(count))
                count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.setItem(row, 0, name_item)
                self.setItem(row, 1, count_item)
        finally:
            self.setUpdatesEnabled(True)

    def _copy_cell(self, row: int, column: int) -> None:
        item = self.item(row, column)
        if item is not None:
            QApplication.clipboard().setText(item.text())
