"""域名统计表：域名 / 条形 / 次数 三列，Canvas 自绘，双击复制域名。

``ttk.Treeview`` 只能整行设色，做不到「同一行三列三种颜色」，因此用 Canvas
自绘单元格；表头单独用 Frame 拼装以便不随内容滚动。

为支撑上千域名，绘制做了**可见行虚拟化**（只画视口内的行）与**截断宽度缓存**
（同一宽度下不重复 ``font.measure()`` 二分）。
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from typing import Optional, Sequence

from . import theme
from .widgets import SlimScrollbar, px

_BAR_MAX_LEN = 10  # 条形最大长度（▮ 个数）
_BAR_COLUMN_WIDTH = 120
_COUNT_COLUMN_WIDTH = 64
_ROW_HEIGHT = 24
_HEADER_HEIGHT = 26


def _elide(text: str, font: tkfont.Font, max_width: int) -> str:
    """超出 ``max_width`` 时用省略号右截断（对齐 Qt 的 ``Qt.ElideRight``）。"""
    if max_width <= 0:
        return ""
    if font.measure(text) <= max_width:
        return text
    ellipsis = "\u2026"
    low, high = 0, len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if font.measure(text[:mid] + ellipsis) <= max_width:
            low = mid
        else:
            high = mid - 1
    return (text[:low] + ellipsis) if low > 0 else ellipsis


class StatsTable(tk.Frame):
    """域名统计表：域名（青色、省略号截断）/ 条形（绿色 ▮）/ 次数（绿色右对齐）。"""

    def __init__(self, master: tk.Misc, font: tkfont.Font, header_font: tkfont.Font) -> None:
        """构建统计表。

        Args:
            master: 父容器。
            font: 数据行字体。
            header_font: 表头字体（11px）。
        """
        super().__init__(master, bg=theme.current().pane, bd=0, highlightthickness=0)
        self._font = font
        self._header_font = header_font
        self._rows: list[tuple[str, int]] = []
        self._hover_index = -1
        self._selected_index = -1

        self._row_h = px(_ROW_HEIGHT)
        self._header_h = px(_HEADER_HEIGHT)
        self._bar_col_w = px(_BAR_COLUMN_WIDTH)
        self._count_col_w = px(_COUNT_COLUMN_WIDTH)

        # 截断缓存：(域名) -> 当前宽度下的省略结果；宽度变化时整体失效
        self._elide_cache: dict[str, str] = {}
        self._text_width = -1

        self._build_header()
        self._build_body()

    # ------------------------------------------------------------------ 构建

    def _build_header(self) -> None:
        """表头：透明底、muted 11px、下方 1px 分隔线，行高 26。"""
        t = theme.current()
        head = tk.Frame(self, bg=t.pane, height=self._header_h)
        head.pack(side="top", fill="x", padx=(0, px(8)))
        head.pack_propagate(False)

        self._header_labels: list[tk.Label] = []

        domain_cell = tk.Frame(head, bg=t.pane)
        domain_cell.pack(side="left", fill="both", expand=True)
        self._header_labels.append(
            tk.Label(
                domain_cell,
                text="域名",
                bg=t.pane,
                fg=t.muted,
                font=self._header_font,
                anchor="w",
                bd=0,
                highlightthickness=0,
            )
        )
        self._header_labels[-1].pack(side="left", padx=(px(6), 0))

        bar_cell = tk.Frame(head, bg=t.pane, width=self._bar_col_w, height=self._header_h)
        bar_cell.pack(side="left", fill="y")
        bar_cell.pack_propagate(False)
        self._header_labels.append(
            tk.Label(
                bar_cell,
                text="条形",
                bg=t.pane,
                fg=t.muted,
                font=self._header_font,
                anchor="w",
                bd=0,
                highlightthickness=0,
            )
        )
        self._header_labels[-1].pack(side="left", padx=(px(6), 0))

        count_cell = tk.Frame(head, bg=t.pane, width=self._count_col_w, height=self._header_h)
        count_cell.pack(side="left", fill="y")
        count_cell.pack_propagate(False)
        self._header_labels.append(
            tk.Label(
                count_cell,
                text="次数",
                bg=t.pane,
                fg=t.muted,
                font=self._header_font,
                anchor="e",
                bd=0,
                highlightthickness=0,
            )
        )
        self._header_labels[-1].pack(side="right", padx=(0, px(6)))

        self._head = head
        self._separator = tk.Frame(self, bg=t.border, height=px(1))
        self._separator.pack(side="top", fill="x")

    def _build_body(self) -> None:
        """表体：Canvas 绘制行 + 独立极细滚动条。"""
        t = theme.current()
        body = tk.Frame(self, bg=t.pane, bd=0, highlightthickness=0)
        body.pack(side="top", fill="both", expand=True)
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(
            body,
            bg=t.pane,
            bd=0,
            highlightthickness=0,
            takefocus=1,
            width=1,
            height=1,
            yscrollincrement=self._row_h,
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.vbar = SlimScrollbar(body, "vertical", self._scroll_command, "pane")
        self.vbar.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(yscrollcommand=self.vbar.set)

        self.canvas.bind("<Configure>", self._on_configure)
        self.canvas.bind("<Motion>", self._on_motion)
        self.canvas.bind("<Leave>", self._on_leave)
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<Double-Button-1>", self._on_double_click)
        self.canvas.bind("<MouseWheel>", self._on_wheel)

    # ------------------------------------------------------------------ 主题

    def retheme(self) -> None:
        """主题切换后重染表头、画布与全部行。"""
        t = theme.current()
        self.configure(bg=t.pane)
        self._head.configure(bg=t.pane)
        for cell in self._head.winfo_children():
            if isinstance(cell, tk.Frame):
                cell.configure(bg=t.pane)
        for label in self._header_labels:
            label.configure(bg=t.pane, fg=t.muted)
        self._separator.configure(bg=t.border)
        self.canvas.configure(bg=t.pane)
        self.vbar.retheme()
        self._render()

    # ------------------------------------------------------------------ 数据

    def set_domains(self, domains: Sequence[tuple[str, int]]) -> None:
        """全量刷新（数据源已按次数降序）。

        Args:
            domains: ``(域名, 次数)`` 序列，调用方保证已降序排列。
        """
        self._rows = list(domains)
        self._hover_index = -1
        if self._selected_index >= len(self._rows):
            self._selected_index = -1
        self._render()

    @property
    def row_count(self) -> int:
        """当前行数。"""
        return len(self._rows)

    def copy_domain(self, index: int) -> None:
        """把指定行的域名写入剪贴板。

        Args:
            index: 行号，越界时静默忽略。
        """
        if not 0 <= index < len(self._rows):
            return
        self.clipboard_clear()
        self.clipboard_append(self._rows[index][0])

    # -------------------------------------------------------------- 渲染实现

    def _scroll_command(self, *args: object) -> None:
        """滚动条回调：改视口后重绘可见区。"""
        self.canvas.yview(*args)
        self._render()

    def _visible_range(self, height: int) -> tuple[int, int]:
        """返回当前视口覆盖的行区间 ``[first, last)``。"""
        top = self.canvas.canvasy(0)
        first = max(0, int(top // self._row_h))
        last = min(len(self._rows), int((top + height) // self._row_h) + 2)
        return first, max(first, last)

    def _render(self) -> None:
        """重绘可见行（虚拟化：只画视口内的行）。"""
        t = theme.current()
        self.canvas.delete("row")
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        if width <= 1 or height <= 1:
            return

        total = len(self._rows) * self._row_h
        self.canvas.configure(scrollregion=(0, 0, width, max(total, height)))

        bar_left = width - self._count_col_w - self._bar_col_w
        domain_x = px(6)
        domain_max_w = max(px(24), bar_left - px(12))
        if domain_max_w != self._text_width:  # 宽度变了，截断缓存整体失效
            self._text_width = domain_max_w
            self._elide_cache.clear()
        bar_x = bar_left + px(6)
        count_x = width - px(6)
        max_count = max((count for _, count in self._rows), default=1) or 1

        first, last = self._visible_range(height)
        for index in range(first, last):
            domain, count = self._rows[index]
            top = index * self._row_h
            center = top + self._row_h / 2.0
            self.canvas.create_rectangle(
                0, top, width, top + self._row_h,
                fill=self._background_for(index), outline="", tags="row",
            )
            self.canvas.create_text(
                domain_x, center,
                text=self._elided(domain, domain_max_w),
                anchor="w", fill=t.cyan, font=self._font, tags="row",
            )
            bar_len = max(1, round(count / max_count * _BAR_MAX_LEN))
            self.canvas.create_text(
                bar_x, center,
                text="\u25ae" * bar_len,
                anchor="w", fill=t.green, font=self._font, tags="row",
            )
            self.canvas.create_text(
                count_x, center,
                text=str(count),
                anchor="e", fill=t.green, font=self._font, tags="row",
            )

    def _elided(self, domain: str, max_width: int) -> str:
        """带缓存的省略号截断（同一宽度下命中缓存，不做 font.measure 二分）。"""
        cached = self._elide_cache.get(domain)
        if cached is None:
            cached = _elide(domain, self._font, max_width)
            self._elide_cache[domain] = cached
        return cached

    def _background_for(self, index: int) -> str:
        """行底色：选中 > 悬停 > 面板底色。"""
        t = theme.current()
        if index == self._selected_index:
            return theme.mix(t.green, 0.14, t.pane)
        if index == self._hover_index:
            return t.hover
        return t.pane

    def _index_at(self, y: int) -> int:
        """画布 y 坐标 → 行号。"""
        if self._row_h <= 0:
            return -1
        index = int(self.canvas.canvasy(y) // self._row_h)
        return index if 0 <= index < len(self._rows) else -1

    # ------------------------------------------------------------------ 事件

    def _on_configure(self, _event: tk.Event) -> None:
        self._render()

    def _on_motion(self, event: tk.Event) -> None:
        index = self._index_at(event.y)
        if index == self._hover_index:
            return
        self._hover_index = index
        self._render()

    def _on_leave(self, _event: tk.Event) -> None:
        if self._hover_index == -1:
            return
        self._hover_index = -1
        self._render()

    def _on_click(self, event: tk.Event) -> None:
        index = self._index_at(event.y)
        if index == self._selected_index:
            return
        self._selected_index = index
        self._render()

    def _on_double_click(self, event: tk.Event) -> None:
        index = self._index_at(event.y)
        if index >= 0:
            self.copy_domain(index)

    def _on_wheel(self, event: tk.Event) -> None:
        if not self._rows:
            return
        self.canvas.yview_scroll(int(-event.delta / 120), "units")
        self._render()
