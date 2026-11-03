"""协议栈统计表：单行布局（域名 · 应用层 · 传输层 · 安全层 · ECH + 条形 + 次数），Canvas 自绘。

``ttk.Treeview`` 只能整行设色，做不到「同一段多色」，因此用 Canvas 自绘
单元格；表头单独用 Frame 拼装以便不随内容滚动。

单行布局（v4）：
- 左起依次 域名（cyan）→ 应用层（muted）→ 传输层（dim）→ 安全层（green）
  → ``ECH``（amber，仅 ``has_ech`` 行，紧跟在安全层之后）；
- 右端固定两列：条形（green ▮）+ 次数（green 右对齐），与表头对齐；
- 域名先按「剩余空间扣掉协议栈实测宽度」截断，协议栈本身放不下时再从尾部
  逐段省略号截断，保证 `TLS1.3/…` 与 `ECH` 在窄窗口下也有机会显示。

为支撑上千组合，绘制做了**可见行虚拟化**（只画视口内的行）与**域名截断
宽度缓存**（宽度变化即失效）。
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from typing import Sequence

from . import theme
from ..protocol import StackRow
from .widgets import SlimScrollbar, px

_BAR_MAX_LEN = 6         # 条形最大长度（▮ 个数）
_BAR_COLUMN_WIDTH = 60
_COUNT_COLUMN_WIDTH = 56
_ROW_HEIGHT = 28         # 单行布局
_HEADER_HEIGHT = 30

# ECH 标记文案（与 protocol.ECH_MARK 一致）
_ECH_MARK = "ECH"

_LOG_SEP = "  "          # 段间分隔：两个空格（与日志区一致）
_MIN_DOMAIN_W = 48       # 域名列最小宽度（px），再小就优先压协议栈

# 截断缓存上限：超过整体清空，防止长会话下无界增长
_ELIDE_CACHE_MAX = 4096


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
    """协议栈统计表：单行式 ``域名 · 协议栈 · ECH`` + 条形 + 次数。"""

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
        self._rows: list[StackRow] = []
        self._hover_index = -1
        self._selected_index = -1

        self._row_h = px(_ROW_HEIGHT)
        self._header_h = px(_HEADER_HEIGHT)
        self._bar_col_w = px(_BAR_COLUMN_WIDTH)
        self._count_col_w = px(_COUNT_COLUMN_WIDTH)

        # 截断缓存（共享约定 15）：只缓存域名，协议栈各段按行实测
        self._domain_cache: dict[str, str] = {}
        self._domain_width = -1

        self._build_header()
        self._build_body()

    # ------------------------------------------------------------------ 构建

    def _build_header(self) -> None:
        """表头：透明底、muted 11px、下方 1px 分隔线。"""
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
                text="域名 / 协议栈",
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

    def set_rows(self, rows: Sequence[StackRow]) -> None:
        """全量刷新（数据源已按次数降序、四元组字典序稳定排列）。

        Args:
            rows: :class:`StackRow` 序列，调用方保证已排序。
        """
        self._rows = list(rows)
        self._hover_index = -1
        if self._selected_index >= len(self._rows):
            self._selected_index = -1
        self._render()

    @property
    def row_count(self) -> int:
        """当前行数。"""
        return len(self._rows)

    def copy_row(self, index: int) -> None:
        """把指定行写入剪贴板（TSV：domain/app/transport/security，可粘进 Excel）。

        Args:
            index: 行号，越界时静默忽略。
        """
        if not 0 <= index < len(self._rows):
            return
        row = self._rows[index]
        self.clipboard_clear()
        self.clipboard_append(f"{row.domain}\t{row.transport}\t{row.app}\t{row.security}")

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
        """重绘可见行（虚拟化：只画视口内的行；单行布局）。"""
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
        left_limit = max(domain_x + px(24), bar_left - px(8))
        avail = left_limit - domain_x
        if avail != self._domain_width:  # 宽度变了，只失效域名缓存
            self._domain_width = avail
            self._domain_cache.clear()
        if len(self._domain_cache) > _ELIDE_CACHE_MAX:
            self._domain_cache.clear()
        bar_x = bar_left + px(6)
        count_x = width - px(6)
        sep_w = self._font.measure(_LOG_SEP)
        max_count = max((row.count for row in self._rows), default=1) or 1

        first, last = self._visible_range(height)
        for index in range(first, last):
            row = self._rows[index]
            top = index * self._row_h
            mid_y = top + self._row_h * 0.5
            self.canvas.create_rectangle(
                0, top, width, top + self._row_h,
                fill=self._background_for(index), outline="", tags="row",
            )

            # 协议栈段：应用层 → 传输层 → 安全层 → ECH（紧随 TLS 版本之后）
            domain_max_w, segments = self._compose_line(row, t, avail)
            domain = self._elided_domain(row.domain, domain_max_w)
            self.canvas.create_text(
                domain_x, mid_y,
                text=domain,
                anchor="w", fill=t.cyan, font=self._font, tags="row",
            )

            x = domain_x + self._font.measure(domain) + sep_w
            for text, fill in segments:
                if x >= left_limit:
                    break
                room = left_limit - x
                if self._font.measure(text) > room:
                    text = _elide(text, self._font, room)
                if not text:
                    break
                self.canvas.create_text(
                    x, mid_y,
                    text=text,
                    anchor="w", fill=fill, font=self._font, tags="row",
                )
                x += self._font.measure(text) + sep_w

            bar_len = max(1, round(row.count / max_count * _BAR_MAX_LEN))
            self.canvas.create_text(
                bar_x, mid_y,
                text="\u25ae" * bar_len,
                anchor="w", fill=t.green, font=self._font, tags="row",
            )
            self.canvas.create_text(
                count_x, mid_y,
                text=str(row.count),
                anchor="e", fill=t.green, font=self._font, tags="row",
            )

    def _compose_line(
        self, row: StackRow, t: theme.Theme, avail: int,
    ) -> tuple[int, list[tuple[str, str]]]:
        """按空间优先级决定域名宽度与协议栈段。

        优先级：安全层 / ECH > 域名 > 传输层 > 应用层。窗口够宽时全显示；
        变窄先丢应用层、再丢传输层，始终保住 ``TLS1.3/…`` 与 ``ECH``。

        Returns:
            ``(域名可用宽度, 协议栈段列表)``。
        """
        sep_w = self._font.measure(_LOG_SEP)
        tail: list[tuple[str, str]] = [(self._security_without_ech(row.security), t.green)]
        if row.has_ech:
            tail.append((_ECH_MARK, t.amber))
        for head in (
            [(row.app, t.muted), (row.transport, t.dim)],
            [(row.transport, t.dim)],
            [],
        ):
            segments = head + tail
            width = sum(self._font.measure(text) for text, _ in segments)
            width += sep_w * max(0, len(segments) - 1)
            domain_w = avail - width - sep_w
            if domain_w >= px(_MIN_DOMAIN_W):
                return domain_w, segments
        # 极限窄：只留安全层 / ECH，域名按剩余宽度硬截
        width = sum(self._font.measure(text) for text, _ in tail)
        width += sep_w * max(0, len(tail) - 1)
        return max(px(24), avail - width - sep_w), tail

    @staticmethod
    def _security_without_ech(security: str) -> str:
        """剥掉安全层末尾的 `` ECH`` 后缀：该标记改由紧跟其后的琥珀色段承担。"""
        suffix = f" {_ECH_MARK}"
        if security.endswith(suffix):
            return security[:-len(suffix)]
        return security

    def _elided_domain(self, domain: str, max_width: int) -> str:
        """带缓存的域名省略号截断（同一宽度下命中缓存，不做 font.measure 二分）。"""
        cached = self._domain_cache.get(domain)
        if cached is None:
            cached = _elide(domain, self._font, max_width)
            self._domain_cache[domain] = cached
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
            self.copy_row(index)

    def _on_wheel(self, event: tk.Event) -> None:
        if not self._rows:
            return
        self.canvas.yview_scroll(int(-event.delta / 120), "units")
        self._render()
