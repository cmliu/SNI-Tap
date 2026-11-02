"""SNI 嗅探日志区：只读富文本、自动滚底、上限 5000 行、主题可重染。

Tk 的 ``Text`` 没有 HTML 富文本，改用 tag 实现「时间戳弱化、域名青色」；
批量追加时先一次性 insert 整块文本，再用两条 ``tag_add`` 批量打范围，
避免逐行三次 Tcl 调用把 100ms 的轮询窗口撑爆。
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from collections import deque
from typing import Sequence

from . import theme
from .widgets import SlimScrollbar, px

MAX_LINES = 5000

# 时间戳与域名之间的间隔（对齐原实现的 ``&nbsp;&nbsp;``）
_GAP = "  "


class LogPanel(tk.Frame):
    """SNI 嗅探日志面板。

    基于 ``tk.Text`` + 具名 tag 实现终端风富文本：时间戳 dim、域名 cyan、
    关闭换行、自动滚底；``deque(maxlen=MAX_LINES)`` 与文本同步裁剪，
    保证最多保留 MAX_LINES 行。切主题只需重配 tag 前景色，无需重建文本。
    """

    def __init__(
        self,
        master: tk.Misc,
        font: tkfont.Font,
        placeholder: str = "",
    ) -> None:
        """构建日志面板。

        Args:
            master: 父容器。
            font: 日志区等宽字体。
            placeholder: 文档为空时显示的占位提示（dim 色）。
        """
        super().__init__(master, bg=theme.current().pane, bd=0, highlightthickness=0)
        self._placeholder = placeholder
        self._placeholder_shown = False
        self._entries: deque[tuple[str, str]] = deque(maxlen=MAX_LINES)
        self._nlines = 0

        self.text = tk.Text(
            self,
            bg=theme.current().pane,
            fg=theme.current().text,
            font=font,
            bd=0,
            highlightthickness=0,
            wrap="none",
            padx=px(2),
            pady=px(2),
            cursor="arrow",
            insertwidth=0,
            width=1,
            height=1,
        )
        self.text.configure(state="disabled")
        self._configure_tags()

        self.vbar = SlimScrollbar(self, "vertical", self.text.yview, "pane")
        self.hbar = SlimScrollbar(self, "horizontal", self.text.xview, "pane")
        self.text.configure(yscrollcommand=self.vbar.set, xscrollcommand=self.hbar.set)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.text.grid(row=0, column=0, sticky="nsew")
        self.vbar.grid(row=0, column=1, sticky="ns")
        self.hbar.grid(row=1, column=0, sticky="ew")

        self._show_placeholder()

    # ------------------------------------------------------------------ 主题

    def _configure_tags(self) -> None:
        """按当前主题重配三套 tag 的前景色与控件配色。"""
        t = theme.current()
        self.text.tag_configure("ts", foreground=t.dim)
        self.text.tag_configure("dom", foreground=t.cyan)
        self.text.tag_configure("hint", foreground=t.dim)
        self.text.configure(
            bg=t.pane,
            fg=t.text,
            selectbackground=theme.mix(t.green, 0.30, t.pane),
            selectforeground=t.text,
        )

    def retheme(self) -> None:
        """主题切换后重染：只改 tag 与控件配色，保留全部日志内容。"""
        self.configure(bg=theme.current().pane)
        self._configure_tags()
        self.vbar.retheme()
        self.hbar.retheme()

    # ------------------------------------------------------------------ 数据

    def append_lines(self, lines: list[str]) -> None:
        """批量追加日志行，每行格式 ``"HH:MM:SS domain"``，并滚到底部。

        整块 insert 一次，随后用两条 ``tag_add`` 批量标注时间戳与域名区间，
        单批 400 行的耗时远低于逐行打 tag 的写法。

        Args:
            lines: 日志行列表；空列表直接返回。
        """
        if not lines:
            return
        self._hide_placeholder()

        parsed: list[tuple[str, str]] = []
        for line in lines:
            timestamp, separator, domain = line.partition(" ")
            if not separator:
                timestamp, domain = "", line
            parsed.append((timestamp, domain))
            self._entries.append((timestamp, domain))

        base = self._nlines
        block = "\n".join(
            (f"{timestamp}{_GAP}{domain}" if timestamp else domain)
            for timestamp, domain in parsed
        ) + "\n"

        self.text.configure(state="normal")
        self.text.insert("end", block)

        ts_ranges: list[str] = []
        dom_ranges: list[str] = []
        for offset, (timestamp, _domain) in enumerate(parsed):
            line_no = base + offset + 1
            start = 0
            if timestamp:
                ts_ranges.extend((f"{line_no}.0", f"{line_no}.{len(timestamp)}"))
                start = len(timestamp) + len(_GAP)
            dom_ranges.extend((f"{line_no}.{start}", f"{line_no}.end"))
        if ts_ranges:
            self.text.tag_add("ts", *ts_ranges)
        if dom_ranges:
            self.text.tag_add("dom", *dom_ranges)

        self._nlines += len(parsed)
        self._trim()
        self.text.configure(state="disabled")
        self.text.see("end")

    def clear(self) -> None:
        """清空日志；文档变空后回显占位提示（对齐 QPlainTextEdit 语义）。"""
        self._entries.clear()
        self._nlines = 0
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self._placeholder_shown = False
        if self._placeholder:
            self.text.insert("end", self._placeholder, ("hint",))
            self._placeholder_shown = True
        self.text.configure(state="disabled")

    @property
    def line_count(self) -> int:
        """当前日志行数（不含占位提示）。"""
        return self._nlines

    def entries(self) -> Sequence[tuple[str, str]]:
        """返回当前条目快照 ``(时间戳, 域名)``。"""
        return tuple(self._entries)

    # -------------------------------------------------------------- 内部实现

    def _trim(self) -> None:
        """裁剪超出 MAX_LINES 的头部行。"""
        excess = self._nlines - MAX_LINES
        if excess <= 0:
            return
        self.text.delete("1.0", f"{excess + 1}.0")
        self._nlines = MAX_LINES

    def _show_placeholder(self) -> None:
        """在空文档上显示 dim 占位提示。"""
        if not self._placeholder or self._placeholder_shown:
            return
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", self._placeholder, ("hint",))
        self.text.configure(state="disabled")
        self._placeholder_shown = True

    def _hide_placeholder(self) -> None:
        """移除占位提示，为真实日志腾空文档。"""
        if not self._placeholder_shown:
            return
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self._placeholder_shown = False
