"""协议栈嗅探日志区：只读富文本、自动滚底、上限 5000 行、主题可重染。

每行固定五段：``时间戳  域名  应用层  传输层  安全层``（两空格分隔），
顺序固定为 应用层 → 传输层 → 安全层；安全层后可选 ``ECH`` 标记（两空格
分隔，琥珀色，表示确证客户端发起了真 ECH——外层扩展存在 ∧ 外层 SNI 是
ECH 掩护域名，GREASE ECH 不标记），provisional 行尾加 ``?``，
因此行尾顺序是 安全层 → ECH → ``?``。

Tk 的 ``Text`` 没有 HTML 富文本，改用 tag 实现「时间戳弱化、域名青色」；
批量追加时先一次性 insert 整块文本，再用**五条** ``tag_add`` 批量打范围
（``dim`` 合并时间戳与传输层两个区间），禁止逐行打 tag——单批 400 行的
耗时远低于逐行六次 Tcl 调用的写法。
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from collections import deque
from dataclasses import dataclass
from typing import Sequence

from . import theme
from .widgets import SlimScrollbar, px

MAX_LINES = 5000

# 行内分隔符：两个空格（与 protocol.LOG_SEP 一致，GUI 层不 import 协议模块）
_LOG_SEP = "  "

# ECH 标记文案（与 protocol.ECH_MARK 一致，GUI 层不 import 协议模块）
_ECH_MARK = "ECH"


@dataclass(frozen=True)
class LogEntry:
    """一行日志的五字段快照（FIX-4：定义在 GUI 层，不依赖 protocol.ProtocolStack）。"""

    ts: str
    domain: str
    app: str
    transport: str
    security: str
    provisional: bool = False
    ech: bool = False  # 确证生效的 ECH（= 扩展存在 ∧ SNI 是掩护域名，由上层判定）


class LogPanel(tk.Frame):
    """协议栈嗅探日志面板。

    基于 ``tk.Text`` + 具名 tag 实现终端风富文本：时间戳/传输层 dim、
    域名 cyan、应用层 muted、安全层 green、ECH 标记 amber、关闭换行、自动滚底；
    ``deque(maxlen=MAX_LINES)`` 与文本同步裁剪，保证最多保留 MAX_LINES 行。
    切主题只需重配 tag 前景色，无需重建文本。
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
        self._entries: deque[LogEntry] = deque(maxlen=MAX_LINES)
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
        """按当前主题重配六套 tag 的前景色与控件配色。"""
        t = theme.current()
        self.text.tag_configure("dim", foreground=t.dim)        # 时间戳 + 传输层
        self.text.tag_configure("dom", foreground=t.cyan)       # 域名
        self.text.tag_configure("app", foreground=t.muted)      # 应用层
        self.text.tag_configure("security", foreground=t.green)  # 安全层
        self.text.tag_configure("ech", foreground=t.amber)      # ECH 标记
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

    def append_lines(self, entries: Sequence[LogEntry]) -> None:
        """批量追加日志行并滚到底部。

        整块 insert 一次，随后用五条 ``tag_add`` 批量标注
        （dim / dom / app / security / ech，dim 同时覆盖时间戳与传输层两个区间），
        单批 400 行的耗时远低于逐行打 tag 的写法。**不做列对齐填充**。

        Args:
            entries: 日志条目列表；空列表直接返回。
        """
        if not entries:
            return
        self._hide_placeholder()

        base = self._nlines
        # (行文本, [(tag, start_col, end_col), ...])
        rendered: list[tuple[str, list[tuple[str, int, int]]]] = []

        for entry in entries:
            mark = "?" if entry.provisional else ""
            line = (
                f"{entry.ts}{_LOG_SEP}{entry.domain}{_LOG_SEP}{entry.app}"
                f"{_LOG_SEP}{entry.transport}{_LOG_SEP}{entry.security}"
            )
            ranges: list[tuple[str, int, int]] = []
            pos = 0
            for tag, text in (
                ("dim", entry.ts),
                ("dom", entry.domain),
                ("app", entry.app),
                ("dim", entry.transport),
                ("security", entry.security),
            ):
                start = pos
                pos += len(text)
                ranges.append((tag, start, pos))
                pos += len(_LOG_SEP)
            if entry.ech:
                # 安全层后接两个空格 + ECH；tag 只覆盖 ECH 三字符。
                line += f"{_LOG_SEP}{_ECH_MARK}"
                start = pos
                pos += len(_ECH_MARK)
                ranges.append(("ech", start, pos))
            line += mark
            rendered.append((line, ranges))
            self._entries.append(entry)

        block = "\n".join(line for line, _ in rendered) + "\n"

        self.text.configure(state="normal")
        self.text.insert("end", block)

        # 五条批量 tag_add：每条传平铺的 [start, end, start, end, …]
        tag_ranges: dict[str, list[str]] = {
            "dim": [], "dom": [], "app": [], "security": [], "ech": [],
        }
        for offset, (_line, ranges) in enumerate(rendered):
            line_no = base + offset + 1
            for tag, start, end in ranges:
                tag_ranges[tag].extend((f"{line_no}.{start}", f"{line_no}.{end}"))
        for tag in ("dim", "dom", "app", "security", "ech"):
            if tag_ranges[tag]:
                self.text.tag_add(tag, *tag_ranges[tag])

        self._nlines += len(rendered)
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

    def entries(self) -> Sequence[LogEntry]:
        """返回当前条目快照。"""
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
