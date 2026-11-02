"""共用 Tk 基础件：DPI 缩放、极细滚动条、面板 / 输入框工厂。

``theme.py`` 只管配色令牌，``log_panel`` / ``stats_table`` / ``main_window``
都会用到这里的滚动条与像素缩放，因此单独抽一层，避免环形 import。
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from . import theme

# 逻辑像素 → 物理像素的缩放系数，由 main_window 在开启 DPI 感知后注入
_SCALE: float = 1.0

# 滚动条宽度（逻辑像素）
SCROLLBAR_W = 8


def set_scale(scale: float) -> None:
    """注入当前 DPI 缩放系数（1.0 = 96 DPI）。"""
    global _SCALE
    _SCALE = max(1.0, min(3.0, float(scale)))


def get_scale() -> float:
    """返回当前 DPI 缩放系数。"""
    return _SCALE


def px(value: int) -> int:
    """逻辑像素 → 物理像素（正数至少为 1，0 保持 0）。"""
    if value == 0:
        return 0
    return max(1, int(round(value * _SCALE)))


class SlimScrollbar(tk.Canvas):
    """8px 极细滚动条：无箭头、无轨道，只有一枚滑块。

    Tk 原生 ``Scrollbar`` 与 ``ttk.Scrollbar`` 在 Windows 上都是带箭头的
    粗控件，与暗色终端风格格不入，因此用 Canvas 自绘。
    """

    def __init__(
        self,
        master: tk.Misc,
        orient: str,
        command: Callable[..., object],
        surface: str = "pane",
    ) -> None:
        """构建滚动条。

        Args:
            master: 父容器。
            orient: ``"vertical"`` 或 ``"horizontal"``。
            command: 滚动回调，通常是 ``text.yview`` / ``canvas.yview``。
            surface: 底色令牌名（``"pane"`` / ``"bg"``），随主题重染。
        """
        self._orient = orient
        self._command = command
        self._surface = surface
        self._first = 0.0
        self._last = 1.0
        self._drag_offset = 0.0
        self._hover = False

        if orient == "vertical":
            width, height = px(SCROLLBAR_W), 1
        else:
            width, height = 1, px(SCROLLBAR_W)
        super().__init__(
            master,
            width=width,
            height=height,
            bg=getattr(theme.current(), surface),
            bd=0,
            highlightthickness=0,
            takefocus=0,
        )
        self._thumb = self.create_rectangle(0, 0, 0, 0, fill=theme.current().border, outline="")
        self.bind("<Configure>", self._on_configure)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)

    # ------------------------------------------------------------------ 协议

    def set(self, first: object, last: object) -> None:
        """Tk 滚动协议入口：接收可视区比例并重绘。"""
        try:
            self._first = float(first)  # type: ignore[arg-type]
            self._last = float(last)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return
        self._redraw()

    def retheme(self) -> None:
        """主题切换后重染底色与滑块。"""
        self.configure(bg=getattr(theme.current(), self._surface))
        self._redraw()

    # -------------------------------------------------------------- 内部实现

    def _length(self) -> int:
        """滚动条轴线长度（像素）。"""
        size = self.winfo_height() if self._orient == "vertical" else self.winfo_width()
        return max(1, int(size))

    def _thumb_span(self, length: int) -> tuple[float, float]:
        """滑块在轴线上的起止像素位置。"""
        span = max(0.0, self._last - self._first)
        start = self._first * length
        size = max(span * length, float(px(24)))
        if start + size > length:
            start = max(0.0, length - size)
        return start, start + size

    def _redraw(self) -> None:
        """按当前可视比例绘制滑块；内容未溢出时隐藏。"""
        t = theme.current()
        length = self._length()
        if self._last - self._first >= 0.999:
            self.itemconfigure(self._thumb, state="hidden")
            return
        self.itemconfigure(self._thumb, state="normal")
        start, end = self._thumb_span(length)
        if self._orient == "vertical":
            width = max(1, self.winfo_width())
            self.coords(self._thumb, 0, start, width, end)
        else:
            height = max(1, self.winfo_height())
            self.coords(self._thumb, start, 0, end, height)
        self.itemconfigure(self._thumb, fill=t.dim if self._hover else t.border)

    def _moveto(self, fraction: float) -> None:
        """把视口移动到指定比例位置。"""
        clamped = max(0.0, min(1.0, fraction))
        self._command("moveto", f"{clamped:.4f}")

    # ------------------------------------------------------------------ 事件

    def _on_configure(self, _event: tk.Event) -> None:
        self._redraw()

    def _on_enter(self, _event: tk.Event) -> None:
        self._hover = True
        self._redraw()

    def _on_leave(self, _event: tk.Event) -> None:
        self._hover = False
        self._redraw()

    def _on_press(self, event: tk.Event) -> None:
        length = self._length()
        position = event.y if self._orient == "vertical" else event.x
        start, end = self._thumb_span(length)
        if start <= position <= end:
            self._drag_offset = position - start
        else:  # 点击空白处：滑块中心跳到点击位置
            self._drag_offset = (end - start) / 2.0
            self._moveto((position - self._drag_offset) / length)

    def _on_drag(self, event: tk.Event) -> None:
        length = self._length()
        position = event.y if self._orient == "vertical" else event.x
        self._moveto((position - self._drag_offset) / length)


def make_pane(master: tk.Misc) -> tk.Frame:
    """1px border 描边 + pane 底色的面板容器。"""
    t = theme.current()
    return tk.Frame(
        master,
        bg=t.pane,
        bd=0,
        highlightthickness=px(1),
        highlightbackground=t.border,
        highlightcolor=t.border,
    )


def make_field(master: tk.Misc, width: Optional[int] = None) -> tk.Frame:
    """输入框外壳：1px border 描边 + 内边距（Tk Entry 自身不支持 padding）。

    注意：一旦关闭包管理器传播，Frame 未显式指定的那一维会塌成 1px，
    因此固定宽度时必须配合 :func:`fit_field_height` 显式补上高度。

    Args:
        master: 父容器。
        width: 固定宽度（逻辑像素）；``None`` 表示随布局自适应。
    """
    t = theme.current()
    field = tk.Frame(
        master,
        bg=t.pane,
        bd=0,
        highlightthickness=px(1),
        highlightbackground=t.border,
        highlightcolor=t.green,
    )
    if width is not None:
        field.configure(width=px(width))
        field.pack_propagate(False)
    return field


def fit_field_height(field: tk.Frame, entry: tk.Entry, pad_y: int) -> None:
    """按输入框内容实测高度补齐外壳高度（仅对已关闭传播的定宽输入框生效）。"""
    entry.update_idletasks()
    height = entry.winfo_reqheight() + 2 * px(pad_y) + 2 * px(1)
    field.configure(height=height)
