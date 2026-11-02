"""GUI 主题令牌：暗色（夜间终端）与亮色（日间终端）两套配色，跟随系统。

Theme 为不可变令牌集；模块级 ``current()`` 提供当前生效主题，
``set_scheme()`` 由 MainWindow 在初始化与系统配色变化时调用。
无法识别配色（Unknown）时默认暗色，保持终端工具本色。
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt


@dataclass(frozen=True)
class Theme:
    """一套完整的终端风配色令牌（hex 值，供 QSS 与富文本内联样式使用）。"""

    name: str
    bg: str  # 窗口底色
    pane: str  # 面板 / 输入框底色
    border: str  # 边框
    text: str  # 正文
    muted: str  # 弱化文字
    dim: str  # 更弱文字（时间戳 / 分隔符）
    green: str  # 强调绿：运行 / 次数 / 条形 / 焦点
    cyan: str  # 青：域名 / 对端地址
    red: str  # 红：停止 / 错误
    amber: str  # 黄：过渡态
    hover: str  # 行悬停底色

    def rgba(self, color: str, alpha: float) -> str:
        """把 ``#rrggbb`` 转成带透明度的 ``rgba(r, g, b, a)`` QSS 片段。"""
        c = color.lstrip("#")
        r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        return f"rgba({r}, {g}, {b}, {alpha})"


DARK = Theme(
    name="dark",
    bg="#0a0e12",
    pane="#0f141a",
    border="#1f2a33",
    text="#d6e2ea",
    muted="#5c6b78",
    dim="#3a4750",
    green="#3ddc97",
    cyan="#7ad4ff",
    red="#ff6b6b",
    amber="#e6b455",
    hover="#131b23",
)

LIGHT = Theme(
    name="light",
    bg="#eef1f4",
    pane="#ffffff",
    border="#d3dae1",
    text="#1a232c",
    muted="#5d6a76",
    dim="#93a0ab",
    green="#0c8f63",
    cyan="#0b6ec9",
    red="#cf3a3a",
    amber="#9a6a08",
    hover="#f0f4f8",
)

_scheme: Qt.ColorScheme = Qt.ColorScheme.Unknown
_current: Theme = DARK


def set_scheme(scheme: Qt.ColorScheme) -> None:
    """按系统配色切换当前主题；Unknown 保持暗色。"""
    global _scheme, _current
    _scheme = scheme
    if scheme == Qt.ColorScheme.Light:
        _current = LIGHT
    else:
        _current = DARK


def current() -> Theme:
    """返回当前生效主题。"""
    return _current
