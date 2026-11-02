"""GUI 主题令牌：暗色（夜间终端）与亮色（日间终端）两套配色，跟随系统。

``Theme`` 为不可变令牌集；模块级 :func:`current` 提供当前生效主题，
:func:`set_scheme` 由 MainWindow 在初始化与系统配色变化时调用。
无法识别配色（读注册表失败）时默认暗色，保持终端工具本色。

Tk 没有 alpha 通道，QSS 里的 ``rgba(color, a)`` 必须用 :func:`mix`
预先混成实色后才能交给控件。
"""

from __future__ import annotations

import sys
import tkinter
import tkinter.font as tkfont
from dataclasses import dataclass
from typing import Sequence

# Windows 个性化设置：应用亮暗模式（REG_DWORD，1 = 亮色）
_PERSONALIZE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
_LIGHT_VALUE = "AppsUseLightTheme"


@dataclass(frozen=True)
class Theme:
    """一套完整的终端风配色令牌（hex 值，供 Tk 控件与 Canvas 自绘使用）。"""

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


def _to_rgb(color: str) -> tuple[int, int, int]:
    """``#rrggbb`` → ``(r, g, b)``。"""
    value = color.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def mix(color: str, alpha: float, base: str) -> str:
    """把 ``color`` 以 ``alpha`` 不透明度叠到 ``base`` 上，返回实色 ``#rrggbb``。

    Tk 控件不支持透明度，凡是 QSS 里写成 ``rgba(color, a)`` 的地方都在这里
    预先混成不透明色。

    Args:
        color: 叠加色，``#rrggbb``。
        alpha: 叠加色占比，0.0-1.0（超出范围会被夹取）。
        base: 底色，``#rrggbb``。

    Returns:
        混合后的不透明颜色，形如 ``#0d1a16``。
    """
    ratio = max(0.0, min(1.0, alpha))
    fr, fg, fb = _to_rgb(color)
    br, bg, bb = _to_rgb(base)
    channels = (
        max(0, min(255, int(round(fr * ratio + br * (1.0 - ratio))))),
        max(0, min(255, int(round(fg * ratio + bg * (1.0 - ratio))))),
        max(0, min(255, int(round(fb * ratio + bb * (1.0 - ratio))))),
    )
    return "#{:02x}{:02x}{:02x}".format(*channels)


def detect_system_light() -> bool:
    """读取系统「应用」亮暗模式。

    读的是 ``HKCU\\...\\Themes\\Personalize`` 下的 ``AppsUseLightTheme``
    （1 = 亮色）。非 Windows、键缺失或读取失败一律返回 ``False``
    （即暗色），保持终端工具本色。

    Returns:
        True 表示系统当前为亮色模式。
    """
    if sys.platform != "win32":
        return False
    try:
        import winreg
    except ImportError:  # pragma: no cover - 非 Windows 不会走到
        return False
    key = None
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PERSONALIZE_KEY)
        value, _kind = winreg.QueryValueEx(key, _LIGHT_VALUE)
        return int(value) == 1
    except (OSError, ValueError, TypeError):
        return False
    finally:
        if key is not None:
            try:
                winreg.CloseKey(key)
            except OSError:  # pragma: no cover - 关闭失败无从处理
                pass


def font_family(candidates: Sequence[str]) -> str:
    """从候选字族里挑第一个系统真实存在的，全部缺失时返回首选项。

    Tk 不支持像 Qt 那样把字族列表交给引擎做逐字形回退，只能先探测再单选；
    选中等宽字族后，中文字形仍由 Windows 字体链接机制回退到雅黑。

    Args:
        candidates: 按优先级排列的字族名。

    Returns:
        可用的字族名；``candidates`` 为空时返回 ``"TkDefaultFont"``。

    Note:
        ``tkinter.font.families()`` 需要已存在 root 窗口，因此本函数必须在
        ``tk.Tk()`` 之后调用；调用过早会安全退化为 ``candidates[0]``。
    """
    if not candidates:
        return "TkDefaultFont"
    try:
        available = {name.lower() for name in tkfont.families()}
    except (tkinter.TclError, RuntimeError):
        available = set()
    for family in candidates:
        if family.lower() in available:
            return family
    return candidates[0]


_scheme_light: bool = False
_current: Theme = DARK


def set_scheme(light: bool) -> None:
    """按系统亮暗切换当前主题。"""
    global _scheme_light, _current
    _scheme_light = bool(light)
    _current = LIGHT if _scheme_light else DARK


def is_light() -> bool:
    """当前是否处于亮色模式。"""
    return _scheme_light


def current() -> Theme:
    """返回当前生效主题。"""
    return _current
