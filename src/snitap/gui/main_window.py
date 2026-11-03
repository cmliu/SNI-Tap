"""主窗口：终端风布局 + 双主题（跟随系统亮暗）+ 命令配置行 + 左右分栏。

窗口只做展示：所有网络逻辑在 ``Worker`` 线程，GUI 通过 100ms 轮询
``worker.events`` 队列消费事件，绝不跨线程直接操作控件。
"""

from __future__ import annotations

import ctypes
import os
import queue
import sys
import tkinter as tk
import tkinter.font as tkfont
from typing import Callable, Optional, Union

from ..config import (
    DEFAULT_LISTEN_PORT,
    DEFAULT_TARGET_HOST,
    DEFAULT_TARGET_PORT,
    AppConfig,
)
from ..events import NoticeEvent, StackEvent, StateEvent, StatsEvent, TcpingEvent
from ..stats import Stats
from ..worker import Worker
from . import theme, widgets
from .log_panel import LogEntry, LogPanel
from .stats_table import StatsTable
from .widgets import px

_DRAIN_BATCH = 400
_NOTICE_MS = 5000
_THEME_POLL_MS = 2000

# 等宽字体族优先，中文自动回退微软雅黑
_FONT_CANDIDATES: tuple[str, ...] = (
    "Cascadia Mono",
    "JetBrains Mono",
    "Consolas",
    "Microsoft YaHei UI",
    "Microsoft YaHei",
)

# Windows DWM 属性：标题栏颜色（Win11）/ 深色标题栏（Win10 兜底）
_DWMWA_CAPTION_COLOR = 35
_DWMWA_USE_IMMERSIVE_DARK_MODE = 20

# 布局令牌（逻辑像素，运行时按 DPI 缩放）
WINDOW_W = 760
WINDOW_H = 560
MARGIN_L, MARGIN_T, MARGIN_R, MARGIN_B = 14, 12, 14, 10
ROW_GAP = 8
PANEL_MIN_W = 280
LISTEN_EDIT_W = 80
TOGGLE_MIN_W = 112

TARGET_PLACEHOLDER = "host 或 host:port（端口省略默认 443）"
LOG_PLACEHOLDER = "等待嗅探到 TLS 握手…"

# 主题令牌名 或 由主题算出实色的函数
_PaintValue = Union[str, Callable[[theme.Theme], str]]


def parse_target(text: str, default_port: int = DEFAULT_TARGET_PORT) -> Optional[tuple[str, int]]:
    """解析合一的转发目标输入（host 或 host:port）。

    规则：
    - 空输入返回 ``None``；
    - 含 ``]:``（IPv6 带方括号）按 ``]`` 后端口解析，仅 ``[::1]`` 时
      host 为 ``::1``、端口取 ``default_port``；
    - 只有一个 ``:`` 且冒号后为 1-5 位纯数字时按 ``host:port`` 解析；
      其余情况（含纯 IPv6 如 ``2001:db8::1``）整体视为 host；
    - 端口非数字或不在 1-65535 时返回 ``None``。

    Args:
        text: 用户输入，如 ``cf.090227.xyz``、``cf.090227.xyz:8443``、
            ``[2001:db8::1]:443``。
        default_port: 端口省略时使用的缺省端口。

    Returns:
        ``(host, port)`` 元组；输入无法解析时返回 ``None``。
    """
    host = text.strip()
    if not host:
        return None

    # IPv6 带方括号形式：[::1] 或 [::1]:8443
    if "]:" in host or (host.startswith("[") and host.endswith("]")):
        end = host.find("]")
        if end == -1 or not host.startswith("["):
            return None
        inner = host[1:end]
        rest = host[end + 1:]
        if not inner:
            return None
        port = default_port
        if rest:
            if not rest.startswith(":"):
                return None
            port_text = rest[1:]
            if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
                return None
            port = int(port_text)
        return inner, port

    # 单个冒号且冒号后为 1-5 位纯数字 → host:port
    if host.count(":") == 1:
        head, _, tail = host.partition(":")
        if not head:
            return None
        if tail.isdigit() and 1 <= len(tail) <= 5:
            if not 1 <= int(tail) <= 65535:
                return None
            return head, int(tail)

    # 其余（纯域名 / 纯 IPv6）整体视为 host
    return host, default_port


def _resource_path(name: str) -> str:
    """定位资源文件：PyInstaller 单文件运行时从解包目录，源码模式取项目根。"""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, "assets", name)
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    return os.path.join(root, "assets", name)


def enable_dpi_awareness() -> int:
    """开启 Windows DPI 感知并返回系统 DPI（非 Windows / 失败时返回 96）。

    必须在 ``tk.Tk()`` 之前调用，否则 Tk 会按未感知的 96 DPI 布局；
    同时把缩放系数注入 :mod:`widgets`，供全局 :func:`px` 使用。
    """
    dpi = 96
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
        except Exception:  # noqa: BLE001 - 无 shcore 的旧系统
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:  # noqa: BLE001 - 无 DPI 能力时静默降级
                pass
        try:
            dpi = int(ctypes.windll.user32.GetDpiForSystem())
        except Exception:  # noqa: BLE001 - Win10 1607 之前无此 API
            try:
                hdc = ctypes.windll.user32.GetDC(0)
                dpi = int(ctypes.windll.gdi32.GetDeviceCaps(hdc, 88))  # LOGPIXELSY
                ctypes.windll.user32.ReleaseDC(0, hdc)
            except Exception:  # noqa: BLE001
                dpi = 96
    if dpi <= 0:
        dpi = 96
    widgets.set_scale(dpi / 96.0)
    return dpi


def create_root() -> tk.Tk:
    """创建 Tk 根窗口：先开 DPI 感知，再按 DPI 校正 tk scaling。"""
    dpi = enable_dpi_awareness()
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", dpi / 72.0)
    except tk.TclError:  # pragma: no cover - 极旧 Tk 无 scaling
        pass
    return root


class Fonts:
    """一套按 DPI 缩放的字体对象（UI 用像素尺寸，日志用磅尺寸，与原 QSS 对齐）。"""

    def __init__(self, master: tk.Misc) -> None:
        mono = theme.font_family(_FONT_CANDIDATES)
        log_mono = theme.font_family(("Consolas", "Cascadia Mono", "Courier New"))
        self.mono_family = mono
        self.log_family = log_mono
        self.ui = tkfont.Font(master, family=mono, size=-px(12))
        self.ui_bold = tkfont.Font(master, family=mono, size=-px(12), weight="bold")
        self.small = tkfont.Font(master, family=mono, size=-px(11))
        self.small_bold = tkfont.Font(master, family=mono, size=-px(11), weight="bold")
        self.lamp = tkfont.Font(master, family=mono, size=-px(13))
        # 日志区对齐 QFont("Consolas", pointSize=10)：正数即磅值，随 tk scaling 缩放
        self.log = tkfont.Font(master, family=log_mono, size=10)


class MainWindow:
    """单窗口应用；所有网络逻辑在 Worker 线程，窗口只消费事件。"""

    def __init__(self, root: tk.Tk) -> None:
        """构建主窗口。

        Args:
            root: 由 :func:`create_root` 创建的 Tk 根窗口。
        """
        self.root = root
        self._worker = Worker()
        self._state = "idle"  # idle | starting | running | stopping
        self._last_rows: tuple = ()
        self._last_tcping: Optional[TcpingEvent] = None
        self._last_stats: Optional[StatsEvent] = None
        self._net = (0, 0, 0)
        self._notice_seq = 0
        self._notice_job: Optional[str] = None
        self._notice_error = False
        self._alive = True
        self._placeholder_active = False

        # 主题重刷登记表：(控件, {选项: 令牌名或取色函数})
        self._paint_registry: list[tuple[tk.Misc, dict[str, _PaintValue]]] = []

        theme.set_scheme(theme.detect_system_light())
        self.fonts = Fonts(root)

        self._configure_window()
        self._build_layout()
        self._bind_shortcuts()
        self._apply_state("idle")
        self._apply_theme()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._timer_job: Optional[str] = self.root.after(100, self._tick)
        self._theme_job: Optional[str] = self.root.after(_THEME_POLL_MS, self._poll_theme)

    # ------------------------------------------------------------ 主题登记

    def _paint(self, widget: tk.Misc, **spec: _PaintValue) -> None:
        """设置控件配色并登记，后续切主题时整窗重刷。"""
        self._paint_registry.append((widget, spec))
        self._apply_paint(widget, spec)

    @staticmethod
    def _apply_paint(widget: tk.Misc, spec: dict[str, _PaintValue]) -> None:
        """按当前主题解析并应用一组配色选项。"""
        t = theme.current()
        resolved = {
            key: (value(t) if callable(value) else getattr(t, value))
            for key, value in spec.items()
        }
        widget.configure(**resolved)

    def _apply_theme(self) -> None:
        """整窗重染：登记表 + 自绘组件 + 依赖状态的内联色。"""
        for widget, spec in self._paint_registry:
            self._apply_paint(widget, spec)
        self.log_panel.retheme()
        self.stats_table.retheme()
        self._apply_state(self._state)
        if self._last_tcping is not None:
            self._apply_tcping(self._last_tcping)
        if self.lbl_notice.cget("text"):
            t = theme.current()
            self.lbl_notice.configure(fg=t.red if self._notice_error else t.muted)
        self._render_net()
        self._apply_caption_color()

    def _poll_theme(self) -> None:
        """每 2 秒轮询系统亮暗（等价于 Qt 的 colorSchemeChanged）。"""
        if not self._alive:
            return
        light = theme.detect_system_light()
        if light != theme.is_light():
            theme.set_scheme(light)
            self._apply_theme()
        self._theme_job = self.root.after(_THEME_POLL_MS, self._poll_theme)

    # ---------------------------------------------------------------- 窗口

    def _configure_window(self) -> None:
        """标题、尺寸、图标、标题栏上色与禁用最大化。"""
        self.root.title("SNI域名探测器")
        self._paint(self.root, bg="bg")  # 根窗口底色也要随主题重刷
        self.root.geometry(f"{px(WINDOW_W)}x{px(WINDOW_H)}")
        self.root.minsize(px(640), px(420))
        self.root.resizable(True, True)

        icon = _resource_path("app.ico")
        if os.path.exists(icon):
            try:
                self.root.iconbitmap(default=icon)
            except tk.TclError:  # 图标格式异常时静默跳过
                pass

        self.root.bind("<Map>", self._on_map, add="+")

    def _on_map(self, _event: tk.Event) -> None:
        """窗口首次映射后施加 DWM 标题栏颜色并禁用最大化。"""
        self.root.unbind("<Map>")
        self.root.update_idletasks()
        self._apply_caption_color()
        self._disable_maximize()

    def _top_hwnd(self) -> int:
        """取顶层窗口 HWND：优先 GetParent(winfo_id())，取不到退回 winfo_id()。"""
        inner = int(self.root.winfo_id())
        parent = int(ctypes.windll.user32.GetParent(inner))
        return parent if parent else inner

    def _apply_caption_color(self) -> None:
        """让 Windows 标题栏颜色与主题底色一致（Win11 上色 / Win10 深色兜底）。"""
        if sys.platform != "win32":
            return
        try:
            hwnd = self._top_hwnd()
            c = theme.current().bg.lstrip("#")
            red, green, blue = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
            colorref = ctypes.c_uint(red | (green << 8) | (blue << 16))
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, _DWMWA_CAPTION_COLOR, ctypes.byref(colorref), 4
            )
            if result != 0:  # Win10 不支持 CAPTION_COLOR，退回深/浅标题栏
                dark = ctypes.c_int(0 if theme.is_light() else 1)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, _DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(dark), 4
                )
        except Exception:  # noqa: BLE001 - 标题栏装饰失败不应影响功能
            pass

    def _disable_maximize(self) -> None:
        """保留原生标题栏，仅去掉最大化和系统菜单里的「最大化」项。"""
        if sys.platform != "win32":
            return
        try:
            hwnd = self._top_hwnd()
            user32 = ctypes.windll.user32
            user32.GetWindowLongW.restype = ctypes.c_int32
            style = user32.GetWindowLongW(hwnd, -16)  # GWL_STYLE
            user32.SetWindowLongW(hwnd, -16, style & ~0x00010000)  # ~WS_MAXIMIZEBOX
            menu = user32.GetSystemMenu(hwnd, False)
            if menu:
                user32.DeleteMenu(menu, 0xF030, 0x00000000)  # SC_MAXIMIZE
            user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0020 | 0x0001 | 0x0002 | 0x0004)
        except Exception:  # noqa: BLE001
            pass

    # ---------------------------------------------------------------- 布局

    def _label(
        self,
        master: tk.Misc,
        text: str,
        font: tkfont.Font,
        fg: _PaintValue,
        bg: _PaintValue,
        **kwargs: object,
    ) -> tk.Label:
        """创建统一风格的 Label（去边框、去高亮环）并登记配色。"""
        label = tk.Label(
            master, text=text, font=font, bd=0, highlightthickness=0, **kwargs  # type: ignore[arg-type]
        )
        self._paint(label, fg=fg, bg=bg)
        return label

    def _build_layout(self) -> None:
        """四行布局：配置行 / 状态行 / 主区 / 状态栏。"""
        self.body = tk.Frame(self.root)
        self._paint(self.body, bg="bg")
        self.body.pack(
            fill="both",
            expand=True,
            padx=(px(MARGIN_L), px(MARGIN_R)),
            pady=(px(MARGIN_T), px(MARGIN_B)),
        )

        self.config_row = self._build_config_row(self.body)
        self.config_row.pack(fill="x", pady=(0, px(ROW_GAP)))

        self.status_row = self._build_status_row(self.body)
        self.status_row.pack(fill="x", pady=(0, px(ROW_GAP)))

        self.main_area = self._build_main_area(self.body)
        self.main_area.pack(fill="both", expand=True, pady=(0, px(ROW_GAP)))

        self.status_bar = self._build_status_bar(self.body)
        self.status_bar.pack(fill="x")

    def _build_config_row(self, master: tk.Misc) -> tk.Frame:
        """行1：listen 端口 → 目标 host / 清除 → 启停按钮。"""
        row = tk.Frame(master)
        self._paint(row, bg="bg")

        self.lbl_listen = self._label(row, "listen", self.fonts.ui, "green", "bg")
        self.lbl_listen.pack(side="left", padx=(0, px(8)))

        # 端口输入框：固定 80px 宽
        self.listen_field = widgets.make_field(row, width=LISTEN_EDIT_W)
        self._paint(self.listen_field, bg="pane", highlightbackground="border")
        self.listen_field.pack(side="left")
        self.edit_listen = self._make_entry(self.listen_field)
        self.edit_listen.pack(fill="both", expand=True, padx=px(8), pady=px(5))
        widgets.fit_field_height(self.listen_field, self.edit_listen, 5)
        self.edit_listen.insert(0, str(DEFAULT_LISTEN_PORT))
        self._bind_field_focus(self.listen_field, self.edit_listen)

        self.lbl_arrow = self._label(row, "\u2192", self.fonts.ui, "dim", "bg")
        self.lbl_arrow.pack(side="left", padx=(px(8), px(8)))

        # 目标输入框：随窗口拉伸 + 右侧清除按钮
        self.target_field = widgets.make_field(row)
        self._paint(self.target_field, bg="pane", highlightbackground="border")
        self.target_field.pack(side="left", fill="x", expand=True)

        self.btn_clear_target = self._label(
            self.target_field, "\u2715", self.fonts.small, "muted", "pane",
            cursor="hand2", padx=px(6),
        )
        self.btn_clear_target.pack(side="right")
        self.btn_clear_target.bind("<Button-1>", self._on_clear_target)

        self.edit_target = self._make_entry(self.target_field)
        self.edit_target.pack(side="left", fill="both", expand=True, padx=(px(8), 0), pady=px(5))
        self.edit_target.insert(0, DEFAULT_TARGET_HOST)
        self._bind_field_focus(self.target_field, self.edit_target)
        self._bind_placeholder(self.edit_target)

        # 启停按钮：最小宽 112px
        self.toggle_holder = tk.Frame(row, width=px(TOGGLE_MIN_W), height=px(29))
        self._paint(self.toggle_holder, bg="bg")
        self.toggle_holder.pack(side="left", padx=(px(8), 0))
        self.toggle_holder.pack_propagate(False)

        self.btn_toggle = tk.Button(
            self.toggle_holder,
            text="\u25b6 转发监听",
            font=self.fonts.ui_bold,
            bd=0,
            highlightthickness=px(1),
            relief="flat",
            cursor="hand2",
            takefocus=0,
            command=self._on_toggle,
        )
        self.btn_toggle.pack(fill="both", expand=True)
        self.btn_toggle.bind("<Enter>", self._on_toggle_enter)
        self.btn_toggle.bind("<Leave>", self._on_toggle_leave)
        return row

    def _make_entry(self, master: tk.Misc) -> tk.Entry:
        """创建终端风输入框（去边框、去高亮环、随主题重染）。"""
        entry = tk.Entry(master, font=self.fonts.ui, bd=0, highlightthickness=0, width=1)
        self._paint(
            entry,
            bg="pane",
            fg="text",
            disabledbackground="pane",
            disabledforeground="dim",
            insertbackground="text",
            selectbackground=lambda t: theme.mix(t.green, 0.30, t.pane),
            selectforeground="text",
        )
        return entry

    def _bind_field_focus(self, field: tk.Frame, entry: tk.Entry) -> None:
        """输入框获得焦点时描边转绿（对齐 QLineEdit:focus）。"""
        entry.bind(
            "<FocusIn>",
            lambda _e: field.configure(highlightbackground=theme.current().green),
            add="+",
        )
        entry.bind(
            "<FocusOut>",
            lambda _e: field.configure(highlightbackground=theme.current().border),
            add="+",
        )

    def _bind_placeholder(self, entry: tk.Entry) -> None:
        """为目标输入框模拟 QLineEdit 的 placeholder（Tk Entry 无原生支持）。"""
        entry.bind("<FocusIn>", self._on_target_focus_in, add="+")
        entry.bind("<FocusOut>", self._on_target_focus_out, add="+")

    def _on_target_focus_in(self, _event: tk.Event) -> None:
        if not self._placeholder_active:
            return
        self._placeholder_active = False
        self.edit_target.delete(0, "end")
        self.edit_target.configure(fg=theme.current().text)

    def _on_target_focus_out(self, _event: tk.Event) -> None:
        if self._placeholder_active or self.edit_target.get().strip():
            return
        self._placeholder_active = True
        self.edit_target.delete(0, "end")
        self.edit_target.insert(0, TARGET_PLACEHOLDER)
        self.edit_target.configure(fg=theme.current().dim)

    def _target_value(self) -> str:
        """读取目标输入框的真实内容（占位提示不算内容）。"""
        return "" if self._placeholder_active else self.edit_target.get().strip()

    def _build_status_row(self, master: tk.Misc) -> tk.Frame:
        """行2：状态灯 + 状态文字 + ping + peer + 右侧 notice。"""
        row = tk.Frame(master)
        self._paint(row, bg="bg")

        self.lamp = self._label(row, "\u25cf", self.fonts.lamp, "red", "bg")
        self.lamp.pack(side="left")

        self.lbl_state = self._label(row, "已停止", self.fonts.ui_bold, "text", "bg")
        self.lbl_state.pack(side="left", padx=(px(8), 0))

        # ping：标签名 muted + 数值高亮，Tk Label 不能混色故拆两枚
        self.lbl_ping_key = self._label(row, "ping ", self.fonts.ui, "muted", "bg")
        self.lbl_ping_key.pack(side="left", padx=(px(18), 0))
        self.lbl_ping_value = self._label(row, "--", self.fonts.ui, "muted", "bg")
        self.lbl_ping_value.pack(side="left")

        self.lbl_sep = self._label(row, "\u2502", self.fonts.ui, "dim", "bg")
        self.lbl_sep.pack(side="left", padx=(px(8), 0))

        # peer：标签名 muted + 地址 cyan；为空时整段隐藏（对齐 Qt 单标签置空）
        self.lbl_peer_key = self._label(row, "", self.fonts.ui, "muted", "bg")
        self.lbl_peer_key.pack(side="left", padx=(px(8), 0))
        self.lbl_peer_value = self._label(row, "", self.fonts.ui, "cyan", "bg")
        self.lbl_peer_value.pack(side="left")

        self.lbl_notice = self._label(row, "", self.fonts.ui, "red", "bg")
        self.lbl_notice.pack(side="right")
        return row

    def _build_main_area(self, master: tk.Misc) -> tk.PanedWindow:
        """行3：左右 5:5 可拖动分栏，两栏最小宽 280。"""
        split = tk.PanedWindow(
            master,
            orient="horizontal",
            bg=theme.current().bg,
            sashwidth=px(ROW_GAP),
            sashrelief="flat",
            sashpad=0,
            bd=0,
            relief="flat",
            opaqueresize=True,
            showhandle=False,
        )
        self._paint(split, bg="bg")

        log_pane = self._build_log_pane(split)
        stats_pane = self._build_stats_pane(split)

        half = px((WINDOW_W - MARGIN_L - MARGIN_R - ROW_GAP) // 2)
        split.add(log_pane, minsize=px(PANEL_MIN_W), width=half, stretch="always")
        split.add(stats_pane, minsize=px(PANEL_MIN_W), width=half, stretch="always")

        self.log_pane = log_pane
        self.stats_pane = stats_pane
        return split

    def _build_log_pane(self, master: tk.Misc) -> tk.Frame:
        """左面板：面板头（标题 / 上限提示 / 清除）+ 分隔线 + 日志。"""
        pane = widgets.make_pane(master)
        self._paint(pane, bg="pane", highlightbackground="border")

        head = tk.Frame(pane)
        self._paint(head, bg="pane")
        head.pack(side="top", fill="x")
        inner = tk.Frame(head)
        self._paint(inner, bg="pane")
        inner.pack(fill="x", padx=px(10), pady=px(6))

        self.lbl_pane_title = self._label(
            inner, "\u2500\u2500 stack log \u2500\u2500", self.fonts.small, "green", "pane"
        )
        self.lbl_pane_title.pack(side="left")

        self.btn_clear = tk.Button(
            inner,
            text="[\u6e05\u9664]",
            font=self.fonts.small,
            bd=0,
            highlightthickness=px(1),
            relief="flat",
            cursor="hand2",
            padx=px(8),
            pady=px(1),
            takefocus=0,
            command=self._on_clear_log,
        )
        self._paint(
            self.btn_clear,
            bg="pane",
            fg="muted",
            activebackground="pane",
            activeforeground="text",
            highlightbackground="border",
            highlightcolor="border",
        )
        self.btn_clear.pack(side="right")
        self.btn_clear.bind("<Enter>", lambda _e: self.btn_clear.configure(fg=theme.current().text))
        self.btn_clear.bind("<Leave>", lambda _e: self.btn_clear.configure(fg=theme.current().muted))

        self.lbl_pane_hint = self._label(
            inner, "上限 5000 行", self.fonts.small, "dim", "pane"
        )
        self.lbl_pane_hint.pack(side="right", padx=(0, px(8)))

        separator = tk.Frame(pane, height=px(1))
        self._paint(separator, bg="border")
        separator.pack(side="top", fill="x")

        body = tk.Frame(pane)
        self._paint(body, bg="pane")
        body.pack(side="top", fill="both", expand=True, padx=px(6), pady=(px(4), px(6)))

        self.log_panel = LogPanel(body, self.fonts.log, placeholder=LOG_PLACEHOLDER)
        self.log_panel.pack(fill="both", expand=True)
        return pane

    def _build_stats_pane(self, master: tk.Misc) -> tk.Frame:
        """右面板：无面板头，直接三列表格 + footer（对齐原实现）。"""
        pane = widgets.make_pane(master)
        self._paint(pane, bg="pane", highlightbackground="border")
        body = tk.Frame(pane)
        self._paint(body, bg="pane")
        body.pack(fill="both", expand=True, padx=px(6), pady=(px(4), px(6)))

        self.stats_table = StatsTable(body, self.fonts.ui, self.fonts.small)
        self.stats_table.pack(side="top", fill="both", expand=True)

        self.lbl_total = self._label(body, "total 0", self.fonts.small, "dim", "pane", anchor="w")
        self.lbl_total.pack(side="bottom", fill="x", pady=(px(4), 0))
        return pane

    def _build_status_bar(self, master: tk.Misc) -> tk.Frame:
        """行4：tcp / udp / sni 计数 + 快捷键提示。"""
        row = tk.Frame(master)
        self._paint(row, bg="bg")

        def make(key: str, value_color: str) -> tk.Label:
            self._label(row, key, self.fonts.small, "muted", "bg").pack(side="left")
            value = self._label(row, " 0", self.fonts.small, value_color, "bg")
            value.pack(side="left")
            return value

        self.lbl_tcp = make("tcp", "text")
        self._label(row, " \u2502 ", self.fonts.small, "dim", "bg").pack(side="left")
        self.lbl_udp = make("udp", "text")
        self._label(row, " \u2502 ", self.fonts.small, "dim", "bg").pack(side="left")
        self.lbl_sni = make("sni", "green")

        self.lbl_shortcut = self._label(
            row, "Ctrl + L 清屏 \u00b7 Enter 启停", self.fonts.small, "dim", "bg"
        )
        self.lbl_shortcut.pack(side="right")
        return row

    # ---------------------------------------------------------------- 交互

    def _bind_shortcuts(self) -> None:
        """键盘流：Enter（含小键盘）启停，Ctrl + L 清日志。"""
        self.root.bind("<Return>", lambda _e: self._on_toggle())
        self.root.bind("<KP_Enter>", lambda _e: self._on_toggle())
        self.root.bind("<Control-l>", lambda _e: self._on_clear_log())
        self.root.bind("<Control-L>", lambda _e: self._on_clear_log())

    def _on_clear_target(self, _event: tk.Event) -> None:
        """目标输入框的 ✕：清空内容并聚焦。"""
        if self.edit_target.cget("state") == "disabled":
            return
        self._placeholder_active = False
        self.edit_target.configure(fg=theme.current().text)
        self.edit_target.delete(0, "end")
        self.edit_target.focus_set()

    def _on_clear_log(self) -> None:
        """清空日志区。"""
        self.log_panel.clear()

    def _on_toggle_enter(self, _event: tk.Event) -> None:
        """启停按钮悬停：底色换成 22% 混合色（disabled 时不动）。"""
        if self._state in ("starting", "stopping"):
            return
        t = theme.current()
        tone = t.red if self._state == "running" else t.green
        self.btn_toggle.configure(bg=theme.mix(tone, 0.22, t.bg))

    def _on_toggle_leave(self, _event: tk.Event) -> None:
        if self._state in ("starting", "stopping"):
            return
        t = theme.current()
        tone = t.red if self._state == "running" else t.green
        self.btn_toggle.configure(bg=theme.mix(tone, 0.12, t.bg))

    def _on_toggle(self) -> None:
        """启停开关；starting / stopping 期间重复触发直接忽略。"""
        if self._state in ("starting", "stopping"):
            return
        if self._state == "idle":
            target_text = self._target_value()
            if not target_text:
                self._notice("请先填写转发目标域名 / IP", error=True)
                return
            listen_text = self.edit_listen.get().strip()
            if not listen_text.isdigit() or not 1 <= int(listen_text) <= 65535:
                self._notice("监听端口无效，需为 1-65535 的整数", error=True)
                return
            parsed = parse_target(target_text)
            if parsed is None:
                self._notice("目标格式无效，示例：cf.090227.xyz 或 cf.090227.xyz:443", error=True)
                return
            host, port = parsed
            config = AppConfig(
                listen_port=int(listen_text),
                target_host=host,
                target_port=port,
            )
            self._reset_session_view()
            self._apply_state("starting")
            self._worker.start(config)
        else:  # running
            self._apply_state("stopping")
            self._worker.stop(timeout=3.0)
            self._apply_state("idle")

    # ------------------------------------------------------------ 状态与提示

    def _apply_state(self, state: str) -> None:
        """状态机：同步按钮文案 / 配色 / 状态灯 / 输入框锁定。"""
        self._state = state
        t = theme.current()
        locking = state in ("starting", "running", "stopping")

        for field in (self.edit_listen, self.edit_target):
            field.configure(state="disabled" if locking else "normal")

        if state == "idle":
            self._style_toggle("\u25b6 转发监听", t.green, enabled=True)
            self.lamp.configure(fg=t.red)
            self.lbl_state.configure(text="已停止", fg=t.text)
            self.btn_clear_target.configure(fg=t.muted)
            # 对齐 Qt 的 _set_state("idle")：ping 回落为 muted 的「--」，peer 清空
            self.lbl_ping_value.configure(text="--", fg=t.muted)
            self._set_peer("")
            self._last_tcping = None
        elif state == "starting":
            self._style_toggle("启动中…", t.amber, enabled=False)
            self.lamp.configure(fg=t.amber)
            self.lbl_state.configure(text="启动中…", fg=t.text)
            self.btn_clear_target.configure(fg=t.dim)
        elif state == "running":
            self._style_toggle("\u25a0 停止", t.red, enabled=True)
            self.lamp.configure(fg=t.green)
            self.lbl_state.configure(text="监听中", fg=t.text)
            self.btn_clear_target.configure(fg=t.dim)
        elif state == "stopping":
            self._style_toggle("停止中…", t.amber, enabled=False)
            self.lamp.configure(fg=t.amber)
            self.lbl_state.configure(text="停止中…", fg=t.text)
            self.btn_clear_target.configure(fg=t.dim)

    def _style_toggle(self, text: str, tone: str, enabled: bool) -> None:
        """统一设置启停按钮的文案与四种视觉属性。"""
        t = theme.current()
        if enabled:
            self.btn_toggle.configure(
                text=text,
                state="normal",
                fg=tone,
                disabledforeground=tone,
                bg=theme.mix(tone, 0.12, t.bg),
                activeforeground=tone,
                activebackground=theme.mix(tone, 0.22, t.bg),
                highlightbackground=theme.mix(tone, 0.45, t.bg),
                highlightcolor=theme.mix(tone, 0.45, t.bg),
            )
        else:  # 对齐 QSS 的 :disabled —— 透明底、border 描边、dim 文字
            self.btn_toggle.configure(
                text=text,
                state="disabled",
                fg=t.dim,
                disabledforeground=t.dim,
                bg=t.bg,
                activeforeground=t.dim,
                activebackground=t.bg,
                highlightbackground=t.border,
                highlightcolor=t.border,
            )

    def _notice(self, message: str, error: bool) -> None:
        """状态行 notice 提示；error 为红色，普通信息为弱化色，超时自动消失。"""
        self._notice_error = error
        if not message:
            self.lbl_notice.configure(text="")
            return
        if self._notice_job is not None:
            try:
                self.root.after_cancel(self._notice_job)
            except (tk.TclError, ValueError):
                pass
            self._notice_job = None
        t = theme.current()
        self.lbl_notice.configure(text=message, fg=t.red if error else t.muted)
        self._notice_seq += 1
        sequence = self._notice_seq
        self._notice_job = self.root.after(_NOTICE_MS, lambda: self._expire_notice(sequence))

    def _expire_notice(self, sequence: int) -> None:
        if sequence == self._notice_seq:
            self.lbl_notice.configure(text="")
        self._notice_job = None

    def _set_peer(self, peer: str) -> None:
        """设置对端地址片段；为空时「peer 」前缀一并隐藏。"""
        self.lbl_peer_key.configure(text="peer " if peer else "")
        self.lbl_peer_value.configure(text=peer)

    def _render_net(self) -> None:
        """刷新底部状态条的 tcp / udp / sni 计数。"""
        tcp, udp, sni = self._net
        self.lbl_tcp.configure(text=f" {tcp}")
        self.lbl_udp.configure(text=f" {udp}")
        self.lbl_sni.configure(text=f" {sni}")

    def _reset_session_view(self) -> None:
        """开工前清空上一轮会话的展示数据。"""
        self.log_panel.clear()
        self._last_rows = ()
        self._last_stats = None
        self._last_tcping = None
        self.stats_table.set_rows(())
        self._net = (0, 0, 0)
        self._render_net()
        self.lbl_total.configure(text="total 0 · 0 组")
        self.lbl_ping_value.configure(text="--", fg=theme.current().muted)
        self._set_peer("")

    # ------------------------------------------------------------ 事件消费

    def _tick(self) -> None:
        """100ms 轮询：抽干事件队列后重新排期。"""
        if not self._alive:
            return
        self._drain_events()
        self._timer_job = self.root.after(100, self._tick)

    def _drain_events(self) -> None:
        """批量消费 worker 事件，减少控件重绘次数。"""
        log_entries: list[LogEntry] = []
        stats: Optional[StatsEvent] = None

        for _ in range(_DRAIN_BATCH):
            try:
                event = self._worker.events.get_nowait()
            except queue.Empty:
                break

            if isinstance(event, StackEvent):
                # 把 ProtocolStack 投影成 GUI 层的 LogEntry（FIX-4）
                stack = event.stack
                log_entries.append(
                    LogEntry(
                        ts=event.ts,
                        domain=stack.domain,
                        app=stack.app,
                        transport=stack.transport_label,
                        security=stack.security,
                        provisional=stack.provisional,
                    )
                )
            elif isinstance(event, TcpingEvent):
                self._apply_tcping(event)
            elif isinstance(event, StateEvent):
                if event.state == "running":
                    self._apply_state("running")
                    self._notice(event.message or "", error=False)
                elif event.state == "stopped":
                    self._apply_state("idle")
                elif event.state == "error":
                    self._apply_state("idle")
                    self._notice(event.message, error=True)
            elif isinstance(event, StatsEvent):
                stats = event
            elif isinstance(event, NoticeEvent):
                self._notice(event.message, error=(event.level == "error"))

        if log_entries:
            self.log_panel.append_lines(log_entries)
        if stats is not None:
            self._apply_stats(stats)

    def _apply_tcping(self, event: TcpingEvent) -> None:
        """行2 状态行的 ping 值与对端地址（双色）；缓存供主题重刷。"""
        self._last_tcping = event
        t = theme.current()
        if event.latency_ms is None:
            self.lbl_ping_value.configure(text="超时", fg=t.red)
            self._set_peer("")
            return
        self.lbl_ping_value.configure(text=f"{event.latency_ms:.1f}ms", fg=t.green)
        self._set_peer(event.peer or "")

    def _apply_stats(self, event: StatsEvent) -> None:
        """刷新统计表、底部计数与 footer。"""
        self._last_stats = event
        if event.rows != self._last_rows:
            self._last_rows = event.rows
            self.stats_table.set_rows(event.rows)
        self._net = (event.tcp_conns, event.udp_sessions, event.total_hits)
        self._render_net()
        footer = f"total {event.total_hits} · {event.distinct} 组"
        if event.truncated:
            footer += f" · 仅显示前 {Stats.MAX_ROWS} 组"
        self.lbl_total.configure(text=footer)

    # ------------------------------------------------------------------ 关闭

    def _on_close(self) -> None:
        """关闭窗口：中止在跑的会话并撤掉两个定时器。"""
        self._alive = False
        for job in (self._timer_job, self._theme_job, self._notice_job):
            if job is not None:
                try:
                    self.root.after_cancel(job)
                except (tk.TclError, ValueError):
                    pass
        self._timer_job = self._theme_job = self._notice_job = None
        if self._worker.running or self._state != "idle":
            self._worker.stop(timeout=3.0)
        self.root.destroy()

    def run(self) -> None:
        """进入 Tk 事件循环（阻塞直到窗口关闭）。"""
        self.root.mainloop()
