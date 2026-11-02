"""主窗口：终端风布局 + 双主题（跟随系统亮暗）+ 命令配置行 + 左右分栏。"""

from __future__ import annotations

import os
import queue
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import (
    QFont,
    QFontDatabase,
    QIcon,
    QIntValidator,
    QKeySequence,
    QShortcut,
)
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..config import (
    DEFAULT_LISTEN_PORT,
    DEFAULT_TARGET_HOST,
    DEFAULT_TARGET_PORT,
    AppConfig,
)
from ..events import NoticeEvent, SniEvent, StateEvent, StatsEvent, TcpingEvent
from ..worker import Worker
from . import theme
from .log_panel import LogPanel
from .stats_table import StatsTable

_DRAIN_BATCH = 400
_NOTICE_MS = 5000

# 等宽字体族优先，中文自动回退微软雅黑
_FONT_CANDIDATES = (
    "Cascadia Mono",
    "JetBrains Mono",
    "Consolas",
    "Microsoft YaHei UI",
    "Microsoft YaHei",
)

# Windows DWM 属性：标题栏颜色（Win11）/ 深色标题栏（Win10 兜底）
_DWMWA_CAPTION_COLOR = 35
_DWMWA_USE_IMMERSIVE_DARK_MODE = 20


def parse_target(text: str, default_port: int = DEFAULT_TARGET_PORT) -> tuple[str, int] | None:
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


def apply_default_font(app: QApplication) -> None:
    """统一 UI 字体：优先等宽字体族（终端风），中文自动回退微软雅黑。"""
    available = set(QFontDatabase.families())
    font = QFont()
    families = [family for family in _FONT_CANDIDATES if family in available]
    if families:
        # Qt6 支持字族列表：等宽优先，缺失字形（中文）自动回退
        font.setFamilies(families)
        font.setStyleHint(QFont.Monospace)
    font.setPointSize(9)
    app.setFont(font)


class MainWindow(QWidget):
    """单窗口应用；所有网络逻辑在 Worker 线程，窗口只消费事件。"""

    def __init__(self) -> None:
        super().__init__()
        self._worker = Worker()
        self._state = "idle"  # idle | starting | running | stopping
        self._last_domains: tuple[tuple[str, int], ...] = ()
        self._notice_seq = 0
        self._last_tcping: TcpingEvent | None = None  # 主题切换重刷状态行用
        self._last_stats: StatsEvent | None = None

        self.setObjectName("RootWindow")
        self.setWindowTitle("SNI域名探测器")
        # 移除窗口最大化能力（按钮与系统行为一并禁用）
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, False)
        self.resize(760, 560)

        icon_path = _resource_path("app.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # 主题跟随系统亮暗；系统切换时实时重刷
        self._apply_scheme()
        app_hints = QApplication.styleHints()
        app_hints.colorSchemeChanged.connect(self._on_scheme_changed)

        self._build_ui()
        self._build_shortcuts()
        self._apply_style()
        self._set_state("idle")

        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._drain_events)
        self._timer.start()

    # ------------------------------------------------------------ 主题与标题栏

    def _apply_scheme(self) -> None:
        """读取系统配色并设定当前主题令牌。"""
        theme.set_scheme(QApplication.styleHints().colorScheme())
        self._t = theme.current()

    def _on_scheme_changed(self, _scheme) -> None:
        """系统亮暗切换：整窗重刷 QSS、内联色、统计表与日志重染、标题栏。"""
        self._apply_scheme()
        self._apply_style()
        self._set_lamp_for_state()
        if self._last_tcping is not None:
            self._apply_tcping(self._last_tcping)
        if self._last_stats is not None:
            self.lbl_net.setText(self._format_net_stats_for(self._last_stats))
        if self._last_domains:
            self.stats_table.set_domains(self._last_domains)
        self.log_panel.retheme()
        self._apply_caption_color()

    def _set_lamp_for_state(self) -> None:
        """按当前状态机刷新状态灯颜色（主题切换后调用）。"""
        color = {
            "idle": self._t.red,
            "starting": self._t.amber,
            "running": self._t.green,
            "stopping": self._t.amber,
        }.get(self._state, self._t.red)
        self._set_lamp(color)

    def _apply_caption_color(self) -> None:
        """让 Windows 标题栏颜色与主题底色一致（Win11 上色 / Win10 暗色兜底）。"""
        if sys.platform != "win32":  # 非 Windows 无 DWM，静默跳过
            return
        try:
            import ctypes

            hwnd = int(self.winId())
            color = ctypes.c_uint(self._caption_colorref())
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, _DWMWA_CAPTION_COLOR, ctypes.byref(color), 4
            )
            if result != 0:  # Win10 不支持 CAPTION_COLOR，退回深/浅标题栏
                dark = ctypes.c_int(0 if self._t.name == "light" else 1)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, _DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(dark), 4
                )
        except Exception:  # noqa: BLE001 - 标题栏装饰失败不应影响功能
            pass

    def _caption_colorref(self) -> int:
        """主题底色 → Windows COLORREF（0x00BBGGRR）。"""
        c = self._t.bg.lstrip("#")
        r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        return r | (g << 8) | (b << 16)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        super().showEvent(event)
        self._apply_caption_color()

    # ------------------------------------------------------------------ 构建

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 10)
        root.setSpacing(8)

        root.addLayout(self._build_config_row())
        root.addLayout(self._build_status_row())
        root.addWidget(self._build_main_area(), 1)
        root.addLayout(self._build_status_bar())

    def _build_config_row(self) -> QHBoxLayout:
        """行1 命令配置行：listen 端口 → host:port 合一输入 → 启停按钮。

        监听端口用 QLineEdit + QIntValidator 而非 QSpinBox：终端风下
        QSpinBox 需去掉上下按钮（NoButtons），而「NoButtons + QSS」组合
        会触发 Qt QStyleSheetStyle 的缺陷，把内部输入区算成 1px 宽导致
        文字不可见；QLineEdit 与右侧目标输入框视觉一致且无此问题。
        """
        row = QHBoxLayout()
        row.setSpacing(8)

        self.lbl_listen = QLabel("listen")
        self.lbl_listen.setObjectName("CmdKey")

        self.edit_listen = QLineEdit(str(DEFAULT_LISTEN_PORT))
        self.edit_listen.setValidator(QIntValidator(1, 65535, self))
        self.edit_listen.setFixedWidth(80)
        self.edit_listen.setAlignment(Qt.AlignLeft)
        self.edit_listen.setToolTip("本地监听端口（1-65535）")

        self.lbl_arrow = QLabel("→")
        self.lbl_arrow.setObjectName("CmdSep")

        self.edit_target = QLineEdit(DEFAULT_TARGET_HOST)
        self.edit_target.setPlaceholderText("host 或 host:port（端口省略默认 443）")
        self.edit_target.setClearButtonEnabled(True)
        self.edit_target.setMinimumWidth(180)

        self.btn_toggle = QPushButton("▶ 转发监听")
        self.btn_toggle.setObjectName("ToggleButton")
        self.btn_toggle.setMinimumWidth(112)
        self.btn_toggle.setCursor(Qt.PointingHandCursor)
        self.btn_toggle.clicked.connect(self._on_toggle)

        row.addWidget(self.lbl_listen)
        row.addWidget(self.edit_listen)
        row.addWidget(self.lbl_arrow)
        row.addWidget(self.edit_target, 1)
        row.addWidget(self.btn_toggle)
        return row

    def _build_status_row(self) -> QHBoxLayout:
        """行2 状态行：状态灯 + 状态文字 + ping + peer + notice 提示。"""
        row = QHBoxLayout()
        row.setSpacing(8)

        self.lamp = QLabel("●")
        self.lamp.setObjectName("Lamp")

        self.lbl_state = QLabel("已停止")
        self.lbl_state.setObjectName("StateText")

        self.lbl_ping = QLabel("ping --")
        self.lbl_ping.setObjectName("StatusInfo")

        self.lbl_sep = QLabel("│")
        self.lbl_sep.setObjectName("CmdSep")

        self.lbl_peer = QLabel("")
        self.lbl_peer.setObjectName("StatusInfo")

        self.lbl_notice = QLabel("")
        self.lbl_notice.setObjectName("NoticeText")
        self.lbl_notice.setWordWrap(False)

        row.addWidget(self.lamp)
        row.addWidget(self.lbl_state)
        row.addSpacing(10)
        row.addWidget(self.lbl_ping)
        row.addWidget(self.lbl_sep)
        row.addWidget(self.lbl_peer)
        row.addStretch(1)
        row.addWidget(self.lbl_notice)
        return row

    def _make_pane(
        self, title_text: str, hint_text: str, action: QWidget | None = None
    ) -> tuple[QFrame, QVBoxLayout]:
        """构造终端风面板：面板头（标题 + 弱化提示 + 可选动作按钮）+ 内容区。

        Args:
            title_text: 面板头标题，如 ``── sni log ──``。
            hint_text: 面板头右侧弱化提示。
            action: 可选动作控件（如 [清除] 按钮），置于最右侧。

        Returns:
            (面板容器, 内容区布局) 二元组；调用方往内容区布局里加控件。
        """
        pane = QFrame()
        pane.setObjectName("Pane")
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setObjectName("PaneHeader")
        head = QHBoxLayout(header)
        head.setContentsMargins(10, 6, 10, 6)
        head.setSpacing(8)
        title = QLabel(title_text)
        title.setObjectName("PaneTitle")
        hint = QLabel(hint_text)
        hint.setObjectName("Hint")
        head.addWidget(title)
        head.addStretch(1)
        head.addWidget(hint)
        if action is not None:
            head.addWidget(action)
        layout.addWidget(header)

        body = QVBoxLayout()
        body.setContentsMargins(6, 4, 6, 6)
        body.setSpacing(4)
        layout.addLayout(body, 1)
        return pane, body

    def _build_main_area(self) -> QSplitter:
        """行3 主区：水平左右分栏 —— 左=嗅探日志，右=域名统计，5:5 正中分割。"""
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)

        # 左栏：嗅探日志（clear 就近放在面板头）
        self.btn_clear = QPushButton("[清除]")
        self.btn_clear.setObjectName("ClearButton")
        self.btn_clear.setCursor(Qt.PointingHandCursor)
        self.btn_clear.clicked.connect(self._clear_log)
        log_pane, log_body = self._make_pane("── sni log ──", "上限 5000 行", self.btn_clear)
        self.log_panel = LogPanel()
        log_body.addWidget(self.log_panel, 1)

        # 右栏：域名统计（无面板头，直接表格，视觉更整齐）
        stats_pane = QFrame()
        stats_pane.setObjectName("Pane")
        stats_layout = QVBoxLayout(stats_pane)
        stats_layout.setContentsMargins(6, 4, 6, 6)
        stats_layout.setSpacing(4)
        self.stats_table = StatsTable()
        self.stats_table.verticalHeader().setDefaultSectionSize(24)
        stats_layout.addWidget(self.stats_table, 1)
        self.lbl_total = QLabel("total 0")
        self.lbl_total.setObjectName("PaneFooter")
        stats_layout.addWidget(self.lbl_total)

        splitter.addWidget(log_pane)
        splitter.addWidget(stats_pane)
        # 两栏对称最小宽：避免日志面板头文字把左栏最小宽撑大、破坏 5:5 初始比例
        log_pane.setMinimumWidth(280)
        stats_pane.setMinimumWidth(280)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        splitter.setSizes([362, 362])
        return splitter

    def _build_status_bar(self) -> QHBoxLayout:
        """行4 底部状态条：tcp / udp / sni 计数 + 快捷键提示（完整可读形式）。"""
        row = QHBoxLayout()
        row.setSpacing(12)

        self.lbl_net = QLabel(self._format_net_stats(0, 0, 0))
        self.lbl_net.setObjectName("StatusBarText")

        self.lbl_shortcut = QLabel("Ctrl + L 清屏 · Enter 启停")
        self.lbl_shortcut.setObjectName("ShortcutHint")

        row.addWidget(self.lbl_net)
        row.addStretch(1)
        row.addWidget(self.lbl_shortcut)
        return row

    def _build_shortcuts(self) -> None:
        """键盘流：Enter（含小键盘）启停，Ctrl + L 清日志。"""
        for key in (Qt.Key_Return, Qt.Key_Enter):
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(self._on_toggle)
        clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        clear_shortcut.activated.connect(self._clear_log)

    def _apply_style(self) -> None:
        """整窗终端风 QSS；全部颜色令牌来自当前主题（亮/暗自适应）。"""
        t = self._t
        self.setStyleSheet(
            f"""
            QWidget {{
                color: {t.text};
                font-size: 12px;
                font-family: "Cascadia Mono", "JetBrains Mono", Consolas, "Microsoft YaHei UI";
                selection-background-color: {t.rgba(t.green, 0.30)};
                selection-color: {t.text};
            }}
            QWidget#RootWindow {{ background: {t.bg}; }}

            /* 行1 命令配置行 */
            QLabel#CmdKey {{ color: {t.green}; }}
            QLabel#CmdSep {{ color: {t.dim}; }}
            QLineEdit {{
                background: {t.pane};
                border: 1px solid {t.border};
                border-radius: 3px;
                padding: 5px 8px;
                color: {t.text};
                font-size: 12px;
            }}
            QLineEdit:focus {{ border: 1px solid {t.green}; }}
            QLineEdit:disabled {{ color: {t.dim}; }}

            QPushButton#ToggleButton {{
                background: {t.rgba(t.green, 0.12)};
                border: 1px solid {t.rgba(t.green, 0.45)};
                border-radius: 3px;
                color: {t.green};
                padding: 6px 16px;
                font-weight: 600;
            }}
            QPushButton#ToggleButton:hover {{ background: {t.rgba(t.green, 0.22)}; }}
            QPushButton#ToggleButton[running="true"] {{
                background: {t.rgba(t.red, 0.12)};
                border: 1px solid {t.rgba(t.red, 0.45)};
                color: {t.red};
            }}
            QPushButton#ToggleButton[running="true"]:hover {{ background: {t.rgba(t.red, 0.22)}; }}
            QPushButton#ToggleButton:disabled {{
                background: transparent;
                border: 1px solid {t.border};
                color: {t.dim};
            }}

            /* 行2 状态行 */
            QLabel#Lamp {{ font-size: 13px; }}
            QLabel#StateText {{ color: {t.text}; font-size: 12px; font-weight: 600; }}
            QLabel#StatusInfo {{ color: {t.muted}; font-size: 12px; }}
            QLabel#NoticeText {{ color: {t.red}; font-size: 12px; }}

            /* 行3 面板与分栏 */
            QFrame#Pane {{
                background: {t.pane};
                border: 1px solid {t.border};
                border-radius: 4px;
            }}
            QFrame#PaneHeader {{
                background: transparent;
                border: none;
                border-bottom: 1px solid {t.border};
            }}
            QLabel#PaneTitle {{ color: {t.green}; font-size: 11px; }}
            QLabel#Hint {{ color: {t.dim}; font-size: 11px; }}
            QLabel#PaneFooter {{ color: {t.dim}; font-size: 11px; }}
            QPushButton#ClearButton {{
                background: transparent;
                border: 1px solid {t.border};
                border-radius: 3px;
                color: {t.muted};
                padding: 1px 8px;
                font-size: 11px;
            }}
            QPushButton#ClearButton:hover {{ color: {t.text}; border: 1px solid {t.dim}; }}
            QSplitter::handle {{ background: {t.bg}; }}

            QPlainTextEdit#LogPanel {{
                background: transparent;
                border: none;
                color: {t.text};
            }}

            QTableWidget#StatsTable {{
                background: transparent;
                border: none;
                font-size: 12px;
            }}
            QTableWidget#StatsTable::item {{ border: none; }}
            QTableWidget#StatsTable::item:hover {{ background: {t.hover}; }}
            QTableWidget#StatsTable::item:selected {{
                background: {t.rgba(t.green, 0.14)};
                color: {t.text};
            }}
            QHeaderView::section {{
                background: transparent;
                color: {t.muted};
                border: none;
                border-bottom: 1px solid {t.border};
                padding: 4px 6px;
                font-size: 11px;
            }}

            /* 行4 底部状态条 */
            QLabel#StatusBarText {{ color: {t.muted}; font-size: 11px; }}
            QLabel#ShortcutHint {{ color: {t.dim}; font-size: 11px; }}

            /* 细滚动条，保持终端工具感 */
            QScrollBar:vertical {{ background: transparent; width: 8px; margin: 0; }}
            QScrollBar::handle:vertical {{ background: {t.border}; border-radius: 4px; min-height: 24px; }}
            QScrollBar::handle:vertical:hover {{ background: {t.dim}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QScrollBar:horizontal {{ background: transparent; height: 8px; margin: 0; }}
            QScrollBar::handle:horizontal {{ background: {t.border}; border-radius: 4px; min-width: 24px; }}
            QScrollBar::handle:horizontal:hover {{ background: {t.dim}; }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
            QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

            QToolTip {{
                background: {t.pane};
                color: {t.text};
                border: 1px solid {t.border};
                padding: 3px 6px;
            }}
            """
        )

    # ------------------------------------------------------------ 状态与开关

    def _on_toggle(self) -> None:
        """启停开关；starting / stopping 期间重复触发直接忽略。"""
        if self._state in ("starting", "stopping"):
            return
        if self._state == "idle":
            target_text = self.edit_target.text().strip()
            if not target_text:
                self._notice("请先填写转发目标域名 / IP", error=True)
                return
            listen_text = self.edit_listen.text().strip()
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
            self._set_state("starting")
            self._worker.start(config)
        else:  # running
            self._set_state("stopping")
            self._worker.stop(timeout=3.0)
            self._set_state("idle")

    def _format_net_stats(self, tcp: int, udp: int, sni: int) -> str:
        """底部状态条富文本：tcp / udp / sni 计数，分隔符弱化。"""
        t = self._t
        return (
            f"tcp <span style='color: {t.text};'>{tcp}</span>"
            f" <span style='color: {t.dim};'>│</span>"
            f" udp <span style='color: {t.text};'>{udp}</span>"
            f" <span style='color: {t.dim};'>│</span>"
            f" sni <span style='color: {t.green};'>{sni}</span>"
        )

    def _format_net_stats_for(self, event: StatsEvent) -> str:
        """按 StatsEvent 生成底部状态条富文本（主题重刷用）。"""
        return self._format_net_stats(event.tcp_conns, event.udp_sessions, event.total_hits)

    def _reset_session_view(self) -> None:
        """开工前清空上一轮会话的展示数据。"""
        self.log_panel.clear()
        self._last_domains = ()
        self.stats_table.setRowCount(0)
        self.lbl_net.setText(self._format_net_stats(0, 0, 0))
        self.lbl_total.setText("total 0")
        self.lbl_ping.setText("ping --")
        self.lbl_peer.setText("")

    def _set_state(self, state: str) -> None:
        """状态机：同步按钮文案 / 状态灯 / 输入锁定。"""
        self._state = state
        locking = state in ("starting", "running", "stopping")

        if state == "idle":
            self.btn_toggle.setText("▶ 转发监听")
            self.btn_toggle.setProperty("running", False)
            self.btn_toggle.setEnabled(True)
            self.lbl_state.setText("已停止")
            self._set_lamp(self._t.red)
            self.lbl_ping.setText("ping --")
            self.lbl_peer.setText("")
        elif state == "starting":
            self.btn_toggle.setText("启动中…")
            self.btn_toggle.setProperty("running", False)
            self.btn_toggle.setEnabled(False)
            self.lbl_state.setText("启动中…")
            self._set_lamp(self._t.amber)
        elif state == "running":
            self.btn_toggle.setText("■ 停止")
            self.btn_toggle.setProperty("running", True)
            self.btn_toggle.setEnabled(True)
            self.lbl_state.setText("监听中")
            self._set_lamp(self._t.green)
        elif state == "stopping":
            self.btn_toggle.setText("停止中…")
            self.btn_toggle.setProperty("running", True)
            self.btn_toggle.setEnabled(False)
            self.lbl_state.setText("停止中…")
            self._set_lamp(self._t.amber)

        for widget in (self.edit_listen, self.edit_target):
            widget.setEnabled(not locking)

        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

    def _set_lamp(self, color: str) -> None:
        self.lamp.setStyleSheet(f"color: {color};")

    def _clear_log(self) -> None:
        self.log_panel.clear()

    def _notice(self, message: str, error: bool) -> None:
        """状态行 notice 提示；error 为红色，普通信息为弱化色，超时自动消失。"""
        if not message:
            return
        self.lbl_notice.setText(message)
        color = self._t.red if error else self._t.muted
        self.lbl_notice.setStyleSheet(f"color: {color};")
        self._notice_seq += 1
        seq = self._notice_seq
        QTimer.singleShot(_NOTICE_MS, lambda: self._expire_notice(seq))

    def _expire_notice(self, seq: int) -> None:
        if seq == self._notice_seq:
            self.lbl_notice.setText("")

    # ------------------------------------------------------------ 事件消费

    def _drain_events(self) -> None:
        log_lines: list[str] = []
        stats: StatsEvent | None = None

        for _ in range(_DRAIN_BATCH):
            try:
                event = self._worker.events.get_nowait()
            except queue.Empty:
                break

            if isinstance(event, SniEvent):
                log_lines.append(f"{event.ts} {event.domain}")
            elif isinstance(event, TcpingEvent):
                self._apply_tcping(event)
            elif isinstance(event, StateEvent):
                if event.state == "running":
                    self._set_state("running")
                    self._notice(event.message or "", error=False)
                elif event.state == "stopped":
                    self._set_state("idle")
                elif event.state == "error":
                    self._set_state("idle")
                    self._notice(event.message, error=True)
            elif isinstance(event, StatsEvent):
                stats = event
            elif isinstance(event, NoticeEvent):
                self._notice(event.message, error=(event.level == "error"))

        if log_lines:
            self.log_panel.append_lines(log_lines)
        if stats is not None:
            self._apply_stats(stats)

    def _apply_tcping(self, event: TcpingEvent) -> None:
        """行2 状态行的 ping 值与对端地址（富文本双色）；缓存供主题重刷。"""
        self._last_tcping = event
        t = self._t
        if event.latency_ms is None:
            self.lbl_ping.setText(f"ping <span style='color: {t.red};'>超时</span>")
            self.lbl_peer.setText("")
            return
        self.lbl_ping.setText(f"ping <span style='color: {t.green};'>{event.latency_ms:.1f}ms</span>")
        if event.peer:
            self.lbl_peer.setText(f"peer <span style='color: {t.cyan};'>{event.peer}</span>")
        else:
            self.lbl_peer.setText("")

    def _apply_stats(self, event: StatsEvent) -> None:
        self._last_stats = event
        if event.domains != self._last_domains:
            self._last_domains = event.domains
            self.stats_table.set_domains(event.domains)
        self.lbl_net.setText(self._format_net_stats_for(event))
        self.lbl_total.setText(f"total {event.total_hits}")

    # ------------------------------------------------------------------ 关闭

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if self._worker.running or self._state != "idle":
            self._worker.stop(timeout=3.0)
        super().closeEvent(event)
