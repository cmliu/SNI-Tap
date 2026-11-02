"""主窗口：配置区 + tcping 状态区 + 统计/日志上下分割主区 + 状态栏。"""

from __future__ import annotations

import queue

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
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
from .log_panel import LogPanel
from .stats_table import StatsTable

_ACCENT = "#185FA5"
_ACCENT_HOVER = "#1A6CB7"
_STOP = "#A32D2D"
_STOP_HOVER = "#BF3636"
_OK = "#2E9E5B"
_BAD = "#D9534F"
_WAIT = "#C8961E"
_MUTED = "rgba(128, 132, 138, 1)"

_DRAIN_BATCH = 400
_NOTICE_MS = 5000

_FONT_CANDIDATES = (
    "Microsoft YaHei UI",
    "Microsoft YaHei",
    "PingFang SC",
    "Noto Sans CJK SC",
    "Source Han Sans SC",
)


def apply_default_font(app: QApplication) -> None:
    """统一 UI 字体：优先微软雅黑等中文字体，保证中英文混排一致。"""
    available = set(QFontDatabase.families())
    font = QFont()
    for family in _FONT_CANDIDATES:
        if family in available:
            font.setFamily(family)
            break
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

        self.setWindowTitle("SNI域名探测器")
        self.resize(760, 760)

        self._build_ui()
        self._apply_style()
        self._set_state("idle")

        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._drain_events)
        self._timer.start()

    # ------------------------------------------------------------------ 构建

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 10)
        root.setSpacing(10)

        root.addLayout(self._build_config_row())
        root.addLayout(self._build_status_row())
        root.addWidget(self._build_main_area(), 1)
        root.addLayout(self._build_status_bar())

    def _build_config_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        self.spin_listen = QSpinBox()
        self.spin_listen.setRange(1, 65535)
        self.spin_listen.setValue(DEFAULT_LISTEN_PORT)
        self.spin_listen.setFixedWidth(96)

        self.edit_target = QLineEdit(DEFAULT_TARGET_HOST)
        self.edit_target.setClearButtonEnabled(True)
        self.edit_target.setMinimumWidth(180)

        self.spin_tport = QSpinBox()
        self.spin_tport.setRange(1, 65535)
        self.spin_tport.setValue(DEFAULT_TARGET_PORT)
        self.spin_tport.setFixedWidth(96)

        self.btn_toggle = QPushButton("转发监听")
        self.btn_toggle.setObjectName("ToggleButton")
        self.btn_toggle.setMinimumWidth(112)
        self.btn_toggle.setCursor(Qt.PointingHandCursor)
        self.btn_toggle.clicked.connect(self._on_toggle)

        row.addLayout(self._field("本地监听端口", self.spin_listen))
        row.addLayout(self._field("转发目标域名 / IP", self.edit_target), 1)
        row.addLayout(self._field("目标端口", self.spin_tport))
        row.addLayout(self._field(" ", self.btn_toggle))
        return row

    def _field(self, label_text: str, widget: QWidget) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(4)
        label = QLabel(label_text)
        label.setObjectName("FieldLabel")
        box.addWidget(label)
        box.addWidget(widget)
        return box

    def _build_status_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        self.lamp = QLabel("●")
        self.lamp.setObjectName("Lamp")

        self.lbl_state = QLabel("已停止")
        self.lbl_state.setObjectName("StateText")

        self.lbl_latency = QLabel("--")
        self.lbl_latency.setObjectName("Latency")

        self.lbl_peer = QLabel("")
        self.lbl_peer.setObjectName("PeerText")

        self.lbl_notice = QLabel("")
        self.lbl_notice.setObjectName("NoticeText")
        self.lbl_notice.setWordWrap(False)

        self.btn_clear = QPushButton("清除日志")
        self.btn_clear.setCursor(Qt.PointingHandCursor)
        self.btn_clear.clicked.connect(self._clear_log)

        row.addWidget(self.lamp)
        row.addWidget(self.lbl_state)
        row.addSpacing(12)
        row.addWidget(self.lbl_latency)
        row.addWidget(self.lbl_peer)
        row.addStretch(1)
        row.addWidget(self.lbl_notice)
        row.addWidget(self.btn_clear)
        return row

    def _build_main_area(self) -> QSplitter:
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)

        stats_box = QWidget()
        stats_layout = QVBoxLayout(stats_box)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(6)
        stats_head = QHBoxLayout()
        stats_title = QLabel("域名统计 · 本次启动")
        stats_title.setObjectName("SectionTitle")
        stats_hint = QLabel("按次数降序 · 双击复制")
        stats_hint.setObjectName("Hint")
        stats_head.addWidget(stats_title)
        stats_head.addStretch(1)
        stats_head.addWidget(stats_hint)
        stats_layout.addLayout(stats_head)
        self.stats_table = StatsTable()
        self.stats_table.verticalHeader().setDefaultSectionSize(26)
        stats_layout.addWidget(self.stats_table, 1)

        log_box = QWidget()
        log_layout = QVBoxLayout(log_box)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(6)
        log_head = QHBoxLayout()
        log_title = QLabel("SNI 嗅探日志")
        log_title.setObjectName("SectionTitle")
        log_hint = QLabel("上限 5000 行 · 自动滚动")
        log_hint.setObjectName("Hint")
        log_head.addWidget(log_title)
        log_head.addStretch(1)
        log_head.addWidget(log_hint)
        log_layout.addLayout(log_head)
        self.log_panel = LogPanel()
        log_layout.addWidget(self.log_panel, 1)

        splitter.addWidget(stats_box)
        splitter.addWidget(log_box)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        splitter.setSizes([300, 420])
        return splitter

    def _build_status_bar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(18)
        self.lbl_conns = QLabel("TCP 连接 0")
        self.lbl_udp = QLabel("UDP 映射 0")
        self.lbl_hits = QLabel("嗅探总数 0")
        self.lbl_target_info = QLabel(f"目标 {DEFAULT_TARGET_HOST}:{DEFAULT_TARGET_PORT}")
        for label in (self.lbl_conns, self.lbl_udp, self.lbl_hits, self.lbl_target_info):
            label.setObjectName("StatusBarText")
        row.addWidget(self.lbl_conns)
        row.addWidget(self.lbl_udp)
        row.addWidget(self.lbl_hits)
        row.addStretch(1)
        row.addWidget(self.lbl_target_info)
        return row

    def _apply_style(self) -> None:
        self.setStyleSheet(
            f"""
            QLabel#FieldLabel {{ color: {_MUTED}; font-size: 12px; }}
            QLabel#SectionTitle {{ font-size: 13px; font-weight: 600; }}
            QLabel#Hint {{ color: {_MUTED}; font-size: 11px; }}
            QLabel#Lamp {{ font-size: 14px; }}
            QLabel#StateText {{ font-size: 13px; font-weight: 500; }}
            QLabel#Latency {{ font-size: 18px; font-weight: 600; }}
            QLabel#PeerText {{ color: {_MUTED}; font-size: 12px; }}
            QLabel#NoticeText {{ font-size: 12px; }}
            QLabel#StatusBarText {{ color: {_MUTED}; font-size: 12px; }}
            QPushButton {{ font-size: 13px; padding: 6px 14px; }}
            QPushButton#ToggleButton {{
                color: white; background: {_ACCENT}; border: none;
                border-radius: 6px; padding: 7px 20px; font-weight: 600;
            }}
            QPushButton#ToggleButton:hover {{ background: {_ACCENT_HOVER}; }}
            QPushButton#ToggleButton:disabled {{ background: #98A2AB; }}
            QPushButton#ToggleButton[running="true"] {{ background: {_STOP}; }}
            QPushButton#ToggleButton[running="true"]:hover {{ background: {_STOP_HOVER}; }}
            QLineEdit {{ font-size: 13px; padding: 5px 8px; }}
            QSpinBox {{ font-size: 13px; padding: 5px 6px; }}
            QPlainTextEdit#LogPanel {{
                background: rgba(127, 127, 127, 0.06);
                border: 1px solid rgba(127, 127, 127, 0.18);
                border-radius: 8px; padding: 6px;
            }}
            QTableWidget#StatsTable {{
                background: rgba(127, 127, 127, 0.06);
                border: 1px solid rgba(127, 127, 127, 0.18);
                border-radius: 8px; font-size: 12px;
            }}
            QHeaderView::section {{
                background: transparent; border: none;
                border-bottom: 1px solid rgba(127, 127, 127, 0.2);
                padding: 4px 8px; font-weight: 500;
            }}
            """
        )

    # ------------------------------------------------------------ 状态与开关

    def _on_toggle(self) -> None:
        if self._state in ("starting", "stopping"):
            return
        if self._state == "idle":
            target = self.edit_target.text().strip()
            if not target:
                self._notice("请先填写转发目标域名 / IP", error=True)
                return
            config = AppConfig(
                listen_port=self.spin_listen.value(),
                target_host=target,
                target_port=self.spin_tport.value(),
            )
            self._reset_session_view()
            self.lbl_target_info.setText(f"目标 {config.target_host}:{config.target_port}")
            self._set_state("starting")
            self._worker.start(config)
        else:  # running
            self._set_state("stopping")
            self._worker.stop(timeout=3.0)
            self._set_state("idle")

    def _reset_session_view(self) -> None:
        self.log_panel.clear()
        self._last_domains = ()
        self.stats_table.setRowCount(0)
        self.lbl_conns.setText("TCP 连接 0")
        self.lbl_udp.setText("UDP 映射 0")
        self.lbl_hits.setText("嗅探总数 0")

    def _set_state(self, state: str) -> None:
        self._state = state
        locking = state in ("starting", "running", "stopping")

        if state == "idle":
            self.btn_toggle.setText("转发监听")
            self.btn_toggle.setProperty("running", False)
            self.btn_toggle.setEnabled(True)
            self.lbl_state.setText("已停止")
            self._set_lamp(_BAD)
            self.lbl_latency.setText("--")
            self.lbl_latency.setStyleSheet(f"color: {_MUTED};")
            self.lbl_peer.setText("")
        elif state == "starting":
            self.btn_toggle.setText("启动中…")
            self.btn_toggle.setProperty("running", False)
            self.btn_toggle.setEnabled(False)
            self.lbl_state.setText("启动中…")
            self._set_lamp(_WAIT)
        elif state == "running":
            self.btn_toggle.setText("■ 停止")
            self.btn_toggle.setProperty("running", True)
            self.btn_toggle.setEnabled(True)
            self.lbl_state.setText("监听中")
            self._set_lamp(_OK)
        elif state == "stopping":
            self.btn_toggle.setText("停止中…")
            self.btn_toggle.setProperty("running", True)
            self.btn_toggle.setEnabled(False)
            self.lbl_state.setText("停止中…")
            self._set_lamp(_WAIT)

        for widget in (self.spin_listen, self.edit_target, self.spin_tport):
            widget.setEnabled(not locking)

        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

    def _set_lamp(self, color: str) -> None:
        self.lamp.setStyleSheet(f"color: {color};")

    def _clear_log(self) -> None:
        self.log_panel.clear()

    def _notice(self, message: str, error: bool) -> None:
        if not message:
            return
        self.lbl_notice.setText(message)
        self.lbl_notice.setStyleSheet(f"color: {_BAD};" if error else f"color: {_MUTED};")
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
                log_lines.append(f"{event.ts}   {event.domain}")
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
        if event.latency_ms is None:
            self.lbl_latency.setText("超时")
            self.lbl_latency.setStyleSheet(f"color: {_BAD};")
            self.lbl_peer.setText("")
            return
        self.lbl_latency.setText(f"{event.latency_ms:.1f} ms")
        self.lbl_latency.setStyleSheet(f"color: {_OK};")
        self.lbl_peer.setText(f"→ {event.peer}" if event.peer else "")

    def _apply_stats(self, event: StatsEvent) -> None:
        if event.domains != self._last_domains:
            self._last_domains = event.domains
            self.stats_table.set_domains(event.domains)
        self.lbl_conns.setText(f"TCP 连接 {event.tcp_conns}")
        self.lbl_udp.setText(f"UDP 映射 {event.udp_sessions}")
        self.lbl_hits.setText(f"嗅探总数 {event.total_hits}")

    # ------------------------------------------------------------------ 关闭

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if self._worker.running or self._state != "idle":
            self._worker.stop(timeout=3.0)
        super().closeEvent(event)
