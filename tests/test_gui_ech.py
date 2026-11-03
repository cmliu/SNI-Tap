"""GUI 层 ECH 渲染的无头断言：日志 tag 区间、统计表标记去重、footer 双计数。

不打开真实窗口交互，只创建离屏 Tk 根窗口后直接断言控件状态：

- ``LogPanel``：``ech`` tag 的区间必须恰好覆盖 ``ECH`` 三个字符（不能把
  分隔空格或行尾 ``?`` 圈进去），且位置在 ``security`` 之后、``?`` 之前；
- ``StatsTable``：单行布局下 ``has_ech`` 行的画布上只能出现一处 ``ECH`` 文本
  （紧跟在安全层之后），但 ``copy_row`` 的 TSV **仍带** `` ECH``
  ——「显示去重、数据不丢」；
- ``MainWindow``：footer 顺序为 total → 组数 → ``ech K``（确证）→ ``ech? X``
  （疑似 GREASE）→ 截断说明；日志侧只按 ``stack.ech``（确证语义）打标记，
  GREASE 行不得出现 ``ECH``。

无图形环境（Tk 不可用）时整组跳过，不影响其余用例。
"""

from __future__ import annotations

import pathlib
import sys
import tkinter as tk
import tkinter.font as tkfont
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from snitap.protocol import ECH_MARK, StackRow
from snitap.gui.log_panel import LogEntry, LogPanel
from snitap.gui.stats_table import StatsTable

_ECH_TAG = f" {ECH_MARK}"


def _tk_available() -> bool:
    """探测当前环境能否创建 Tk 根窗口（CI 无图形时返回 False）。"""
    try:
        root = tk.Tk()
    except tk.TclError:
        return False
    root.destroy()
    return True


TK_OK = _tk_available()


def _entry(
    *,
    domain: str = "ech.example",
    app: str = "h2",
    transport: str = "TCP",
    security: str = "TLS1.3/A128GCM",
    provisional: bool = False,
    ech: bool = False,
    ts: str = "12:00:00",
) -> LogEntry:
    """构造一条日志条目（默认**不带** ECH）。"""
    return LogEntry(
        ts=ts,
        domain=domain,
        app=app,
        transport=transport,
        security=security,
        provisional=provisional,
        ech=ech,
    )


class _TkTestCase(unittest.TestCase):
    """离屏 Tk 根窗口夹具：窗口放到屏幕外，避免弹窗干扰。"""

    root: tk.Tk

    @classmethod
    def setUpClass(cls) -> None:
        if not TK_OK:
            raise unittest.SkipTest("Tk 不可用（无图形环境），跳过 GUI 用例")
        cls.root = tk.Tk()
        cls.root.geometry("640x460+3000+3000")
        cls.font = tkfont.Font(family="Consolas", size=9)
        cls.header_font = tkfont.Font(family="Segoe UI", size=9)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.root.destroy()

    def tearDown(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()
        self.root.update_idletasks()


class LogPanelEchTagTest(_TkTestCase):
    """风险点 6：``ech`` tag 区间精确、位置正确、``?`` 不被污染。"""

    def _panel(self) -> LogPanel:
        panel = LogPanel(self.root, self.font, placeholder="空")
        panel.pack(fill="both", expand=True)
        return panel

    def _tag_slices(self, panel: LogPanel, tag: str) -> list[str]:
        """取出某个 tag 覆盖的全部文本片段。"""
        ranges = panel.text.tag_ranges(tag)
        return [
            panel.text.get(str(ranges[i]), str(ranges[i + 1]))
            for i in range(0, len(ranges), 2)
        ]

    def test_ech_tag_covers_exactly_three_chars(self) -> None:
        panel = self._panel()
        panel.append_lines([_entry(ech=True)])
        self.assertEqual(self._tag_slices(panel, "ech"), [ECH_MARK])

    def test_ech_tag_excludes_separator_and_question_mark(self) -> None:
        panel = self._panel()
        panel.append_lines([_entry(ech=True, provisional=True)])
        line = panel.text.get("1.0", "1.end")
        self.assertTrue(line.endswith(f"{ECH_MARK}?"))
        self.assertEqual(self._tag_slices(panel, "ech"), [ECH_MARK])
        for slice_text in self._tag_slices(panel, "ech"):
            self.assertNotIn("?", slice_text)
            self.assertNotIn(" ", slice_text)

    def test_ech_sits_after_security_and_before_question_mark(self) -> None:
        panel = self._panel()
        panel.append_lines([_entry(ech=True, provisional=True)])
        security_ranges = panel.text.tag_ranges("security")
        ech_ranges = panel.text.tag_ranges("ech")
        self.assertEqual(len(security_ranges), 2)
        self.assertEqual(len(ech_ranges), 2)
        security_end = str(security_ranges[1])
        ech_start, ech_end = str(ech_ranges[0]), str(ech_ranges[1])
        self.assertLess(
            int(security_end.split(".")[1]), int(ech_start.split(".")[1])
        )
        # ? 紧接 ECH 之后，且未被打上 ech tag
        gap = panel.text.get(ech_end, "1.end")
        self.assertEqual(gap, "?")

    def test_no_ech_entry_leaves_tag_empty(self) -> None:
        panel = self._panel()
        panel.append_lines([_entry(ech=False)])
        self.assertEqual(panel.text.tag_ranges("ech"), ())
        self.assertNotIn(ECH_MARK, panel.text.get("1.0", "end"))

    def test_batch_marks_only_ech_rows(self) -> None:
        panel = self._panel()
        panel.append_lines(
            [
                _entry(domain="a.example", ech=True),
                _entry(domain="b.example", ech=False),
                _entry(domain="c.example", ech=True),
            ]
        )
        self.assertEqual(self._tag_slices(panel, "ech"), [ECH_MARK, ECH_MARK])
        ranges = panel.text.tag_ranges("ech")
        lines = sorted({str(ranges[i]).split(".")[0] for i in range(0, len(ranges), 2)})
        self.assertEqual(lines, ["1", "3"])  # 第 2 行无标记

    def test_security_tag_covers_only_security_value(self) -> None:
        # ECH 不得被 security tag 一并圈进去（否则颜色会串）
        panel = self._panel()
        panel.append_lines([_entry(ech=True)])
        self.assertEqual(self._tag_slices(panel, "security"), ["TLS1.3/A128GCM"])

    def test_line_layout_is_five_segments_in_order(self) -> None:
        panel = self._panel()
        panel.append_lines([_entry(ech=True, provisional=True)])
        line = panel.text.get("1.0", "1.end")
        self.assertEqual(line, "12:00:00  ech.example  h2  TCP  TLS1.3/A128GCM  ECH?")
        # 五段正文之间共 5 个双空格分隔符（时间戳→域名→应用→传输→安全→ECH）
        self.assertEqual(line.count("  "), 5)
        self.assertLess(line.index("TLS1.3"), line.index(ECH_MARK))
        self.assertLess(line.index(ECH_MARK), line.index("?"))

    def test_entry_snapshot_keeps_flag(self) -> None:
        panel = self._panel()
        panel.append_lines([_entry(ech=True), _entry(ech=False)])
        self.assertEqual([e.ech for e in panel.entries()], [True, False])

    def test_retrim_keeps_ech_tag_on_surviving_lines(self) -> None:
        """超出 MAX_LINES 触发行裁剪后，存活行仍能正常渲染（不崩、tag 可读）。

        裁剪从头部删除 ``total - MAX_LINES`` 行，被删行上的 tag 随文本一起
        消失，因此存活标记数 = 未被裁剪的偶数下标行数。
        """
        from snitap.gui.log_panel import MAX_LINES

        total = MAX_LINES + 10
        excess = total - MAX_LINES
        panel = self._panel()
        panel.append_lines(
            [_entry(domain=f"h{i}.example", ech=(i % 2 == 0)) for i in range(total)]
        )
        self.assertEqual(panel.line_count, MAX_LINES)
        expected = len([i for i in range(excess, total) if i % 2 == 0])
        self.assertEqual(len(self._tag_slices(panel, "ech")), expected)
        # 存活行上的 tag 仍然精确覆盖 ECH 三字符
        self.assertTrue(all(s == ECH_MARK for s in self._tag_slices(panel, "ech")[:20]))


class StatsTableEchRenderTest(_TkTestCase):
    """风险点 6：``has_ech`` 行只显示一处 ECH，但数据不丢。"""

    def _table(self) -> StatsTable:
        table = StatsTable(self.root, self.font, self.header_font)
        table.pack(fill="both", expand=True)
        self.root.update()
        if table.canvas.winfo_width() <= 1:
            self.skipTest("画布未完成布局，跳过绘制断言")
        return table

    def _texts(self, table: StatsTable) -> list[tuple[str, str]]:
        """画布上全部文本项及其填充色。"""
        return [
            (table.canvas.itemcget(item, "text"), table.canvas.itemcget(item, "fill"))
            for item in table.canvas.find_all()
            if table.canvas.type(item) == "text"
        ]

    def test_ech_row_draws_exactly_one_mark(self) -> None:
        table = self._table()
        table.set_rows([StackRow("ech.example", "h2", "TCP", f"TLS1.3/A128GCM{_ECH_TAG}", 5)])
        self.root.update()
        texts = [text for text, _ in self._texts(table)]
        self.assertEqual(texts.count(ECH_MARK), 1)
        # 单行布局：安全层单独成段（不带 `` ECH`` 后缀），标记是独立一段
        self.assertIn("TLS1.3/A128GCM", texts)
        self.assertNotIn(f"TLS1.3/A128GCM{_ECH_TAG}", texts)
        self.assertFalse([text for text in texts if "·" in text])  # 不再有摘要行

    def test_mark_sits_right_after_security_on_same_line(self) -> None:
        table = self._table()
        table.set_rows([StackRow("ech.example", "h2", "TCP", f"TLS1.3/A128GCM{_ECH_TAG}", 5)])
        self.root.update()
        positions: dict[str, tuple[float, float]] = {}
        for item in table.canvas.find_all():
            if table.canvas.type(item) != "text":
                continue
            text = table.canvas.itemcget(item, "text")
            positions.setdefault(text, table.canvas.coords(item))
        self.assertIn(ECH_MARK, positions)
        self.assertIn("TLS1.3/A128GCM", positions)
        self.assertIn("ech.example", positions)
        mark_x, mark_y = positions[ECH_MARK]
        sec_x, sec_y = positions["TLS1.3/A128GCM"]
        dom_x, dom_y = positions["ech.example"]
        self.assertAlmostEqual(mark_y, sec_y, delta=1.0)  # 与安全层同一行
        self.assertAlmostEqual(mark_y, dom_y, delta=1.0)  # 与域名同一行（单行布局）
        self.assertGreater(mark_x, sec_x)                 # ECH 跟在 TLS 版本后面
        self.assertGreater(sec_x, dom_x)                  # 协议栈在域名右侧

    def test_non_ech_row_has_no_mark(self) -> None:
        table = self._table()
        table.set_rows([StackRow("plain.example", "h2", "TCP", "TLS1.3/A128GCM", 3)])
        self.root.update()
        texts = [text for text, _ in self._texts(table)]
        self.assertNotIn(ECH_MARK, texts)
        self.assertIn("TLS1.3/A128GCM", texts)

    def test_mixed_rows_only_ech_row_marked(self) -> None:
        table = self._table()
        table.set_rows(
            [
                StackRow("a.example", "h2", "TCP", f"TLS1.3/A128GCM{_ECH_TAG}", 5),
                StackRow("b.example", "h2", "TCP", "TLS1.3/A128GCM", 3),
            ]
        )
        self.root.update()
        texts = [text for text, _ in self._texts(table)]
        self.assertEqual(texts.count(ECH_MARK), 1)

    def test_copy_row_tsv_keeps_ech_suffix(self) -> None:
        # 「显示去重、数据不丢」：TSV 必须仍带 `` ECH``
        table = self._table()
        row = StackRow("ech.example", "h2", "TCP", f"TLS1.3/A128GCM{_ECH_TAG}", 5)
        table.set_rows([row])
        self.root.update()
        table.copy_row(0)
        try:
            payload = self.root.clipboard_get()
        except tk.TclError:  # 极少数环境无剪贴板
            self.skipTest("剪贴板不可用，跳过 TSV 断言")
        self.assertEqual(payload, "ech.example\tTCP\th2\tTLS1.3/A128GCM ECH")
        self.assertIn(_ECH_TAG, payload)

    def test_security_without_ech_strips_only_trailing_mark(self) -> None:
        # 只剥尾部后缀，不动正文里可能出现的 ECH 字样
        strip = StatsTable._security_without_ech
        self.assertEqual(strip(f"TLS1.3/A128GCM{_ECH_TAG}"), "TLS1.3/A128GCM")
        self.assertEqual(strip("TLS1.3/A128GCM"), "TLS1.3/A128GCM")
        self.assertEqual(strip("ECH"), "ECH")
        self.assertEqual(strip(f"-{_ECH_TAG}"), "-")

    def test_has_ech_detection_matches_stack_row(self) -> None:
        self.assertTrue(StackRow("a", "b", "c", f"x{_ECH_TAG}", 1).has_ech)
        self.assertFalse(StackRow("a", "b", "c", "x", 1).has_ech)
        # 域名里含 ECH 不算
        self.assertFalse(StackRow("ECH", "b", "c", "x", 1).has_ech)


class MainWindowEchWindowTest(unittest.TestCase):
    """整窗层面的 ECH 语义：footer 双计数段 + 日志侧只按 ``stack.ech`` 标记。

    每个用例自建离屏 Tk 根窗口（``create_root`` 先开 DPI 感知），
    ``_on_close`` 负责撤销窗口自己的两个 ``after`` 定时器。
    """

    def setUp(self) -> None:
        if not TK_OK:
            raise unittest.SkipTest("Tk 不可用（无图形环境），跳过 GUI 用例")
        from snitap.gui.main_window import MainWindow, create_root

        self.root = create_root()
        self.root.geometry("640x460+3000+3000")
        self.window = MainWindow(self.root)

    def tearDown(self) -> None:
        self.window._on_close()

    def _stats(self, **kwargs: int) -> None:
        from snitap.events import StatsEvent

        base = dict(tcp_conns=0, udp_sessions=0, total_hits=0, distinct=0)
        base.update(kwargs)
        self.window._apply_stats(
            StatsEvent(ts="00:00:00", rows=(), **base)  # type: ignore[arg-type]
        )

    def test_footer_without_ech(self) -> None:
        self._stats(total_hits=4, distinct=2)
        self.assertEqual(self.window.lbl_total.cget("text"), "total 4 · 2 组")

    def test_footer_confirmed_only(self) -> None:
        self._stats(total_hits=4, distinct=2, ech_hits=2, ech_ext_hits=2)
        self.assertEqual(self.window.lbl_total.cget("text"), "total 4 · 2 组 · ech 2")

    def test_footer_appends_suspected_grease_after_ech(self) -> None:
        # 顺序固定：total → 组数 → ech → ech?
        self._stats(total_hits=5, distinct=2, ech_hits=1, ech_ext_hits=3)
        self.assertEqual(
            self.window.lbl_total.cget("text"), "total 5 · 2 组 · ech 1 · ech? 2"
        )

    def test_footer_grease_only_has_no_ech_segment(self) -> None:
        # ech_hits == 0 时不出现 `ech K`，只出现 `ech? X`
        self._stats(total_hits=3, distinct=1, ech_hits=0, ech_ext_hits=3)
        self.assertEqual(self.window.lbl_total.cget("text"), "total 3 · 1 组 · ech? 3")

    def test_footer_truncated_comes_last(self) -> None:
        from snitap.events import StatsEvent

        self.window._apply_stats(
            StatsEvent(
                ts="00:00:00",
                rows=(),
                tcp_conns=0,
                udp_sessions=0,
                total_hits=9,
                distinct=400,
                truncated=True,
                ech_hits=1,
                ech_ext_hits=4,
            )
        )
        text = self.window.lbl_total.cget("text")
        self.assertTrue(text.endswith("· 仅显示前 300 组"))
        self.assertLess(text.index("· ech 1"), text.index("· ech? 3"))

    def _drain_one_stack(self, stack: "object") -> str:
        from snitap.events import StackEvent

        self.window._worker.events.put(StackEvent(ts="12:00:00", stack=stack))  # type: ignore[arg-type]
        self.window._drain_events()
        return self.window.log_panel.text.get("1.0", "end")

    def test_log_marks_confirmed_ech_only(self) -> None:
        from snitap.protocol import ProtocolStack

        confirmed = ProtocolStack(
            sni="cloudflare-ech.com",
            tls_version="TLS1.3",
            cipher="A128GCM",
            alpn="h2",
            ech=True,
            ech_ext=True,
        )
        self.assertIn(f"  {ECH_MARK}", self._drain_one_stack(confirmed))

    def test_log_does_not_mark_grease_stack(self) -> None:
        from snitap.protocol import ProtocolStack

        grease = ProtocolStack(
            sni="test.cmliussss.dpdns.org",
            tls_version="TLS1.3",
            cipher="A128GCM",
            alpn="h2",
            ech=False,
            ech_ext=True,
        )
        text = self._drain_one_stack(grease)
        self.assertNotIn(ECH_MARK, text)
        self.assertIn("test.cmliussss.dpdns.org", text)


if __name__ == "__main__":
    unittest.main()
