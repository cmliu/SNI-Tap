"""QA 独立复核：ECH 标记语义收紧（GREASE ECH 不再打标）。

本文件是**第二双眼睛**，刻意不复用工程师的夹具
（``test_tls_sniffer.build_client_hello``），ClientHello 字节全部由本文件的
``client_hello()`` 自建：random 填充、GREASE 套件前置、**ECH 扩展放在扩展区
首位**（工程师夹具放在末位），以免「夹具口径相同」掩盖解析顺序缺陷。

覆盖的 8 个风险点（对应任务书章节）：

1. ``SNITAP_ECH_PUBLIC_NAMES`` 覆盖：真 ``importlib.reload(snitap.config)``，
   并**穿透到 ``flow`` 已绑定的函数对象**（§1）；
2. 判定边界矩阵：尾点 / 大小写 / 空白 / 相似域名 / 子域 / 空 / None /
   非字符串 / 超长（§2）；
3. 位置参数契约：``StatsEvent`` 第 7/8 位、``ProtocolStack`` 8~12 位（§3）；
4. GUI footer 四种组合 + 与截断说明的顺序（§4）；
5. 用户场景端到端：原始字节 → ``TcpFlow`` → ``Stats`` → 真实 Tk 日志（§5）；
6. 未命中零影响回归，含「顺序不可颠倒」（§6）；
7. 异常面：``is_ech_public_name`` 不抛、``_merge`` 的 SNI 缺失畸形包不抛（§7）；
8. 文档：``ARCHITECTURE.md`` 前 364 行逐字节不变 + README 无越界表述（§8）；
9. 资产保全：上一轮测试用例数只增不减（§9）。

背景（RFC 9849 §6.2 / §10.10.4）：无 ECHConfig 的客户端 SHOULD 发 GREASE ECH，
且真 ECH 与 GREASE 对被动观察者在设计上不可区分；唯一可用判据是外层 SNI 是否
为 ECHConfig 的 ``public_name``（Cloudflare = ``cloudflare-ech.com``）。
"""

from __future__ import annotations

import importlib
import os
import pathlib
import shutil
import subprocess
import sys
import tkinter as tk
import tkinter.font as tkfont
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests"))

from snitap import config
from snitap.events import StatsEvent
from snitap.flow import TcpFlow, _merge
from snitap.protocol import ECH_MARK, LayerSource, ProtocolStack, StackRow
from snitap.stats import Stats
from snitap.tls_sniffer import CLIENT, SERVER, HelloInfo

ENV_NAME = "SNITAP_ECH_PUBLIC_NAMES"
DEFAULT_NAMES = ("cloudflare-ech.com",)
PUBLIC_NAME = "cloudflare-ech.com"
REAL_DOMAIN = "test.cmliussss.dpdns.org"

# 扩展号与套件（本文件自带常量，不 import 源码私有常量）
EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ECH = 0xFE0D
GREASE_CIPHER = 0x0A0A
TLS_AES_128_GCM = 0x1301


# --------------------------------------------------------------------- 自建夹具


def _ext(ext_type: int, data: bytes) -> bytes:
    """拼一个 ``type(2) + len(2) + data`` 的扩展。"""
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _ext_sni(host: str) -> bytes:
    name = host.encode("ascii")
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    return _ext(EXT_SNI, len(entry).to_bytes(2, "big") + entry)


def _ext_alpn(proto: bytes = b"h2") -> bytes:
    item = bytes([len(proto)]) + proto
    return _ext(EXT_ALPN, len(item).to_bytes(2, "big") + item)


def _ext_supported_versions(version: int = 0x0304) -> bytes:
    return _ext(EXT_SUPPORTED_VERSIONS, b"\x02" + version.to_bytes(2, "big"))


def grease_ech_body(seed: int = 0x5A) -> bytes:
    """伪造形状合法的 GREASE ECH 扩展体（RFC 9849 §6.2 描述的结构）。

    结构：``cipher_suite(4) || config_id(1) || enc(32) || payload_len(2) || payload``，
    全部填随机样式的假字节——嗅探器一旦尝试解析内部字段就会在随机长度上炸掉。
    """
    payload_len = 0x40 + (seed & 0x0F)
    return (
        b"\x00\x20"                     # KDF id (HKDF-SHA256)
        + b"\x00\x01"                   # AEAD id (AES-128-GCM)
        + bytes([seed & 0xFF])          # config_id（随机）
        + bytes(((seed * (i + 3)) & 0xFF) for i in range(32))  # enc（伪装 KEM 输出）
        + payload_len.to_bytes(2, "big")
        + bytes(((seed + i * 7) & 0xFF) for i in range(payload_len))
    )


def client_hello(host: str | None, *, ech: bytes | None = None) -> bytes:
    """构造一个 TLS 记录包裹的 ClientHello。

    Args:
        host: SNI 主机名；``None`` 表示**不带 SNI 扩展**（畸形/隐私客户端场景）。
        ech: ``0xFE0D`` 扩展体；``None`` 表示完全不发该扩展。给定值时**放在扩展区
            首位**（与工程师夹具的末位相反，用于验证解析与顺序无关）。
    """
    exts = b""
    if ech is not None:
        exts += _ext(EXT_ECH, ech)
    if host is not None:
        exts += _ext_sni(host)
    exts += _ext_alpn(b"h2")
    exts += _ext_supported_versions(0x0304)
    body = (
        b"\x03\x03"                              # legacy_version
        + bytes([0xA5]) * 32                     # random（与共享夹具不同）
        + b"\x20" + bytes([0x11]) * 32           # legacy_session_id(32)
        + b"\x00\x04" + b"\x0a\x0a\x13\x01"      # GREASE 套件 + TLS_AES_128_GCM
        + b"\x01\x00"                            # compression_methods
        + len(exts).to_bytes(2, "big") + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def stack_from_bytes(host: str | None, *, ech: bytes | None = None) -> ProtocolStack:
    """原始字节 → ``TcpFlow`` → ``ProtocolStack``（只喂客户端方向）。"""
    stacks: list[ProtocolStack] = []
    flow = TcpFlow(stacks.append)
    sink = flow.sink("up")
    assert sink is not None
    sink(client_hello(host, ech=ech))
    flow.close()
    if len(stacks) != 1:
        raise AssertionError(f"期望恰好上报 1 条协议栈，实际 {len(stacks)} 条")
    return stacks[0]


def expected_names_from_env(raw: str | None) -> tuple[str, ...]:
    """独立复算「环境变量 → 名单」的期望值（不复用源码的私有实现）。"""
    if raw is None:
        return DEFAULT_NAMES
    return tuple(part.strip().lower() for part in raw.split(",") if part.strip())


# ---------------------------------------------------------------- 配置隔离基类


class _ConfigIsolatedCase(unittest.TestCase):
    """把 ``snitap.config`` 隔离到「环境变量未设置 + 默认名单」的基线。

    ``setUp`` 先落基线，``tearDown`` 复原调用者的环境变量并再次 reload，
    最后自检复原结果，保证不把名单泄漏给其它测试模块。
    """

    def setUp(self) -> None:
        self._saved = os.environ.get(ENV_NAME)
        os.environ.pop(ENV_NAME, None)
        importlib.reload(config)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(ENV_NAME, None)
        else:
            os.environ[ENV_NAME] = self._saved
        importlib.reload(config)
        self.assertEqual(config.ECH_PUBLIC_NAMES, expected_names_from_env(self._saved))

    def reload_with(self, raw: str) -> None:
        """设置环境变量并真正 reload ``snitap.config``。"""
        os.environ[ENV_NAME] = raw
        importlib.reload(config)


# ---------------------------------------------------------- §1 环境变量覆盖路径


class EnvOverrideReloadTest(_ConfigIsolatedCase):
    """§1：``SNITAP_ECH_PUBLIC_NAMES`` 必须走真 reload 并穿透到 ``flow``。"""

    def test_baseline_without_env_is_default(self) -> None:
        self.assertEqual(config.ECH_PUBLIC_NAMES, DEFAULT_NAMES)
        self.assertTrue(config.is_ech_public_name(PUBLIC_NAME))

    def test_multi_value_with_spaces_and_mixed_case(self) -> None:
        self.reload_with("  ECH.Example.NET ,, CloudFlare-ECH.com , evil.example ")
        self.assertEqual(
            config.ECH_PUBLIC_NAMES,
            ("ech.example.net", "cloudflare-ech.com", "evil.example"),
        )
        for hit in ("ech.example.net", "ECH.EXAMPLE.NET", "  Cloudflare-Ech.Com\t", "evil.example"):
            with self.subTest(sni=hit):
                self.assertTrue(config.is_ech_public_name(hit))

    def test_override_replaces_default_entirely(self) -> None:
        self.reload_with("my-ech.example")
        self.assertEqual(config.ECH_PUBLIC_NAMES, ("my-ech.example",))
        self.assertTrue(config.is_ech_public_name("MY-ech.example"))
        self.assertFalse(config.is_ech_public_name(PUBLIC_NAME))

    def test_override_reaches_flow_already_bound_function(self) -> None:
        """``flow`` 在 import 时已 ``from .config import is_ech_public_name``。

        reload 复用同一个模块 ``__dict__``，故 flow 手里的旧函数对象也能看到新
        名单——这是「环境变量覆盖对真实嗅探路径生效」的关键前提。
        """
        self.reload_with("my-ech.example")
        self.assertTrue(config.ECH_PUBLIC_NAMES == ("my-ech.example",))

        # 新名单内的域名 + 扩展 → 确证
        hit = stack_from_bytes("my-ech.example", ech=grease_ech_body())
        self.assertTrue(hit.ech_ext)
        self.assertTrue(hit.ech)
        self.assertEqual(hit.security_label, "TLS1.3/A128GCM ECH")

        # 默认名单里的域名 + 扩展 → 已被显式覆盖，退回 GREASE 处理
        miss = stack_from_bytes(PUBLIC_NAME, ech=grease_ech_body())
        self.assertTrue(miss.ech_ext)
        self.assertFalse(miss.ech)
        self.assertEqual(miss.security_label, "TLS1.3/A128GCM")

    def test_empty_string_disables_marking_even_for_real_ech(self) -> None:
        """空串 = 关闭标记：连真 ECH 形态（掩护域名 + 扩展）也判 False。"""
        for raw in ("", "   ", ",", " , , ", "\t,\n"):
            with self.subTest(raw=raw):
                self.reload_with(raw)
                self.assertEqual(config.ECH_PUBLIC_NAMES, ())
                self.assertFalse(config.is_ech_public_name(PUBLIC_NAME))
                stack = stack_from_bytes(PUBLIC_NAME, ech=grease_ech_body())
                self.assertTrue(stack.ech_ext)   # 原始观测保留
                self.assertFalse(stack.ech)      # 标记关闭
                self.assertEqual(stack.ech_mark, "")
                self.assertEqual(stack.security_label, "TLS1.3/A128GCM")

    def test_illegal_values_never_crash(self) -> None:
        """非法 / 畸形环境变量不应崩，只是「不命中」。

        注：``os.environ`` 本身拒绝 NUL 与超过 32767 字符的值，故「超长」取
        32000 字符（仍远超任何域名长度），不对 OS 层限制做断言。
        """
        illegal = (
            "<script>alert(1)</script>",
            "cloudflare-ech.com; rm -rf /",
            "*",
            ".",
            "..",
            "cloudflare-ech.com,cloudflare-ech.com",   # 重复项：退化为单值语义
            "例え.jp, é.example",                       # 非 ASCII
            "a" * 32000,                                # 超长（OS 上限内）
            "line1\nline2",
            " " * 100,
            "==",
            "-",
        )
        for raw in illegal:
            with self.subTest(raw=raw[:20]):
                self.reload_with(raw)
                self.assertIsInstance(config.ECH_PUBLIC_NAMES, tuple)
                self.assertTrue(
                    all(name == name.strip().lower() for name in config.ECH_PUBLIC_NAMES)
                )
                # 判定函数在畸形名单下仍必须返回纯 bool、不抛
                for probe in (PUBLIC_NAME, "", None, 1, b"x", object()):
                    self.assertIsInstance(config.is_ech_public_name(probe), bool)

    def test_duplicate_entries_collapse_via_exact_membership(self) -> None:
        self.reload_with("cloudflare-ech.com,CLOUDFLARE-ECH.COM")
        self.assertEqual(
            config.ECH_PUBLIC_NAMES, ("cloudflare-ech.com", "cloudflare-ech.com")
        )
        # 精确匹配（in 元组），重复项不影响判定结果
        self.assertTrue(config.is_ech_public_name("cloudflare-ech.com"))

    def test_teardown_restores_default(self) -> None:
        # tearDown 会再断言一次；此处显式确认样本用例不会污染后继用例
        self.assertEqual(config.ECH_PUBLIC_NAMES, DEFAULT_NAMES)


# --------------------------------------------------------------- §2 判定边界


class BoundaryMatrixTest(_ConfigIsolatedCase):
    """§2：逐条给出「预期 → 实测」，覆盖率敏感边界。"""

    def _assert_matrix(self, expectations: dict[str, bool]) -> None:
        for sni, expected in expectations.items():
            with self.subTest(sni=sni):
                actual = config.is_ech_public_name(sni)
                self.assertIs(actual, expected, f"sni={sni!r} 期望 {expected}，实测 {actual}")

    def test_default_list_boundaries(self) -> None:
        self._assert_matrix(
            {
                PUBLIC_NAME: True,
                "CLOUDFLARE-ECH.COM": True,
                "CloudFlare-Ech.Com": True,
                " cloudflare-ech.com ": True,
                "\tcloudflare-ech.com\r\n": True,
                # 全角空格属于 Unicode 空白，str.strip() 同样会去掉
                "\u3000cloudflare-ech.com": True,
                # DNS 绝对名（尾点）：精确匹配下**不命中**，见下方说明
                "cloudflare-ech.com.": False,
                "CloudFlare-Ech.Com.": False,
                # 相似 / 伪装域名一律不命中（防冒充）
                "cloudflare-ech.com.evil.tld": False,
                "evil-cloudflare-ech.com": False,
                "xcloudflare-ech.com": False,
                "cloudflare-ech.co": False,
                "cloudflare-ech": False,
                "cloudflare-ech.com:443": False,
                # 子域不命中：名单是精确匹配，不做后缀展开
                "sub.cloudflare-ech.com": False,
                "a.b.cloudflare-ech.com": False,
                # 零宽字符不被 strip 去掉 → 不命中
                "\u200bcloudflare-ech.com": False,
                # 空 / 真实域名
                "": False,
                "   ": False,
                "cloudflare-ech.com\t": True,
                REAL_DOMAIN: False,
                "cf.090227.xyz": False,
            }
        )

    def test_trailing_dot_is_not_matched_p3_note(self) -> None:
        """尾点形式：现状不命中，判定为 **P3 文档性**问题而非功能缺陷。

        依据：RFC 6066 §3 规定 SNI 的 ``host_name`` 是「ASCII 编码、**不带尾点**」
        的主机名，合规客户端不会发送 ``cloudflare-ech.com.``；被动嗅探路径上拿到
        的 SNI 一定来自客户端原始字节，因此该形态**不可达**。
        本用例把「不命中」固化为期望，避免后续有人误改成后缀匹配而放宽冒充面。
        """
        self.assertFalse(config.is_ech_public_name("cloudflare-ech.com."))
        # 若将来要支持，必须显式加「去尾点」归一化，且不能退化为后缀匹配
        self.assertFalse(config.is_ech_public_name("evil.cloudflare-ech.com."))

    def test_non_string_inputs_are_false_and_never_raise(self) -> None:
        class _Weird:
            def __str__(self) -> str:
                return PUBLIC_NAME

        probes = (
            None,
            b"cloudflare-ech.com",
            bytearray(b"cloudflare-ech.com"),
            0,
            -1,
            3.14,
            True,
            object(),
            _Weird(),
            ["cloudflare-ech.com"],
            {"cloudflare-ech.com"},
            ("cloudflare-ech.com",),
        )
        for probe in probes:
            with self.subTest(probe=type(probe).__name__):
                self.assertIs(config.is_ech_public_name(probe), False)

    def test_overlong_string_is_false(self) -> None:
        for sni in ("a" * 100000, PUBLIC_NAME + "a" * 65536, "a" * 255):
            with self.subTest(length=len(sni)):
                self.assertIs(config.is_ech_public_name(sni), False)

    def test_str_subclass_is_matched(self) -> None:
        class _Host(str):
            pass

        self.assertIs(config.is_ech_public_name(_Host(PUBLIC_NAME)), True)


# ------------------------------------------------------- §3 位置参数向后兼容


class PositionalContractTest(unittest.TestCase):
    """§3：新增字段只能追加在末尾，既有位置参数不得被顶掉。"""

    def test_stats_event_seven_positional_keeps_truncated(self) -> None:
        event = StatsEvent("00:00:01", (), 1, 2, 3, 4, True)
        self.assertTrue(event.truncated)
        self.assertEqual(event.ech_hits, 0)
        self.assertEqual(event.ech_ext_hits, 0)

    def test_stats_event_eighth_positional_is_ech_hits(self) -> None:
        """实测契约：7=truncated、8=ech_hits、9=ech_ext_hits。

        （历史备注：``src/snitap/events.py`` 的 ``ech_ext_hits`` 注释与
        ``test_stats.py::test_eighth_positional_is_ech_ext_hits`` 的用例名曾双双
        偏一位，现已修正为「第 9 个位置参数」与
        ``test_ninth_positional_is_ech_ext_hits``；本用例按实测契约固化。）
        """
        eight = StatsEvent("00:00:02", (), 1, 2, 3, 4, True, 7)
        self.assertTrue(eight.truncated)         # 第 7 位仍是 truncated
        self.assertEqual(eight.ech_hits, 7)      # 第 8 位是 ech_hits
        self.assertEqual(eight.ech_ext_hits, 0)
        self.assertEqual(eight.total_hits, 3)
        self.assertEqual(eight.distinct, 4)

    def test_stats_event_ninth_positional_is_ech_ext_hits(self) -> None:
        event = StatsEvent("00:00:03", (), 1, 2, 3, 4, True, 7, 9)
        self.assertTrue(event.truncated)
        self.assertEqual(event.ech_hits, 7)
        self.assertEqual(event.ech_ext_hits, 9)

    def test_stats_event_field_tail_order(self) -> None:
        import dataclasses

        names = [f.name for f in dataclasses.fields(StatsEvent)]
        self.assertEqual(names[-3:], ["truncated", "ech_hits", "ech_ext_hits"])

    def test_protocol_stack_eight_positional_untouched(self) -> None:
        """8 个位置参数对应 sni..alpn，两个 ECH 字段保持默认 False。"""
        stack = ProtocolStack(
            "d.example", "QUIC", "v1", "TLS1.3",
            LayerSource.CLIENT, "A128GCM", LayerSource.CLIENT, "h2",
        )
        self.assertEqual(stack.sni, "d.example")
        self.assertEqual(stack.alpn, "h2")
        self.assertFalse(stack.provisional)
        self.assertFalse(stack.ech)
        self.assertFalse(stack.ech_ext)
        self.assertEqual(stack.key, ("d.example", "h2", "QUIC/v1", "TLS1.3/A128GCM"))

    def test_protocol_stack_ten_positional_still_provisional(self) -> None:
        """10 个位置参数的末位必须仍是 ``provisional``（既有最后一个字段）。"""
        stack = ProtocolStack(
            "d.example", "TCP", "-", "TLS1.3",
            LayerSource.CLIENT, "A128GCM", LayerSource.CLIENT,
            "h2", LayerSource.CLIENT, True,
        )
        self.assertTrue(stack.provisional)
        self.assertFalse(stack.ech)
        self.assertFalse(stack.ech_ext)
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM")

    def test_protocol_stack_eleventh_and_twelfth_are_ech_then_ext(self) -> None:
        base = (
            "d.example", "TCP", "-", "TLS1.3",
            LayerSource.CLIENT, "A128GCM", LayerSource.CLIENT,
            "h2", LayerSource.CLIENT, True,
        )
        ech_only = ProtocolStack(*base, True)
        self.assertTrue(ech_only.ech)
        self.assertFalse(ech_only.ech_ext)
        self.assertTrue(ech_only.provisional)       # 既有字段未被挤动
        self.assertEqual(ech_only.alpn, "h2")

        both = ProtocolStack(*base, True, True)
        self.assertTrue(both.ech)
        self.assertTrue(both.ech_ext)
        self.assertTrue(both.provisional)
        self.assertEqual(both.security_label, "TLS1.3/A128GCM ECH")

    def test_protocol_stack_tail_field_order(self) -> None:
        import dataclasses

        names = [f.name for f in dataclasses.fields(ProtocolStack)]
        self.assertEqual(names[-3:], ["provisional", "ech", "ech_ext"])


# ---------------------------------------------------------------- Tk 可用性探测


def _tk_available() -> bool:
    try:
        root = tk.Tk()
    except tk.TclError:
        return False
    root.destroy()
    return True


TK_OK = _tk_available()


# -------------------------------------------------------------- §4 footer 组合


class FooterCombinationTest(unittest.TestCase):
    """§4：``total N · M 组 [· ech K] [· ech? X] [· 仅显示前 300 组]``。"""

    def setUp(self) -> None:
        if not TK_OK:
            raise unittest.SkipTest("Tk 不可用（无图形环境），跳过 footer 用例")
        from snitap.gui.main_window import MainWindow, create_root

        self.root = create_root()
        self.root.geometry("640x460+3000+3000")
        self.window = MainWindow(self.root)

    def tearDown(self) -> None:
        self.window._on_close()

    def _footer(self, **kwargs: object) -> str:
        base: dict[str, object] = dict(
            tcp_conns=0, udp_sessions=0, total_hits=0, distinct=0,
        )
        base.update(kwargs)
        event = StatsEvent(ts="00:00:00", rows=(), **base)  # type: ignore[arg-type]
        self.window._apply_stats(event)
        return self.window.lbl_total.cget("text")

    def test_combo_none(self) -> None:
        text = self._footer(total_hits=6, distinct=3, ech_hits=0, ech_ext_hits=0)
        self.assertEqual(text, "total 6 · 3 组")
        self.assertNotIn("ech", text)

    def test_combo_confirmed_only(self) -> None:
        text = self._footer(total_hits=6, distinct=3, ech_hits=1, ech_ext_hits=1)
        self.assertEqual(text, "total 6 · 3 组 · ech 1")
        self.assertNotIn("ech?", text)

    def test_combo_mixed(self) -> None:
        text = self._footer(total_hits=6, distinct=3, ech_hits=1, ech_ext_hits=3)
        self.assertEqual(text, "total 6 · 3 组 · ech 1 · ech? 2")

    def test_combo_grease_only_never_shows_ech_zero(self) -> None:
        text = self._footer(total_hits=6, distinct=3, ech_hits=0, ech_ext_hits=2)
        self.assertEqual(text, "total 6 · 3 组 · ech? 2")
        self.assertNotIn("ech 0", text)
        self.assertNotIn("ech? 0", text)

    def test_truncation_note_stays_last(self) -> None:
        text = self._footer(
            total_hits=9, distinct=400, ech_hits=2, ech_ext_hits=5, truncated=True,
        )
        self.assertEqual(
            text, "total 9 · 400 组 · ech 2 · ech? 3 · 仅显示前 300 组"
        )
        self.assertLess(text.index("· ech 2"), text.index("· ech? 3"))
        self.assertTrue(text.endswith("· 仅显示前 300 组"))

    def test_default_field_omission_behaves_like_zero(self) -> None:
        # 老式 7 参构造（不传 ECH 计数）→ 不应凭空出现 ech 段
        self.window._apply_stats(
            StatsEvent(ts="00:00:00", rows=(), tcp_conns=0, udp_sessions=0,
                       total_hits=2, distinct=1, truncated=False)
        )
        self.assertEqual(self.window.lbl_total.cget("text"), "total 2 · 1 组")


# ----------------------------------------------------- §5 用户场景端到端验收


class UserScenarioEndToEndTest(_ConfigIsolatedCase):
    """§5：原始字节 → TcpFlow → Stats → 真实 Tk 日志。

    同一会话里同时出现「用户真实域名（已关 ECH，仍带扩展）」与「掩护域名
    （带扩展）」时，**只有后者**允许出现 ``ECH`` 文本。
    """

    def _build_stats(self) -> tuple[Stats, ProtocolStack, ProtocolStack]:
        grease = stack_from_bytes(REAL_DOMAIN, ech=grease_ech_body(0x11))
        confirmed = stack_from_bytes(PUBLIC_NAME, ech=grease_ech_body(0x22))
        stats = Stats()
        stats.add_stack(grease)
        stats.add_stack(confirmed)
        return stats, grease, confirmed

    def test_stack_level_split(self) -> None:
        _stats, grease, confirmed = self._build_stats()

        self.assertEqual(grease.domain, REAL_DOMAIN)
        self.assertTrue(grease.ech_ext)
        self.assertFalse(grease.ech)
        self.assertEqual(grease.security_label, "TLS1.3/A128GCM")
        self.assertEqual(grease.ech_mark, "")

        self.assertEqual(confirmed.domain, PUBLIC_NAME)
        self.assertTrue(confirmed.ech_ext)
        self.assertTrue(confirmed.ech)
        self.assertEqual(confirmed.security_label, "TLS1.3/A128GCM ECH")

    def test_stats_counters_and_rows(self) -> None:
        stats, _grease, _confirmed = self._build_stats()
        self.assertEqual(stats.total_hits, 2)
        self.assertEqual(stats.distinct, 2)
        self.assertEqual(stats.ech_hits, 1)
        self.assertEqual(stats.ech_ext_hits, 2)

        rows = stats.snapshot_rows()
        self.assertEqual(len(rows), 2)
        by_domain = {row.domain: row for row in rows}
        self.assertTrue(by_domain[PUBLIC_NAME].has_ech)
        self.assertFalse(by_domain[REAL_DOMAIN].has_ech)
        self.assertEqual(by_domain[PUBLIC_NAME].security, "TLS1.3/A128GCM ECH")
        self.assertEqual(by_domain[REAL_DOMAIN].security, "TLS1.3/A128GCM")

    def test_rendered_log_marks_only_confirmed(self) -> None:
        if not TK_OK:
            raise unittest.SkipTest("Tk 不可用（无图形环境），跳过日志渲染断言")
        from snitap.events import StackEvent
        from snitap.gui.main_window import MainWindow, create_root

        _stats, grease, confirmed = self._build_stats()
        root = create_root()
        root.geometry("640x460+3000+3000")
        window = MainWindow(root)
        try:
            for stack in (grease, confirmed):
                window._worker.events.put(StackEvent(ts="12:00:00", stack=stack))
            window._drain_events()

            panel = window.log_panel
            text = panel.text.get("1.0", "end-1c")
            lines = text.splitlines()
            self.assertEqual(len(lines), 2)

            grease_line = next(line for line in lines if REAL_DOMAIN in line)
            confirmed_line = next(line for line in lines if PUBLIC_NAME in line)

            # 1) 真实域名行整体不含 ECH 文本
            self.assertNotIn(ECH_MARK, grease_line)
            # 2) 掩护域名行在安全层之后出现 ECH；整行为客户端偏好 → 行首 ~（行尾不再加 ?）
            self.assertTrue(confirmed_line.endswith(f"  {ECH_MARK}"))
            self.assertTrue(confirmed_line.startswith("~"))
            self.assertNotIn("?", confirmed_line)
            # 3) 全文只出现一次 ECH
            self.assertEqual(text.count(ECH_MARK), 1)

            # 4) security tag 区间只覆盖安全层值，不含 ECH 后缀
            slices = [
                panel.text.get(str(r[0]), str(r[1]))
                for r in zip(*[iter(panel.text.tag_ranges("security"))] * 2)
            ]
            self.assertEqual(slices, ["TLS1.3/A128GCM", "TLS1.3/A128GCM"])
            self.assertTrue(all(ECH_MARK not in s for s in slices))

            # 5) ech tag 恰好覆盖三字符且只有一处
            ech_slices = [
                panel.text.get(str(r[0]), str(r[1]))
                for r in zip(*[iter(panel.text.tag_ranges("ech"))] * 2)
            ]
            self.assertEqual(ech_slices, [ECH_MARK])
        finally:
            window._on_close()

    def test_stats_table_badge_only_on_confirmed_row(self) -> None:
        if not TK_OK:
            raise unittest.SkipTest("Tk 不可用（无图形环境），跳过统计表断言")
        from snitap.gui.stats_table import StatsTable

        stats, _grease, _confirmed = self._build_stats()
        root = tk.Tk()
        root.geometry("640x460+3000+3000")
        try:
            table = StatsTable(
                root, tkfont.Font(family="Consolas", size=9),
                tkfont.Font(family="Segoe UI", size=9),
            )
            table.pack(fill="both", expand=True)
            root.update()
            if table.canvas.winfo_width() <= 1:
                self.skipTest("画布未完成布局")
            table.set_rows(list(stats.snapshot_rows()))
            root.update()
            marks = [
                table.canvas.itemcget(item, "text")
                for item in table.canvas.find_all()
                if table.canvas.type(item) == "text"
                and table.canvas.itemcget(item, "text") == ECH_MARK
            ]
            self.assertEqual(len(marks), 1)  # 两行里只有确证行带徽章
        finally:
            root.destroy()


class _LoopStop(Exception):
    """用于把无限统计循环中断在第二轮（仅测试用）。"""


class WorkerWiringTest(_ConfigIsolatedCase):
    """worker → ``StatsEvent`` → footer 的接线：计数必须在真实装配线上不丢。"""

    def _run_stats_loop_once(self) -> list:
        """让 ``Worker._stats_loop`` 只跑一轮后退出（把 1s 睡眠换掉）。"""
        import asyncio

        from snitap import worker as worker_mod

        calls = {"n": 0}

        async def fake_sleep(_seconds: float) -> None:
            calls["n"] += 1
            if calls["n"] > 1:
                raise _LoopStop

        original = worker_mod.asyncio.sleep
        worker_mod.asyncio.sleep = fake_sleep           # type: ignore[assignment]
        try:
            worker = worker_mod.Worker()
            for stack in self._stacks():
                worker._on_stack(stack)
            with self.assertRaises(_LoopStop):
                asyncio.run(worker._stats_loop())
        finally:
            worker_mod.asyncio.sleep = original         # type: ignore[assignment]

        drained = []
        while not worker.events.empty():
            drained.append(worker.events.get_nowait())
        return [event for event in drained if isinstance(event, StatsEvent)]

    def _stacks(self) -> tuple[ProtocolStack, ProtocolStack]:
        grease = stack_from_bytes(REAL_DOMAIN, ech=grease_ech_body(0x31))
        confirmed = stack_from_bytes(PUBLIC_NAME, ech=grease_ech_body(0x32))
        return grease, confirmed

    def test_worker_emits_both_counters(self) -> None:
        events = self._run_stats_loop_once()
        self.assertEqual(len(events), 1, "一轮循环应恰好发出一条 StatsEvent")
        event = events[0]
        self.assertEqual(event.ech_hits, 1)
        self.assertEqual(event.ech_ext_hits, 2)
        self.assertEqual(event.total_hits, 2)
        self.assertEqual(event.distinct, 2)
        self.assertFalse(event.truncated)
        self.assertTrue(any(row.has_ech for row in event.rows))

    def test_worker_counters_reach_footer(self) -> None:
        if not TK_OK:
            raise unittest.SkipTest("Tk 不可用（无图形环境），跳过 footer 断言")
        from snitap.gui.main_window import MainWindow, create_root

        event = self._run_stats_loop_once()[0]
        root = create_root()
        root.geometry("640x460+3000+3000")
        window = MainWindow(root)
        try:
            window._apply_stats(event)
            self.assertEqual(
                window.lbl_total.cget("text"),
                "total 2 · 2 组 · ech 1 · ech? 1",
            )
        finally:
            window._on_close()


# ------------------------------------------------------ §6 未命中零影响回归


class ZeroImpactRegressionTest(_ConfigIsolatedCase):
    """§6：不带扩展时一切保持 v2 原样，且「顺序不可颠倒」。"""

    def test_no_extension_label_and_key_unchanged(self) -> None:
        stack = stack_from_bytes(REAL_DOMAIN)
        self.assertFalse(stack.ech)
        self.assertFalse(stack.ech_ext)
        self.assertEqual(stack.ech_mark, "")
        self.assertEqual(stack.security_label, stack.security)
        self.assertEqual(stack.security, "TLS1.3/A128GCM")
        self.assertEqual(stack.key, (REAL_DOMAIN, "h2", "TCP", "TLS1.3/A128GCM"))
        self.assertEqual(stack.caption(), "h2 · TCP · TLS1.3/A128GCM")

        row = StackRow.from_stack(stack, 3)
        self.assertFalse(row.has_ech)
        self.assertEqual(row.key, stack.key)
        self.assertEqual(row.caption(), stack.caption())

    def test_public_name_sni_without_extension_is_not_marked(self) -> None:
        """名单命中但**无扩展** → 不标记（``ech = 扩展 ∧ 名单``，顺序不可颠倒）。"""
        stack = stack_from_bytes(PUBLIC_NAME)
        self.assertFalse(stack.ech_ext)
        self.assertFalse(stack.ech)
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM")
        self.assertNotIn(ECH_MARK, stack.caption())

    def test_no_ech_bytes_report_zero_counters(self) -> None:
        stats = Stats()
        stats.add_stack(stack_from_bytes(REAL_DOMAIN))
        stats.add_stack(stack_from_bytes(PUBLIC_NAME))
        self.assertEqual(stats.ech_hits, 0)
        self.assertEqual(stats.ech_ext_hits, 0)
        self.assertEqual(stats.total_hits, 2)
        self.assertTrue(all(not row.has_ech for row in stats.snapshot_rows()))

    def test_mark_authority_is_ech_not_ech_ext(self) -> None:
        """展示层只看 ``ech``：``ech_ext=True, ech=False`` 绝不产生标记。

        反向（``ech=True, ech_ext=False``）在数据模型里不被禁止——``ech`` 是唯一
        权威字段，``ech_ext`` 只喂 footer 的疑似计数，二者语义不可互替。
        """
        ext_only = ProtocolStack(sni=REAL_DOMAIN, tls_version="TLS1.3",
                                 cipher="A128GCM", ech=False, ech_ext=True)
        self.assertEqual(ext_only.security_label, "TLS1.3/A128GCM")
        self.assertEqual(ext_only.ech_mark, "")

        mark_only = ProtocolStack(sni=REAL_DOMAIN, tls_version="TLS1.3",
                                  cipher="A128GCM", ech=True, ech_ext=False)
        self.assertEqual(mark_only.security_label, "TLS1.3/A128GCM ECH")
        self.assertTrue(mark_only.key[3].endswith(f" {ECH_MARK}"))


# ------------------------------------------------------------- §7 异常面


class ExceptionSurfaceTest(_ConfigIsolatedCase):
    """§7：嗅探路径上的函数对畸形输入只许返回 False / 不抛。"""

    def test_merge_with_missing_sni_and_ech_does_not_raise(self) -> None:
        client = HelloInfo(kind=CLIENT, sni=None, ech=True)
        stack = _merge(client, None, transport="TCP", quic_version="-")
        assert stack is not None
        self.assertTrue(stack.ech_ext)
        self.assertFalse(stack.ech)
        self.assertEqual(stack.domain, "-")
        self.assertEqual(stack.security_label, "-")

    def test_merge_with_server_side_ech_only_does_not_mark(self) -> None:
        # 只观测到服务端 HRR 的明文扩展：不参与标记计算（宁漏不错）
        server = HelloInfo(kind=SERVER, sni=None, ech=True)
        stack = _merge(None, server, transport="TCP", quic_version="-")
        assert stack is not None
        self.assertFalse(stack.ech_ext)
        self.assertFalse(stack.ech)

    def test_merge_with_both_directions_ech_and_no_sni(self) -> None:
        client = HelloInfo(kind=CLIENT, sni=None, ech=True)
        server = HelloInfo(kind=SERVER, sni=None, ech=True)
        stack = _merge(client, server, transport="QUIC", quic_version="v1")
        assert stack is not None
        self.assertTrue(stack.ech_ext)
        self.assertFalse(stack.ech)
        self.assertEqual(stack.transport_label, "QUIC/v1")

    def test_merge_both_none_returns_none(self) -> None:
        self.assertIsNone(_merge(None, None, transport="TCP", quic_version="-"))

    def test_client_hello_without_sni_ext_through_flow(self) -> None:
        """无 SNI 扩展但带 ECH 扩展的畸形 / 隐私包：不崩、不标记、domain 为 ``-``。"""
        stack = stack_from_bytes(None, ech=grease_ech_body())
        self.assertTrue(stack.ech_ext)
        self.assertFalse(stack.ech)
        self.assertEqual(stack.domain, "-")
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM")

    def test_is_ech_public_name_never_raises_on_fuzz(self) -> None:
        import random

        rng = random.Random(20261103)
        alphabet = "abcdefghijklmnopqrstuvwxyz.-_ \t\u3000\u200b/:*," + "0123456789"
        probes: list[object] = [None, "", b"", 0, object()]
        for _ in range(200):
            probes.append(
                "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 64)))
            )
        for probe in probes:
            with self.subTest(probe=repr(probe)[:24]):
                self.assertIsInstance(
                    config.is_ech_public_name(probe), bool,  # type: ignore[arg-type]
                )


# --------------------------------------------------------------- §8 文档


_GIT = shutil.which("git")
_DOC = _ROOT / "docs" / "ARCHITECTURE.md"
_README = _ROOT / "README.md"
_LEGACY_REF = "32246c5^:docs/ARCHITECTURE.md"
_LEGACY_LINES = 364


class DocumentationTest(unittest.TestCase):
    """§8：架构文档前缀不得改写，README 不得越界表述。"""

    @unittest.skipUnless(_GIT and _DOC.exists(), "缺少 git 或 docs/ARCHITECTURE.md")
    def test_architecture_prefix_is_byte_identical(self) -> None:
        proc = subprocess.run(
            [_GIT, "show", _LEGACY_REF],
            cwd=str(_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        legacy = proc.stdout
        current = _DOC.read_bytes().splitlines(keepends=True)
        self.assertGreater(len(current), _LEGACY_LINES)
        self.assertEqual(
            b"".join(current[:_LEGACY_LINES]), legacy,
            "ARCHITECTURE.md 前 364 行被改动（v1/v2 定稿部分应保持逐字节不变）",
        )

    @unittest.skipUnless(_DOC.exists(), "缺少 docs/ARCHITECTURE.md")
    def test_architecture_length_not_shrunk(self) -> None:
        lines = _DOC.read_bytes().splitlines()
        self.assertGreaterEqual(len(lines), 556, "v3 章节疑似被删减（原 556 行）")

    @unittest.skipUnless(_README.exists(), "缺少 README.md")
    def test_readme_has_no_service_acceptance_overreach(self) -> None:
        """任何提到「服务端已接受 / ECH 生效已验证」的行必须同时是否定表述。"""
        overreach = ("服务端已", "已接受", "生效已确认", "生效已验证", "已验证生效")
        negations = ("不", "无", "未", "禁止", "杜绝", "不能", "无法")
        offenders: list[str] = []
        for lineno, line in enumerate(
            _README.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if ECH_MARK not in line and "ECH" not in line:
                continue
            if any(phrase in line for phrase in overreach):
                if not any(neg in line for neg in negations):
                    offenders.append(f"README:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [], "README 出现把 ECH 表述为服务端已接受的越界句")

    @unittest.skipUnless(_README.exists(), "缺少 README.md")
    def test_readme_documents_new_semantics(self) -> None:
        text = _README.read_text(encoding="utf-8")
        required = {
            "GREASE": "GREASE ECH 概念",
            "0xFE0D": "扩展号",
            "cloudflare-ech.com": "默认掩护域名",
            "SNITAP_ECH_PUBLIC_NAMES": "环境变量覆盖入口",
            "ech?": "疑似 GREASE 计数段",
            "确证": "确证语义用词",
        }
        missing = [label for token, label in required.items() if token not in text]
        self.assertEqual(missing, [], f"README 缺少新语义要素：{missing}")


# ------------------------------------------------------- §9 上一轮资产保全


class PreviousRoundAssetTest(unittest.TestCase):
    """§9：上一轮的用例只增不减（防止「改测试迁就实现」）。"""

    def _count(self, module_name: str) -> int:
        module = importlib.import_module(module_name)
        return unittest.TestLoader().loadTestsFromModule(module).countTestCases()

    def test_ech_integration_still_has_35_cases(self) -> None:
        self.assertGreaterEqual(self._count("test_ech_integration"), 35)

    def test_gui_ech_still_has_at_least_16_cases(self) -> None:
        self.assertGreaterEqual(self._count("test_gui_ech"), 16)

    def test_ech_public_name_module_present(self) -> None:
        self.assertGreaterEqual(self._count("test_ech_public_name"), 18)


if __name__ == "__main__":
    unittest.main()
