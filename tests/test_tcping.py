"""tcping 对端地址格式化单元测试。

回归护栏：修复「IPv6 对端地址与端口粘连显示」——
修复前 ``f"{peername[0]}:{peername[1]}"`` 会把 IPv6 拼成
``2606:4700:3030::6815:47f9:443``（地址与端口无法切分），
修复后按 RFC 3986 方括号写法输出 ``[2606:4700:3030::6815:47f9]:443``。

同时锁定 **IPv4 场景行为完全不变**（``104.16.132.229:443``，不加括号）。
"""

from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from snitap.config import AppConfig
from snitap.tcping import Tcping, format_host_port, format_peer

# (peername 输入, 期望输出)
PEER_CASES: list[tuple[object, str | None]] = [
    # ---- 空值分支：GUI 侧据此隐藏 peer 片段 ----
    (None, None),
    ((), None),
    ([], None),
    ("", None),
    ("   ", None),
    ((None, 443), None),
    (("", 443), None),
    (("   ", 443), None),
    # ---- IPv4：与修复前完全一致，不额外加括号 ----
    (("104.16.132.229", 443), "104.16.132.229:443"),
    (("1.2.3.4", 80), "1.2.3.4:80"),
    (("127.0.0.1", 1234), "127.0.0.1:1234"),
    # ---- IPv6：asyncio 的 4 元组 (host, port, flowinfo, scope_id) ----
    (("2606:4700:3030::6815:47f9", 443, 0, 0), "[2606:4700:3030::6815:47f9]:443"),
    (("2606:4700:3030::6815:47f9", 443), "[2606:4700:3030::6815:47f9]:443"),
    (("2001:db8::1", 8443, 0, 0), "[2001:db8::1]:8443"),
    (("::1", 443, 0, 0), "[::1]:443"),
    (("::", 443, 0, 0), "[::]:443"),
    (("2001:0db8:0000:0000:0000:0000:0000:0001", 443, 0, 0), "[2001:0db8:0000:0000:0000:0000:0000:0001]:443"),
    # ---- 链路本地 + zone / scope id：zone id 必须保留在方括号内 ----
    (("fe80::1%eth0", 443, 0, 2), "[fe80::1%eth0]:443"),
    (("fe80::1%3", 443, 0, 3), "[fe80::1%3]:443"),
    # ---- host 已被方括号包裹：不得重复加括号 ----
    (("[::1]", 443), "[::1]:443"),
    (("[2001:db8::1]", 8443), "[2001:db8::1]:8443"),
    # ---- IPv4-mapped IPv6：按 IPv6 处理 ----
    (("::ffff:1.2.3.4", 443, 0, 0), "[::ffff:1.2.3.4]:443"),
    # ---- 域名 / 字符串 host：不受影响 ----
    (("cf.090227.xyz", 443), "cf.090227.xyz:443"),
    # ---- 端口省略 ----
    (("::1", None), "[::1]"),
    (("1.2.3.4", None), "1.2.3.4"),
    # ---- peername 直接是字符串：稳健兜底，绝不产出 "::1:443" ----
    ("1.2.3.4:443", "1.2.3.4:443"),
    ("cf.090227.xyz:443", "cf.090227.xyz:443"),
    ("::1", "[::1]"),
    ("2001:db8::1", "[2001:db8::1]"),
    ("fe80::1%eth0", "[fe80::1%eth0]"),
    ("::ffff:1.2.3.4", "[::ffff:1.2.3.4]"),
    ("[::1]", "[::1]"),
    ("[::1]:443", "[::1]:443"),
    ("[fe80::1%eth0]:443", "[fe80::1%eth0]:443"),
    (" host:8443 ", "host:8443"),
]


class FormatPeerTest(unittest.TestCase):
    """format_peer() 行为表：逐条锁定所有分支的输出。"""

    def test_format_peer_cases(self) -> None:
        """覆盖空值 / IPv4 / IPv6 / zone id / 已加括号 / 字符串兜底全部分支。"""
        for peername, expected in PEER_CASES:
            with self.subTest(peername=peername):
                self.assertEqual(format_peer(peername), expected)

    def test_ipv4_output_unchanged(self) -> None:
        """IPv4 场景必须与修复前逐字节一致（不加方括号）。"""
        self.assertEqual(format_peer(("104.16.132.229", 443)), "104.16.132.229:443")

    def test_ipv6_output_uses_brackets(self) -> None:
        """IPv6 场景地址被方括号包裹，端口在括号之后。"""
        text = format_peer(("2606:4700:3030::6815:47f9", 443, 0, 0))
        self.assertEqual(text, "[2606:4700:3030::6815:47f9]:443")
        assert text is not None  # 便于类型检查器收窄
        self.assertTrue(text.startswith("["))
        host, _, port = text.rpartition("]:")
        self.assertEqual(host, "[2606:4700:3030::6815:47f9")
        self.assertEqual(port, "443")

    def test_no_ambiguous_ipv6_concatenation(self) -> None:
        """任何 IPv6 输入都不得产出「地址:端口」粘连的歧义字符串。"""
        ambiguous = [
            "::1:443",
            "2606:4700:3030::6815:47f9:443",
            "fe80::1%eth0:443",
            "::ffff:1.2.3.4:443",
        ]
        inputs: list[object] = [
            ("::1", 443, 0, 0),
            ("2606:4700:3030::6815:47f9", 443, 0, 0),
            ("fe80::1%eth0", 443, 0, 2),
            ("::ffff:1.2.3.4", 443, 0, 0),
            "::1",
            "2606:4700:3030::6815:47f9",
        ]
        for peername in inputs:
            with self.subTest(peername=peername):
                text = format_peer(peername)
                self.assertIsNotNone(text)
                for bad in ambiguous:
                    self.assertNotEqual(text, bad)

    def test_never_raises_for_odd_input(self) -> None:
        """纯函数对任意输入都不抛异常（位于探测热路径上）。"""
        for peername in (0, 1.5, b"1.2.3.4", object(), {"host": "::1"}, [1], ("::1",), (b"::1", 443)):
            with self.subTest(peername=peername):
                result = format_peer(peername)
                self.assertTrue(result is None or isinstance(result, str))


class FormatHostPortTest(unittest.TestCase):
    """format_host_port() 是 format_peer() 的内核，单独锁定。"""

    def test_ipv6_bracketed(self) -> None:
        """IPv6 字面量统一加方括号。"""
        self.assertEqual(format_host_port("::1", 443), "[::1]:443")
        self.assertEqual(format_host_port("2001:db8::1", 8443), "[2001:db8::1]:8443")
        self.assertEqual(format_host_port("fe80::1%eth0", 443), "[fe80::1%eth0]:443")

    def test_already_bracketed_not_doubled(self) -> None:
        """已带方括号的 host 不会变成 "[[::1]]:443"。"""
        self.assertEqual(format_host_port("[::1]", 443), "[::1]:443")
        self.assertEqual(format_host_port(" [::1] ", 443), "[::1]:443")

    def test_ipv4_and_domain_unbracketed(self) -> None:
        """IPv4 / 域名不加方括号，输出与修复前一致。"""
        self.assertEqual(format_host_port("104.16.132.229", 443), "104.16.132.229:443")
        self.assertEqual(format_host_port("cf.090227.xyz", 443), "cf.090227.xyz:443")

    def test_port_omitted(self) -> None:
        """端口为 None / 空白串时只输出地址部分。"""
        self.assertEqual(format_host_port("::1", None), "[::1]")
        self.assertEqual(format_host_port("1.2.3.4", None), "1.2.3.4")
        self.assertEqual(format_host_port("::1", ""), "[::1]")

    def test_accepts_non_string_port(self) -> None:
        """端口为非字符串（int / 形似端口的对象）时按 str() 归一。"""
        self.assertEqual(format_host_port("::1", 8443), "[::1]:8443")
        self.assertEqual(format_host_port("::1", 0), "[::1]:0")


class _FakeWriter:
    """模拟 asyncio.StreamWriter 的最小接口（只提供 _probe 用到的三个方法）。"""

    def __init__(self, peername: object) -> None:
        self._peername = peername
        self.closed = False

    def get_extra_info(self, name: str, default: object = None) -> object:
        return self._peername if name == "peername" else default

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class ProbePeerWiringTest(unittest.IsolatedAsyncioTestCase):
    """_probe() 必须把 peername 交给 format_peer()，而不是自行拼接。"""

    async def _run_probe(self, peername: object) -> tuple[list[tuple[float | None, str | None]], _FakeWriter]:
        results: list[tuple[float | None, str | None]] = []
        config = AppConfig(target_host="example.com", target_port=443)
        tcping = Tcping(config, lambda latency, peer: results.append((latency, peer)))
        writer = _FakeWriter(peername)

        async def fake_open_connection(host: str, port: int) -> tuple[object, _FakeWriter]:
            return object(), writer

        with mock.patch("snitap.tcping.asyncio.open_connection", fake_open_connection):
            await tcping._probe()
        return results, writer

    async def test_probe_ipv6_peer_bracketed(self) -> None:
        """IPv6 连接的对端显示为 [addr]:port。"""
        results, writer = await self._run_probe(("2606:4700:3030::6815:47f9", 443, 0, 0))
        self.assertEqual(len(results), 1)
        latency, peer = results[0]
        self.assertIsNotNone(latency)  # 握手成功 → 有延迟
        self.assertEqual(peer, "[2606:4700:3030::6815:47f9]:443")
        self.assertTrue(writer.closed)

    async def test_probe_ipv4_peer_unchanged(self) -> None:
        """IPv4 连接的对端显示保持原样（不加括号）。"""
        results, _writer = await self._run_probe(("104.16.132.229", 443))
        self.assertEqual(results[0][1], "104.16.132.229:443")

    async def test_probe_without_peername(self) -> None:
        """get_extra_info 返回 None 时 peer 为 None（GUI 隐藏该片段）。"""
        results, _writer = await self._run_probe(None)
        self.assertEqual(len(results), 1)
        self.assertIsNone(results[0][1])

    async def test_probe_connect_failure_reports_none(self) -> None:
        """连接失败时 latency 与 peer 均为 None。"""
        results: list[tuple[float | None, str | None]] = []
        config = AppConfig(target_host="example.com", target_port=443)
        tcping = Tcping(config, lambda latency, peer: results.append((latency, peer)))

        async def failing_open_connection(host: str, port: int) -> tuple[object, object]:
            raise OSError("connect failed")

        with mock.patch("snitap.tcping.asyncio.open_connection", failing_open_connection):
            await tcping._probe()
        self.assertEqual(results, [(None, None)])


if __name__ == "__main__":
    unittest.main()
