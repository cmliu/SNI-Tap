"""流聚合器（TcpFlow / QuicFlow）单元测试。

覆盖：聚合与合并规则、provisional 语义、幂等性（_finish 连调两次只回调
一次）、非 TLS / 非 QUIC 零上报、backstop 兜底与无 loop 场景。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from snitap.flow import QuicFlow, TcpFlow
from snitap.protocol import UNKNOWN, ProtocolStack
from test_tls_sniffer import build_client_hello, build_server_hello


class TcpFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stacks: list[ProtocolStack] = []

    def make_flow(self) -> TcpFlow:
        return TcpFlow(self.stacks.append)  # 无 running loop → 跳过兜底定时器

    def test_only_client_hello_close_emits_provisional(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        assert up is not None
        up(build_client_hello("cf.090227.xyz"))
        self.assertEqual(self.stacks, [])  # 窗口未闭合，先不发
        flow.close()
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertEqual(stack.sni, "cf.090227.xyz")
        self.assertTrue(stack.provisional)
        self.assertEqual(stack.transport, "TCP")
        self.assertEqual(stack.tls_version, "TLS1.3")
        self.assertEqual(stack.cipher, "A128GCM")
        self.assertEqual(stack.app, UNKNOWN)  # 夹具无 ALPN

    def test_both_directions_take_negotiated_values(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        down = flow.sink("down")
        assert up is not None and down is not None
        up(build_client_hello("api.example.com", alpn=b"h2"))
        down(build_server_hello(alpn=b"h3", cipher=0x1302))
        # 双向 finished 立即闭合，无需 close
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertFalse(stack.provisional)
        self.assertEqual(stack.sni, "api.example.com")  # SNI 只来自客户端
        self.assertEqual(stack.app, "h3")               # 三层取协商值
        self.assertEqual(stack.tls_version, "TLS1.3")
        self.assertEqual(stack.cipher, "A256GCM")
        self.assertEqual(stack.security, "TLS1.3/A256GCM")

    def test_non_tls_emits_nothing(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        down = flow.sink("down")
        assert up is not None and down is not None
        up(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        down(b"HTTP/1.1 200 OK\r\n\r\n")
        flow.close()
        self.assertEqual(self.stacks, [])

    def test_sink_returns_none_after_finished(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        assert up is not None
        up(build_client_hello("done.example"))
        down = flow.sink("down")
        assert down is not None
        down(b"HTTP/1.1 400 Bad Request\r\n\r\n")  # 下行 NOT_TLS → 双向 finished → emit
        self.assertEqual(len(self.stacks), 1)
        self.assertIsNone(flow.sink("up"))   # emit 后两个方向都零开销
        self.assertIsNone(flow.sink("down"))

    def test_finish_idempotent(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        assert up is not None
        up(build_client_hello("once.example"))
        flow.close()
        flow.close()
        flow.close()
        self.assertEqual(len(self.stacks), 1)

    def test_sniffer_exception_does_not_break_flow(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        assert up is not None
        up(None)  # type: ignore[arg-type]  # 非法输入触发内部异常路径
        self.assertEqual(self.stacks, [])
        self.assertFalse(flow._done)


class QuicFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stacks: list[ProtocolStack] = []

    def make_flow(self) -> QuicFlow:
        return QuicFlow(self.stacks.append)

    def test_non_quic_udp_emits_nothing(self) -> None:
        flow = self.make_flow()
        flow.feed_client(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        flow.feed_server(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        flow.close()
        self.assertEqual(self.stacks, [])

    def test_version_negotiation_emits_transport_only(self) -> None:
        flow = self.make_flow()
        # 版本协商包：long header 位 + version 0
        datagram = b"\x80\x00\x00\x00\x00\x08" + b"\xa1" * 8 + b"\x00" * 60
        flow.feed_client(datagram)
        flow.close()
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertEqual(stack.transport, "QUIC")
        self.assertEqual(stack.quic_version, "vneg")
        self.assertEqual(stack.transport_label, "QUIC/vneg")
        self.assertEqual(stack.domain, UNKNOWN)
        self.assertTrue(stack.has_content)

    def test_finish_idempotent(self) -> None:
        flow = self.make_flow()
        datagram = b"\x80\x00\x00\x00\x00\x08" + b"\xa1" * 8 + b"\x00" * 60
        flow.feed_client(datagram)
        flow.close()
        flow.close()
        self.assertEqual(len(self.stacks), 1)


if __name__ == "__main__":
    unittest.main()
