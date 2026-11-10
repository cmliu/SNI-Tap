"""流聚合器（TcpFlow / QuicFlow）单元测试。

覆盖：聚合与合并规则、provisional 语义、幂等性（_finish 连调两次只回调
一次）、非 TLS / 非 QUIC 零上报、backstop 兜底与无 loop 场景、
ECH 双字段语义（``ech_ext`` 只取客户端方向的原始观测，``ech`` 还要求外层 SNI
命中 ECH 掩护域名）。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from ech_env_isolation import ConfigIsolatedCase
from snitap.flow import QuicFlow, TcpFlow
from snitap.protocol import UNKNOWN, LayerSource, ProtocolStack
from test_tls_sniffer import build_client_hello, build_server_hello

try:  # QUIC 加密夹具（与 test_quic_sniffer 共用，避免两处各写一份）
    from test_quic_sniffer import _V1 as _QUIC_V1
    from test_quic_sniffer import _encrypt_initial, _hello_message

    _HAS_QUIC_FIXTURE = True
except Exception:  # pragma: no cover - 环境无 cryptography
    _HAS_QUIC_FIXTURE = False


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

    def test_alpn_falls_back_to_client_when_server_is_silent(self) -> None:
        """TLS 1.3 的 ALPN 在加密的 EncryptedExtensions 里（RFC 8446 §4.2.10），
        明文 ServerHello 不含该扩展——此时应用层必须回退到客户端偏好，
        否则任何 TLS 1.3 连接的 app 都会显示 "-"；回退值还要带 `?` 后缀，
        以免「只是偏好 h3」被当成「已协商到 h3」。"""
        flow = self.make_flow()
        up = flow.sink("up")
        down = flow.sink("down")
        assert up is not None and down is not None
        up(build_client_hello("api.example.com", alpn=b"h3"))
        down(build_server_hello(with_alpn=False, cipher=0x1301))
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertFalse(stack.provisional)
        self.assertEqual(stack.alpn, "h3")      # 原始值仍是客户端偏好
        self.assertEqual(stack.app, "h3?")      # 展示值带「未协商」标记
        self.assertEqual(stack.alpn_source, LayerSource.CLIENT)
        # cipher / TLS 版本仍取协商值
        self.assertEqual(stack.cipher, "A128GCM")
        self.assertEqual(stack.cipher_source, LayerSource.NEGOTIATED)
        # 整行标记由 GUI 加在行首 `~`；行内 app 已带 `?`，统计键因此与真协商的 h3 分开
        self.assertEqual(stack.key, ("api.example.com", "h3?", "TCP", "TLS1.3/A128GCM"))

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


class TcpFlowEchTest(ConfigIsolatedCase):
    """ECH 合并规则：``ech_ext`` 取客户端方向原始观测，``ech`` 还要 SNI 命中掩护域名。

    语义收紧（RFC 9849 §6.2 / §10.10.4）：携带 ``0xFE0D`` 扩展不等于 ECH 生效，
    因为客户端没有可用 ECHConfig 时会发送 GREASE ECH；真 ECH 的外层 SNI 必然是
    ``public_name`` 掩护域名，GREASE ECH 的外层 SNI 则是真实域名。

    继承 :class:`ech_env_isolation.ConfigIsolatedCase`：用例断言 ``cloudflare-ech.com``
    命中默认名单，开发机导出 ``SNITAP_ECH_PUBLIC_NAMES`` 时不会假红。
    """

    PUBLIC_NAME = "cloudflare-ech.com"
    REAL_DOMAIN = "test.cmliussss.dpdns.org"

    def setUp(self) -> None:
        super().setUp()   # 先落默认名单基线（ConfigIsolatedCase）
        self.stacks: list[ProtocolStack] = []

    def make_flow(self) -> TcpFlow:
        return TcpFlow(self.stacks.append)

    def test_public_name_sni_marks_ech_confirmed(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        assert up is not None
        up(build_client_hello(self.PUBLIC_NAME, alpn=b"h2", ech=b"\x01\x02\x03"))
        flow.close()
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertTrue(stack.ech_ext)              # 扩展存在
        self.assertTrue(stack.ech)                  # 且 SNI 是掩护域名 → 确证
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM ECH")
        self.assertIn(" ECH", stack.key[3])
        self.assertTrue(stack.provisional)          # 只有客户端方向
        self.assertEqual(stack.sni, self.PUBLIC_NAME)  # 外层 SNI 仍可见

    def test_real_domain_sni_is_grease_not_marked(self) -> None:
        """用户实际报的场景：关闭 ECH 的域名仍携带扩展（GREASE），不得标记。"""
        flow = self.make_flow()
        up = flow.sink("up")
        assert up is not None
        up(build_client_hello(self.REAL_DOMAIN, alpn=b"h2", ech=b"\x01\x02\x03"))
        flow.close()
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertTrue(stack.ech_ext)              # 扩展确实存在
        self.assertFalse(stack.ech)                 # 但不是确证生效
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM")
        self.assertNotIn(" ECH", stack.key[3])
        self.assertEqual(stack.ech_mark, "")

    def test_no_ech_keeps_plain_stack(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        assert up is not None
        up(build_client_hello("plain.example", alpn=b"h2"))
        flow.close()
        stack = self.stacks[0]
        self.assertFalse(stack.ech)
        self.assertFalse(stack.ech_ext)
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM")

    def test_ech_with_both_directions_still_true(self) -> None:
        flow = self.make_flow()
        up = flow.sink("up")
        down = flow.sink("down")
        assert up is not None and down is not None
        up(build_client_hello(self.PUBLIC_NAME, alpn=b"h2", ech=b"\xaa" * 8))
        down(build_server_hello(alpn=b"h3", cipher=0x1302))
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertTrue(stack.ech)                  # 协商值来自服务端，ECH 仍来自客户端
        self.assertTrue(stack.ech_ext)
        self.assertFalse(stack.provisional)
        self.assertEqual(stack.app, "h3")
        self.assertEqual(stack.security_label, "TLS1.3/A256GCM ECH")

    def test_server_side_ech_extension_alone_does_not_mark(self) -> None:
        # 服务端方向不参与 ECH 判定：只有 ServerHello 带扩展时仍不标记
        flow = self.make_flow()
        up = flow.sink("up")
        down = flow.sink("down")
        assert up is not None and down is not None
        up(build_client_hello(self.PUBLIC_NAME, alpn=b"h2"))
        down(build_server_hello(alpn=b"h3", cipher=0x1302))
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertFalse(stack.ech_ext)
        self.assertFalse(stack.ech)


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


@unittest.skipUnless(_HAS_QUIC_FIXTURE, "需要 cryptography 才能构造加密 Initial")
class QuicFlowEchTest(ConfigIsolatedCase):
    """QUIC + ECH 端到端：外层 SNI 可解，且按掩护域名确证 ECH。

    真 ECH 只加密 ClientHelloInner，ClientHelloOuter 的 SNI 仍是明文
    （RFC 9849 §5），值是该 ECHConfig 的 ``public_name``。因此 h3 + ECH 的
    正确表现是「拿到 cloudflare-ech.com + ECH 标记」，而**不是**用户真实域名。
    """

    PUBLIC_NAME = "cloudflare-ech.com"

    def setUp(self) -> None:
        super().setUp()
        self.stacks: list[ProtocolStack] = []

    def test_quic_ech_reports_outer_sni_and_mark(self) -> None:
        flow = QuicFlow(self.stacks.append)
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        record = build_client_hello(self.PUBLIC_NAME, alpn=b"h3", ech=b"\x5a" * 320)
        flow.feed_client(
            _encrypt_initial(
                _QUIC_V1, header_dcid=dcid, header_scid=scid, crypto_data=_hello_message(record),
            )
        )
        flow.close()
        self.assertEqual(len(self.stacks), 1)
        stack = self.stacks[0]
        self.assertEqual(stack.domain, self.PUBLIC_NAME)
        self.assertEqual(stack.transport_label, "QUIC/v1")
        # 只有客户端方向：app 保持原值，整行标记 `~` 由 GUI 加在行首，避免双标记
        self.assertTrue(stack.provisional)
        self.assertEqual(stack.app, "h3")
        self.assertEqual(stack.tls_version, "TLS1.3")
        self.assertTrue(stack.ech_ext)
        self.assertTrue(stack.ech)


if __name__ == "__main__":
    unittest.main()
