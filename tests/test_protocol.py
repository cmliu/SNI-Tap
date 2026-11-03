"""protocol.py 共享契约的单元测试。

覆盖：GREASE 全 16 个值、三张名称表的单射性、key 不含 provisional、
security 三种形态、has_content 四种组合、transport_label 的 FIX-5 表格、
ECH 标记（security_label / key 分离 / StackRow.has_ech）、
StackRow.from_stack 与 caption 的一致性。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from snitap.protocol import (
    ECH_MARK,
    UNKNOWN,
    LayerSource,
    ProtocolStack,
    StackRow,
    alpn_name,
    cipher_name,
    is_grease,
    quic_version_name,
    tls_version_name,
    transport_label,
)


class GreaseTest(unittest.TestCase):
    def test_all_16_grease_values(self) -> None:
        for high in range(16):
            value = (high << 12) | (0x0A << 8) | (high << 4) | 0x0A
            self.assertTrue(is_grease(value), f"0x{value:04x} 应为 GREASE")

    def test_non_grease_values_rejected(self) -> None:
        # 0xAAAA 两个字节相同且低半字节为 0xa，本身就是合法 GREASE，不列入反例
        for value in (0x0000, 0x0304, 0x1301, 0x0A0B, 0x0B0A, 0xFFFB, 0xABAB):
            self.assertFalse(is_grease(value), f"0x{value:04x} 不应为 GREASE")


class NameTableInjectivityTest(unittest.TestCase):
    """名称表必须单射：不同 ID 不得映射到同一字符串。"""

    def test_tls_versions_injective(self) -> None:
        names = [tls_version_name(v) for v in range(0x0300, 0x0305)]
        self.assertEqual(len(names), len(set(names)))

    def test_quic_versions_injective(self) -> None:
        known = [0x00000000, 0x00000001, 0x6B3343CF, 0xFF00001D]
        names = [quic_version_name(v) for v in known]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(
            names, ["vneg", "v1", "v2", "draft-29"]
        )

    def test_ciphers_injective(self) -> None:
        known = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
        names = [cipher_name(v) for v in known]
        self.assertEqual(len(names), len(set(names)))
        # 未收录的走 0x%04x，与收录名天然不相交
        self.assertEqual(cipher_name(0xC02F), "0xc02f")
        self.assertEqual(cipher_name(0x009C), "0x009c")

    def test_unknown_versions_fall_back_to_hex(self) -> None:
        self.assertEqual(tls_version_name(0x7F17), "0x7f17")
        self.assertEqual(quic_version_name(0xDEADBEEF), "0xdeadbeef")


class AlpnNameTest(unittest.TestCase):
    def test_printable_ascii_passthrough(self) -> None:
        self.assertEqual(alpn_name(b"h2"), "h2")
        self.assertEqual(alpn_name(b"http/1.1"), "http/1.1")
        self.assertEqual(alpn_name(b"h3"), "h3")

    def test_non_ascii_becomes_hex(self) -> None:
        self.assertEqual(alpn_name(b"h\x00\x03"), "680003")
        self.assertEqual(alpn_name(b"\xff\xfe"), "fffe")

    def test_empty_is_unknown(self) -> None:
        self.assertEqual(alpn_name(b""), UNKNOWN)


class TransportLabelTest(unittest.TestCase):
    """FIX-5：传输层展示名的唯一出处。"""

    def test_tcp(self) -> None:
        self.assertEqual(transport_label("TCP", UNKNOWN), "TCP")
        self.assertEqual(transport_label("TCP", "v1"), "TCP")

    def test_quic_known_versions(self) -> None:
        self.assertEqual(transport_label("QUIC", "v1"), "QUIC/v1")
        self.assertEqual(transport_label("QUIC", "v2"), "QUIC/v2")
        self.assertEqual(transport_label("QUIC", "draft-29"), "QUIC/draft-29")
        self.assertEqual(transport_label("QUIC", "0xff00001d"), "QUIC/0xff00001d")

    def test_quic_version_negotiation(self) -> None:
        self.assertEqual(transport_label("QUIC", "vneg"), "QUIC/vneg")

    def test_quic_unknown_version(self) -> None:
        self.assertEqual(transport_label("QUIC", UNKNOWN), "QUIC/-")

    def test_plain_udp(self) -> None:
        self.assertEqual(transport_label("UDP", UNKNOWN), "UDP")


class ProtocolStackTest(unittest.TestCase):
    def test_domain_none_becomes_unknown(self) -> None:
        self.assertEqual(ProtocolStack(sni=None).domain, UNKNOWN)
        self.assertEqual(ProtocolStack(sni="a.example").domain, "a.example")

    def test_key_excludes_provisional_and_sources(self) -> None:
        base = dict(
            sni="a.example",
            alpn="h2",
            tls_version="TLS1.3",
            cipher="A128GCM",
        )
        a = ProtocolStack(**base, provisional=False, tls_source=LayerSource.CLIENT)
        b = ProtocolStack(**base, provisional=True, tls_source=LayerSource.NEGOTIATED)
        self.assertEqual(a.key, b.key)
        self.assertEqual(a.key, ("a.example", "h2", "TCP", "TLS1.3/A128GCM"))

    def test_security_three_forms(self) -> None:
        self.assertEqual(ProtocolStack().security, UNKNOWN)
        self.assertEqual(ProtocolStack(tls_version="TLS1.3").security, "TLS1.3")
        self.assertEqual(
            ProtocolStack(tls_version="TLS1.3", cipher="A128GCM").security,
            "TLS1.3/A128GCM",
        )

    def test_has_content_four_combinations(self) -> None:
        # transport_label 恒非 UNKNOWN（TCP/QUIC/-/UDP…），故有传输层值即有内容
        self.assertTrue(ProtocolStack().has_content)  # TCP + 全未知其余
        self.assertTrue(ProtocolStack(transport="QUIC").has_content)  # 仅传输层 QUIC/-
        self.assertTrue(ProtocolStack(transport="QUIC", quic_version="v1").has_content)
        self.assertTrue(
            ProtocolStack(sni="a.example", transport="TCP").has_content
        )

    def test_caption_order_fixed(self) -> None:
        stack = ProtocolStack(
            sni="www.example.org",
            transport="QUIC",
            quic_version="v1",
            tls_version="TLS1.3",
            cipher="A128GCM",
            alpn="h3",
        )
        self.assertEqual(stack.caption(), "h3 · QUIC/v1 · TLS1.3/A128GCM")


class StackRowTest(unittest.TestCase):
    def test_from_stack_matches_caption_and_key(self) -> None:
        stack = ProtocolStack(
            sni="api.cloudflare.com",
            transport="TCP",
            tls_version="TLS1.3",
            cipher="CHACHA20",
            alpn="h2",
            provisional=True,
        )
        row = StackRow.from_stack(stack, 3)
        self.assertEqual(row.key, stack.key)
        self.assertEqual(row.caption(), stack.caption())
        self.assertEqual(row.count, 3)
        self.assertEqual(row.caption(), "h2 · TCP · TLS1.3/CHACHA20")

    def test_row_is_frozen(self) -> None:
        row = StackRow(domain="a", app="b", transport="c", security="d", count=1)
        with self.assertRaises(Exception):
            row.count = 2  # type: ignore[misc]


class EchMarkTest(unittest.TestCase):
    """ECH 标记：语义只是「客户端发起了 ECH」，不声称服务端已接受。"""

    def test_ech_mark_constant(self) -> None:
        self.assertEqual(ECH_MARK, "ECH")

    def test_ech_mark_empty_when_not_ech(self) -> None:
        self.assertEqual(ProtocolStack().ech_mark, "")
        self.assertEqual(
            ProtocolStack(tls_version="TLS1.3", cipher="A128GCM").ech_mark, ""
        )

    def test_security_label_without_ech_equals_security(self) -> None:
        stack = ProtocolStack(tls_version="TLS1.3", cipher="A128GCM")
        self.assertEqual(stack.security_label, stack.security)
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM")

    def test_security_label_with_ech_appends_mark(self) -> None:
        stack = ProtocolStack(tls_version="TLS1.3", cipher="A128GCM", ech=True)
        self.assertEqual(stack.security, "TLS1.3/A128GCM")            # 原值不受影响
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM ECH")
        self.assertEqual(stack.ech_mark, ECH_MARK)

    def test_security_label_unknown_scenario(self) -> None:
        # 三层全未知（只有传输层兜底）时也不得出现裸 "" 或 None
        self.assertEqual(ProtocolStack().security_label, UNKNOWN)
        self.assertEqual(ProtocolStack(ech=True).security_label, f"{UNKNOWN} {ECH_MARK}")

    def test_key_separates_ech_from_non_ech(self) -> None:
        base = dict(sni="a.example", alpn="h2", tls_version="TLS1.3", cipher="A128GCM")
        plain = ProtocolStack(**base)
        with_ech = ProtocolStack(**base, ech=True)
        self.assertNotEqual(plain.key, with_ech.key)
        self.assertEqual(plain.key, ("a.example", "h2", "TCP", "TLS1.3/A128GCM"))
        self.assertEqual(with_ech.key, ("a.example", "h2", "TCP", "TLS1.3/A128GCM ECH"))
        # provisional 仍不进键：ECH 行同样与 provisional 无关
        self.assertEqual(
            with_ech.key, ProtocolStack(**base, ech=True, provisional=True).key
        )

    def test_caption_uses_security_label(self) -> None:
        stack = ProtocolStack(
            sni="www.example.org",
            transport="QUIC",
            quic_version="v1",
            tls_version="TLS1.3",
            cipher="A128GCM",
            alpn="h3",
            ech=True,
        )
        self.assertEqual(stack.caption(), "h3 · QUIC/v1 · TLS1.3/A128GCM ECH")

    def test_stack_row_has_ech_and_caption_consistent(self) -> None:
        stack = ProtocolStack(
            sni="api.cloudflare.com",
            tls_version="TLS1.3",
            cipher="A128GCM",
            alpn="h2",
            ech=True,
        )
        row = StackRow.from_stack(stack, 1)
        self.assertTrue(row.has_ech)
        self.assertEqual(row.key, stack.key)
        self.assertEqual(row.caption(), stack.caption())
        self.assertEqual(row.caption(), "h2 · TCP · TLS1.3/A128GCM ECH")

    def test_stack_row_without_ech(self) -> None:
        stack = ProtocolStack(sni="a.example", tls_version="TLS1.3", alpn="h2")
        row = StackRow.from_stack(stack, 1)
        self.assertFalse(row.has_ech)
        self.assertEqual(row.caption(), "h2 · TCP · TLS1.3")

    def test_stack_row_has_ech_does_not_match_bare_ech_domain(self) -> None:
        # 仅判定安全层的 `` ECH`` 后缀，别的字段含 ECH 不算
        row = StackRow(domain="ECH", app="h2", transport="TCP", security="TLS1.3", count=1)
        self.assertFalse(row.has_ech)


if __name__ == "__main__":
    unittest.main()
