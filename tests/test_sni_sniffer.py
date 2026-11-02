"""TLS ClientHello SNI 解析器单元测试。

用一个手工构造的合法 ClientHello 作为基准样本，覆盖整包/逐字节/非 TLS/
无 SNI 扩展/非 ClientHello/超限等路径。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from snitap.sni_sniffer import SniSniffer, SniffState


def build_client_hello(host: str = "cf.090227.xyz", *, with_sni: bool = True) -> bytes:
    """构造一个结构合法的 TLS 1.3 风格 ClientHello（含可选 SNI 扩展）。"""
    extensions = b""
    if with_sni:
        name = host.encode("ascii")
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        server_name_list = len(entry).to_bytes(2, "big") + entry
        extensions += b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    # supported_versions 扩展，确保扩展区不是空的
    extensions += b"\x00\x2b\x00\x03\x02\x03\x04"

    body = (
        b"\x03\x03"                     # legacy_version
        + bytes(range(32))              # random
        + b"\x20" + bytes(32)           # legacy_session_id（32 字节）
        + b"\x00\x04\x13\x01\x13\x02"   # cipher_suites
        + b"\x01\x00"                   # compression_methods
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class SniSnifferTest(unittest.TestCase):
    def sniff(self, payload: bytes, chunk_size: int = 0) -> SniSniffer:
        sniffer = SniSniffer()
        if chunk_size <= 0:
            sniffer.feed(payload)
        else:
            for start in range(0, len(payload), chunk_size):
                sniffer.feed(payload[start:start + chunk_size])
        return sniffer

    def test_single_feed_extracts_sni(self) -> None:
        sniffer = self.sniff(build_client_hello("cf.090227.xyz"))
        self.assertTrue(sniffer.finished)
        self.assertIs(sniffer.state, SniffState.DONE)
        self.assertEqual(sniffer.result, "cf.090227.xyz")

    def test_byte_by_byte_reassembly(self) -> None:
        sniffer = self.sniff(build_client_hello("api.cloudflare.com"), chunk_size=1)
        self.assertIs(sniffer.state, SniffState.DONE)
        self.assertEqual(sniffer.result, "api.cloudflare.com")

    def test_split_across_two_chunks(self) -> None:
        payload = build_client_hello("example.org")
        split = len(payload) // 2
        sniffer = SniSniffer()
        sniffer.feed(payload[:split])
        self.assertFalse(sniffer.finished)
        sniffer.feed(payload[split:])
        self.assertEqual(sniffer.result, "example.org")

    def test_plain_http_is_rejected_immediately(self) -> None:
        sniffer = self.sniff(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertIs(sniffer.state, SniffState.NOT_TLS)
        self.assertIsNone(sniffer.result)

    def test_no_sni_extension_returns_none(self) -> None:
        sniffer = self.sniff(build_client_hello(with_sni=False))
        self.assertIs(sniffer.state, SniffState.DONE)
        self.assertIsNone(sniffer.result)

    def test_server_hello_is_not_client_hello(self) -> None:
        payload = bytearray(build_client_hello())
        payload[5] = 0x02  # handshake type: ServerHello
        sniffer = self.sniff(bytes(payload))
        self.assertIs(sniffer.state, SniffState.NOT_TLS)

    def test_oversized_record_rejected(self) -> None:
        payload = b"\x16\x03\x01\xff\xff" + b"\x00" * 64  # record_len = 65535
        sniffer = self.sniff(payload)
        self.assertIs(sniffer.state, SniffState.NOT_TLS)

    def test_buffer_overflow_rejected(self) -> None:
        sniffer = SniSniffer()
        sniffer.feed(b"\x16\x03\x01\x40\x00")  # 声称 record 体 16KB
        sniffer.feed(b"\x00" * (21 * 1024))   # 持续喂入直到超限
        self.assertIs(sniffer.state, SniffState.NOT_TLS)

    def test_truncated_body_waits_then_fails_on_mismatch(self) -> None:
        payload = build_client_hello("a.example")
        # 截掉最后一段，嗅探应保持未决，不误报
        sniffer = SniSniffer()
        sniffer.feed(payload[:40])
        self.assertFalse(sniffer.finished)
        self.assertIsNone(sniffer.result)

    def test_extra_bytes_after_done_are_ignored(self) -> None:
        sniffer = self.sniff(build_client_hello("keep.example"))
        sniffer.feed(b"\x17\x03\x03\x00\x05hello")
        self.assertEqual(sniffer.result, "keep.example")


if __name__ == "__main__":
    unittest.main()
