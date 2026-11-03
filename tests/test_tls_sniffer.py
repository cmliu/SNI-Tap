"""TLS 双向 hello 嗅探单元测试。

承接原 ``test_sni_sniffer.py`` 的 10 个用例语义（整包 / 逐字节 / 两段 /
非 TLS / 无 SNI / 非 ClientHello / 超长 record / 缓冲超限 / 截断待续 /
终态忽略追加），并扩充双向解析、GREASE 过滤、supported_versions 优先级、
ALPN 首偏好、扩展区截断等用例。

``build_client_hello`` / ``build_server_hello`` 是共享夹具：
``test_forwarders.py`` 依赖 ``build_client_hello``（签名与行为不变）。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from snitap.protocol import UNKNOWN
from snitap.tls_sniffer import (
    CLIENT,
    SERVER,
    HelloInfo,
    SniffState,
    TlsSniffer,
    parse_client_hello,
    parse_hello,
    parse_server_hello,
)


def build_client_hello(
    host: str = "cf.090227.xyz",
    *,
    with_sni: bool = True,
    alpn: bytes | None = None,
    ciphers: tuple[int, ...] = (0x1301, 0x1302),
    supported: tuple[int, ...] = (0x0304,),
    legacy_version: int = 0x0303,
) -> bytes:
    """构造一个结构合法的 TLS ClientHello（含可选 SNI/ALPN/版本扩展）。

    缺省行为与 v1 完全一致（13 01 13 02 两个套件 + supported_versions 0x0304）。
    """
    extensions = b""
    if with_sni:
        name = host.encode("ascii")
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        server_name_list = len(entry).to_bytes(2, "big") + entry
        extensions += b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    if alpn is not None:
        proto_entry = bytes([len(alpn)]) + alpn
        alpn_list = len(proto_entry).to_bytes(2, "big") + proto_entry
        extensions += b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list
    if supported:
        sv_list = bytes([len(supported) * 2]) + b"".join(
            v.to_bytes(2, "big") for v in supported
        )
        extensions += b"\x00\x2b" + len(sv_list).to_bytes(2, "big") + sv_list

    cipher_bytes = b"".join(v.to_bytes(2, "big") for v in ciphers)
    body = (
        legacy_version.to_bytes(2, "big")  # legacy_version
        + bytes(range(32))                 # random
        + b"\x20" + bytes(32)              # legacy_session_id（32 字节）
        + len(cipher_bytes).to_bytes(2, "big") + cipher_bytes
        + b"\x01\x00"                      # compression_methods
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def build_server_hello(
    *,
    alpn: bytes | None = b"h2",
    cipher: int = 0x1301,
    supported_version: int = 0x0304,
    with_alpn: bool = True,
    with_supported: bool = True,
) -> bytes:
    """构造一个结构合法的 TLS 1.3 风格 ServerHello（含可选 ALPN/版本扩展）。"""
    extensions = b""
    if with_alpn and alpn is not None:
        proto_entry = bytes([len(alpn)]) + alpn
        alpn_list = len(proto_entry).to_bytes(2, "big") + proto_entry
        extensions += b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list
    if with_supported:
        extensions += b"\x00\x2b\x00\x02" + supported_version.to_bytes(2, "big")

    body = (
        b"\x03\x03"                     # legacy_version
        + bytes(range(32))              # random
        + b"\x20" + bytes(32)           # legacy_session_id（32 字节）
        + cipher.to_bytes(2, "big")     # cipher_suite 定长 2 字节
        + b"\x00"                       # compression_methods
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


class TlsSnifferClientTest(unittest.TestCase):
    """原 10 个用例语义 + ClientHello 新增用例。"""

    def sniff(self, payload: bytes, chunk_size: int = 0, kind: str = CLIENT) -> TlsSniffer:
        sniffer = TlsSniffer(kind)
        if chunk_size <= 0:
            sniffer.feed(payload)
        else:
            for start in range(0, len(payload), chunk_size):
                sniffer.feed(payload[start:start + chunk_size])
        return sniffer

    # ---------------------------------------------------------- 原 10 用例

    def test_single_feed_extracts_sni(self) -> None:
        sniffer = self.sniff(build_client_hello("cf.090227.xyz"))
        self.assertTrue(sniffer.finished)
        self.assertIs(sniffer.state, SniffState.DONE)
        info = sniffer.info
        assert info is not None
        self.assertEqual(info.sni, "cf.090227.xyz")

    def test_byte_by_byte_reassembly(self) -> None:
        sniffer = self.sniff(build_client_hello("api.cloudflare.com"), chunk_size=1)
        self.assertIs(sniffer.state, SniffState.DONE)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "api.cloudflare.com")

    def test_split_across_two_chunks(self) -> None:
        payload = build_client_hello("example.org")
        split = len(payload) // 2
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(payload[:split])
        self.assertFalse(sniffer.finished)
        sniffer.feed(payload[split:])
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "example.org")

    def test_plain_http_is_rejected_immediately(self) -> None:
        sniffer = self.sniff(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertIs(sniffer.state, SniffState.NOT_TLS)
        self.assertIsNone(sniffer.info)

    def test_no_sni_extension_returns_none(self) -> None:
        sniffer = self.sniff(build_client_hello(with_sni=False))
        self.assertIs(sniffer.state, SniffState.DONE)
        assert sniffer.info is not None
        self.assertIsNone(sniffer.info.sni)
        self.assertEqual(sniffer.info.tls_version, "TLS1.3")

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
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(b"\x16\x03\x01\x40\x00")  # 声称 record 体 16KB
        sniffer.feed(b"\x00" * (21 * 1024))    # 持续喂入直到超限
        self.assertIs(sniffer.state, SniffState.NOT_TLS)

    def test_truncated_body_waits_then_fails_on_mismatch(self) -> None:
        payload = build_client_hello("a.example")
        # 截掉最后一段，嗅探应保持未决，不误报
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(payload[:40])
        self.assertFalse(sniffer.finished)
        self.assertIsNone(sniffer.info)

    def test_extra_bytes_after_done_are_ignored(self) -> None:
        sniffer = self.sniff(build_client_hello("keep.example"))
        sniffer.feed(b"\x17\x03\x03\x00\x05hello")
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "keep.example")

    # ---------------------------------------------------------- 新增用例

    def test_supported_versions_takes_max_and_filters_grease(self) -> None:
        payload = build_client_hello(
            "sv.example",
            supported=(0x0A0A, 0x0303, 0x1A1A, 0x0304),
        )
        info = parse_client_hello(self._hello_body(payload))
        self.assertEqual(info.tls_version, "TLS1.3")
        self.assertEqual(info.tls_version_raw, 0x0304)

    def test_tls13_client_with_legacy_0303_not_judged_tls12(self) -> None:
        # TLS1.3 客户端 legacy_version 恒为 0x0303，有 supported_versions 时以其为唯一依据
        payload = build_client_hello("v13.example", legacy_version=0x0303)
        info = parse_client_hello(self._hello_body(payload))
        self.assertEqual(info.tls_version, "TLS1.3")

    def test_no_supported_versions_falls_back_to_legacy(self) -> None:
        payload = build_client_hello(
            "v12.example", legacy_version=0x0303, supported=(),
        )
        info = parse_client_hello(self._hello_body(payload))
        self.assertEqual(info.tls_version, "TLS1.2")

    def test_cipher_takes_first_non_grease(self) -> None:
        payload = build_client_hello(
            "cipher.example", ciphers=(0x0A0A, 0x1301, 0x1302),
        )
        info = parse_client_hello(self._hello_body(payload))
        self.assertEqual(info.cipher, "A128GCM")
        self.assertEqual(info.cipher_raw, 0x1301)
        self.assertEqual(info.cipher_count, 3)

    def test_alpn_takes_first_preference(self) -> None:
        # 两个 ALPN 条目 h3 在前 h2 在后，必须取第一条 h3
        info = parse_client_hello(self._ch_body_with_alpn((b"h3", b"h2")))
        self.assertEqual(info.alpn, "h3")
        self.assertEqual(info.ext_count, 2)

    def test_alpn_h2(self) -> None:
        payload = build_client_hello("alpn2.example", alpn=b"h2")
        info = parse_client_hello(self._hello_body(payload))
        self.assertEqual(info.alpn, "h2")

    def test_truncated_extension_area_rejected(self) -> None:
        # 扩展总长声明 256 字节但主体到此截断 → 越界 → NOT_TLS
        body = (
            b"\x03\x03"
            + bytes(range(32))
            + b"\x20" + bytes(32)
            + b"\x00\x04\x13\x01\x13\x02"
            + b"\x01\x00"
            + b"\x01\x00"
        )
        sniffer = TlsSniffer(CLIENT)
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        sniffer.feed(b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake)
        self.assertIs(sniffer.state, SniffState.NOT_TLS)

    def test_kind_server_rejects_client_hello(self) -> None:
        sniffer = self.sniff(build_client_hello("cf.090227.xyz"), kind=SERVER)
        self.assertIs(sniffer.state, SniffState.NOT_TLS)
        self.assertIsNone(sniffer.info)

    def test_parse_hello_dispatcher(self) -> None:
        ch = self._hello_body(build_client_hello("d.example"))
        self.assertEqual(parse_hello(CLIENT, ch).sni, "d.example")
        sh = self._hello_body(build_server_hello())
        self.assertIsNone(parse_hello(SERVER, sh).sni)

    # ---------------------------------------------------------------- 工具

    @staticmethod
    def _hello_body(payload: bytes) -> bytes:
        """从完整 TLS record 中取出 hello 主体（去 5B record 头 + 4B handshake 头）。"""
        hello_len = int.from_bytes(payload[6:9], "big")
        return payload[9:9 + hello_len]

    @staticmethod
    def _ch_body_with_alpn(protos: tuple[bytes, ...]) -> bytes:
        """构造 body 含多 ALPN 条目的 ClientHello 主体。"""
        entries = b"".join(bytes([len(p)]) + p for p in protos)
        alpn_list = len(entries).to_bytes(2, "big") + entries
        alpn_ext = b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list
        sv_ext = b"\x00\x2b\x00\x03\x02\x03\x04"
        extensions = alpn_ext + sv_ext
        return (
            b"\x03\x03"
            + bytes(range(32))
            + b"\x20" + bytes(32)
            + b"\x00\x04\x13\x01\x13\x02"
            + b"\x01\x00"
            + len(extensions).to_bytes(2, "big") + extensions
        )


class TlsSnifferServerTest(unittest.TestCase):
    """ServerHello 解析用例。"""

    def sniff(self, payload: bytes) -> TlsSniffer:
        sniffer = TlsSniffer(SERVER)
        sniffer.feed(payload)
        return sniffer

    def test_server_hello_negotiated_values(self) -> None:
        sniffer = self.sniff(build_server_hello())
        self.assertIs(sniffer.state, SniffState.DONE)
        info = sniffer.info
        assert info is not None
        self.assertIsNone(info.sni)
        self.assertEqual(info.tls_version, "TLS1.3")
        self.assertEqual(info.cipher, "A128GCM")
        self.assertEqual(info.alpn, "h2")
        self.assertEqual(info.kind, SERVER)

    def test_server_hello_bare_supported_versions(self) -> None:
        # supported_versions 是裸 2 字节（无 list 长度前缀）
        payload = build_server_hello(with_alpn=False, supported_version=0x0304)
        body = TlsSnifferClientTest._hello_body(payload)
        info = parse_server_hello(body)
        self.assertEqual(info.tls_version, "TLS1.3")

    def test_server_hello_falls_back_to_legacy_version(self) -> None:
        payload = build_server_hello(with_alpn=False, with_supported=False)
        body = TlsSnifferClientTest._hello_body(payload)
        info = parse_server_hello(body)
        self.assertEqual(info.tls_version, "TLS1.2")

    def test_server_hello_alpn_http11(self) -> None:
        payload = build_server_hello(alpn=b"http/1.1")
        body = TlsSnifferClientTest._hello_body(payload)
        info = parse_server_hello(body)
        self.assertEqual(info.alpn, "http/1.1")

    def test_server_hello_cipher_tls12_suite(self) -> None:
        payload = build_server_hello(cipher=0xC02F, with_alpn=False)
        body = TlsSnifferClientTest._hello_body(payload)
        info = parse_server_hello(body)
        self.assertEqual(info.cipher, "0xc02f")

    def test_client_hello_is_not_server_hello(self) -> None:
        sniffer = self.sniff(build_client_hello("cf.090227.xyz"))
        self.assertIs(sniffer.state, SniffState.NOT_TLS)

    def test_server_hello_byte_by_byte(self) -> None:
        payload = build_server_hello()
        sniffer = TlsSniffer(SERVER)
        for i in range(len(payload)):
            sniffer.feed(payload[i:i + 1])
        self.assertIs(sniffer.state, SniffState.DONE)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.alpn, "h2")


class HelloInfoDefaultsTest(unittest.TestCase):
    def test_default_fields_are_unknown(self) -> None:
        info = HelloInfo(kind=CLIENT)
        self.assertEqual(info.tls_version, UNKNOWN)
        self.assertEqual(info.cipher, UNKNOWN)
        self.assertEqual(info.alpn, UNKNOWN)
        self.assertIsNone(info.sni)


if __name__ == "__main__":
    unittest.main()
