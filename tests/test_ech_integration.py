"""ECH 标记的独立验证：异常面 / 流式路径 / QUIC 复用 / 统计分键 / 未命中零影响。

本文件刻意**不复用** ``test_tls_sniffer`` 的夹具，自带可精确控制原始扩展字节的
构造器，以便覆盖畸形与边界扩展。判定基准（不放宽）：

1. ``encrypted_client_hello`` 扩展类型为 ``0xFE0D``，客户端发起时外层
   ``ClientHelloOuter`` 明文携带，扩展体是 HPKE 密文（GREASE ECH 为随机字节）
   → 实现只允许判「存在」（``HelloInfo.ech`` / ``ProtocolStack.ech_ext``），
   任何解析扩展内容的动作都是缺陷。
2. RFC 9849 §6.2 允许无 ECHConfig 的客户端发送假的 ECH 扩展（GREASE ECH），
   §10.10.4 明确真 ECH 与 GREASE ECH 对被动观察者不可区分 → 「扩展存在」不等于
   「ECH 生效」。``ProtocolStack.ech`` 因此额外要求外层 SNI 命中 ECH 掩护域名
   （``public_name``）；服务端是否接受仍不可判定。
3. QUIC / HTTP3 侧复用 ``parse_hello``，ECH 判定必须自动生效。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from ech_env_isolation import ConfigIsolatedCase
from snitap.protocol import ECH_MARK, UNKNOWN, ProtocolStack, StackRow
from snitap.stats import Stats
from snitap.tls_sniffer import (
    CLIENT,
    SERVER,
    HelloInfo,
    SniffState,
    TlsSniffer,
    _ParseError,
    parse_client_hello,
    parse_hello,
)

EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ECH = 0xFE0D
# GREASE 值（RFC 8701）：与 0xFE0D 混排时必须互不干扰
GREASE_A = 0x0A0A
GREASE_B = 0xFAFA

_ECH_TAG = f" {ECH_MARK}"


# ---------------------------------------------------------------- 构造器

def ext(ext_type: int, payload: bytes) -> bytes:
    """按 TLS 扩展线格式打包一个扩展（类型 + 2B 长度 + 扩展体）。"""
    return ext_type.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


def sni_ext(host: str) -> bytes:
    """server_name 扩展（单个 host_name 条目）。"""
    name = host.encode("ascii")
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    return ext(EXT_SERVER_NAME, len(entry).to_bytes(2, "big") + entry)


def alpn_ext(protocols: tuple[bytes, ...]) -> bytes:
    """ALPN 扩展（多条偏好）。"""
    entries = b"".join(bytes([len(p)]) + p for p in protocols)
    return ext(EXT_ALPN, len(entries).to_bytes(2, "big") + entries)


def sv_ext(versions: tuple[int, ...]) -> bytes:
    """ClientHello 版 supported_versions 扩展（1B list_len + N×2B）。"""
    payload = bytes([len(versions) * 2]) + b"".join(
        v.to_bytes(2, "big") for v in versions
    )
    return ext(EXT_SUPPORTED_VERSIONS, payload)


def ech_ext(payload: bytes) -> bytes:
    """0xFE0D encrypted_client_hello 扩展。"""
    return ext(EXT_ECH, payload)


def build_ch_body(
    extensions: bytes,
    *,
    ciphers: tuple[int, ...] = (0x1301, 0x1302),
    legacy_version: int = 0x0303,
) -> bytes:
    """把任意扩展字节拼成结构合法的 ClientHello 主体（不含 4B handshake 头）。"""
    cipher_bytes = b"".join(c.to_bytes(2, "big") for c in ciphers)
    return (
        legacy_version.to_bytes(2, "big")
        + bytes(range(32))                 # random
        + b"\x20" + bytes(32)              # legacy_session_id（32 字节）
        + len(cipher_bytes).to_bytes(2, "big") + cipher_bytes
        + b"\x01\x00"                      # compression_methods
        + len(extensions).to_bytes(2, "big") + extensions
    )


def wrap_record(body: bytes, *, handshake_type: int = 0x01) -> bytes:
    """把 hello 主体包成完整 TLS record（5B record 头 + 4B handshake 头）。"""
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


# GREASE ECH 的扩展体：客户端随机填充的假密文（确定性取字节以便复现）
GREASE_PAYLOAD = bytes.fromhex("3f9c11d702e84baa5c6e0d91b7")


def assert_parse_error_or_info(case: unittest.TestCase, body: bytes) -> None:
    """断言 ``body`` 的解析结局只有两种：成功，或抛 ``_ParseError``。

    ``_ParseError`` 是「长度字段矛盾」的唯一约定出口；IndexError /
    struct.error / ValueError 等一律视为源码缺陷。
    """
    try:
        info = parse_client_hello(body)
    except _ParseError:
        return
    except Exception as exc:  # noqa: BLE001 - 这里就是要抓所有意外异常类型
        case.fail(f"畸形 hello 抛出了非 _ParseError 异常：{type(exc).__name__}: {exc}")
    else:
        case.assertIsInstance(info, HelloInfo)


class MalformedEchExtensionTest(unittest.TestCase):
    """风险点 1：畸形 / 边界 ECH 扩展不得产生 IndexError / struct.error / 未捕获异常。"""

    def test_zero_length_ech_extension_marks_true(self) -> None:
        info = parse_client_hello(build_ch_body(ech_ext(b"")))
        self.assertTrue(info.ech)
        self.assertEqual(info.ext_count, 1)

    def test_random_bytes_payload_is_never_parsed(self) -> None:
        # 300 字节随机感字节（远超真实 ECH 的定长字段），只判存在
        payload = (GREASE_PAYLOAD * 20)[:300]
        body = build_ch_body(sni_ext("public.example") + ech_ext(payload))
        info = parse_client_hello(body)
        self.assertTrue(info.ech)
        self.assertEqual(info.sni, "public.example")  # 掩护域名照常解出

    def test_ech_extension_declares_more_than_extension_area(self) -> None:
        # ECH 声明 64 字节，但扩展区只留下 8 字节 → 长度矛盾 → _ParseError
        truncated = (
            EXT_ECH.to_bytes(2, "big") + (64).to_bytes(2, "big") + GREASE_PAYLOAD[:8]
        )
        body = build_ch_body(truncated)
        with self.assertRaises(_ParseError):
            parse_client_hello(body)

    def test_ech_extension_declares_max_length(self) -> None:
        # 声明 0xFFFF 字节，实际远不足 → 必须 _ParseError，不能越界读
        truncated = EXT_ECH.to_bytes(2, "big") + b"\xff\xff" + GREASE_PAYLOAD
        with self.assertRaises(_ParseError):
            parse_client_hello(build_ch_body(truncated))

    def test_truncated_ech_extension_through_sniffer_becomes_not_tls(self) -> None:
        # 长度矛盾经流式外壳必须转成 NOT_TLS，且 info 保持 None
        truncated = (
            EXT_ECH.to_bytes(2, "big") + (32).to_bytes(2, "big") + GREASE_PAYLOAD
        )
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(wrap_record(build_ch_body(truncated)))
        self.assertIs(sniffer.state, SniffState.NOT_TLS)
        self.assertIsNone(sniffer.info)

    def test_ech_as_last_extension(self) -> None:
        body = build_ch_body(sni_ext("last.example") + ech_ext(GREASE_PAYLOAD))
        info = parse_client_hello(body)
        self.assertTrue(info.ech)
        self.assertEqual(info.ext_count, 2)

    def test_ech_as_first_extension(self) -> None:
        body = build_ch_body(
            ech_ext(GREASE_PAYLOAD)
            + sni_ext("first.example")
            + alpn_ext((b"h2",))
            + sv_ext((0x0304,))
        )
        info = parse_client_hello(body)
        self.assertTrue(info.ech)
        self.assertEqual(info.ext_count, 4)
        self.assertEqual(info.sni, "first.example")
        self.assertEqual(info.alpn, "h2")
        self.assertEqual(info.tls_version, "TLS1.3")

    def test_ech_mixed_with_grease_extensions(self) -> None:
        body = build_ch_body(
            ext(GREASE_A, b"\x00")
            + ech_ext(GREASE_PAYLOAD)
            + ext(GREASE_B, b"")
            + sni_ext("mixed.example")
        )
        info = parse_client_hello(body)
        self.assertTrue(info.ech)
        self.assertEqual(info.ext_count, 4)
        self.assertEqual(info.sni, "mixed.example")

    def test_grease_extension_alone_is_not_ech(self) -> None:
        # 0x0A0A / 0xFAFA 与 0xFE0D 无关，不得误判
        info = parse_client_hello(
            build_ch_body(ext(GREASE_A, b"\x01") + ext(GREASE_B, b"\x02"))
        )
        self.assertFalse(info.ech)

    def test_ech_with_trailing_partial_header_is_ignored(self) -> None:
        # 扩展区末尾剩 2 字节（不足一个 4B 扩展头）：循环退出，不抛异常
        trailing = ech_ext(GREASE_PAYLOAD) + b"\xfe\x0d"
        info = parse_client_hello(build_ch_body(trailing))
        self.assertTrue(info.ech)
        self.assertEqual(info.ext_count, 1)

    def test_ech_present_but_sibling_extension_truncated_still_raises(self) -> None:
        # ECH 合法、后继 SNI 长度矛盾：整包仍是不可解析 hello
        bad_sni = EXT_SERVER_NAME.to_bytes(2, "big") + (200).to_bytes(2, "big") + b"\x00\x00"
        body = build_ch_body(ech_ext(GREASE_PAYLOAD) + bad_sni)
        with self.assertRaises(_ParseError):
            parse_client_hello(body)

    def test_all_prefix_truncations_never_raise_foreign_exception(self) -> None:
        """逐字节截断整个 ECH hello：每一段前缀都只能是「成功」或 ``_ParseError``。"""
        body = build_ch_body(
            sni_ext("fuzz.example")
            + ech_ext(GREASE_PAYLOAD)
            + alpn_ext((b"h2",))
            + sv_ext((0x0304,))
        )
        for cut in range(len(body) + 1):
            with self.subTest(cut=cut):
                assert_parse_error_or_info(self, body[:cut])

    def test_random_body_mutations_never_raise_foreign_exception(self) -> None:
        """把 ECH 的 2B 长度字段改成各种值，异常类型必须恒为 ``_ParseError``。"""
        prefix = sni_ext("len.example")
        for declared in (0, 1, 2, 7, 255, 256, 4095, 65535):
            with self.subTest(declared=declared):
                raw = (
                    prefix
                    + EXT_ECH.to_bytes(2, "big")
                    + declared.to_bytes(2, "big")
                    + GREASE_PAYLOAD
                )
                assert_parse_error_or_info(self, build_ch_body(raw))


class StreamingEchPathTest(unittest.TestCase):
    """风险点 2：走 ``TlsSniffer`` 分段 feed 的终态，而不是只测纯函数。"""

    def setUp(self) -> None:
        self.body = build_ch_body(
            sni_ext("stream.example") + alpn_ext((b"h2",)) + ech_ext(GREASE_PAYLOAD)
        )
        self.record = wrap_record(self.body)

    def _feed_in_chunks(self, size: int) -> TlsSniffer:
        sniffer = TlsSniffer(CLIENT)
        for start in range(0, len(self.record), size):
            sniffer.feed(self.record[start:start + size])
        return sniffer

    def test_byte_by_byte_reassembly_marks_ech(self) -> None:
        sniffer = self._feed_in_chunks(1)
        self.assertIs(sniffer.state, SniffState.DONE)
        assert sniffer.info is not None
        self.assertTrue(sniffer.info.ech)
        self.assertEqual(sniffer.info.sni, "stream.example")

    def test_two_chunk_split_inside_ech_extension(self) -> None:
        # 切点落在 ECH 扩展体中间
        cut = self.record.index(bytes.fromhex("fe0d")) + 4 + 5
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(self.record[:cut])
        self.assertFalse(sniffer.finished)
        sniffer.feed(self.record[cut:])
        self.assertIs(sniffer.state, SniffState.DONE)
        assert sniffer.info is not None
        self.assertTrue(sniffer.info.ech)

    def test_split_across_record_header(self) -> None:
        # 只喂到 record 头第 3 字节，嗅探必须保持未决
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(self.record[:3])
        self.assertIs(sniffer.state, SniffState.NEED_RECORD)
        self.assertIsNone(sniffer.info)
        sniffer.feed(self.record[3:])
        assert sniffer.info is not None
        self.assertTrue(sniffer.info.ech)

    def test_split_across_handshake_header(self) -> None:
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(self.record[:7])
        self.assertIs(sniffer.state, SniffState.NEED_HANDSHAKE)
        sniffer.feed(self.record[7:])
        assert sniffer.info is not None
        self.assertTrue(sniffer.info.ech)

    def test_ech_survives_extra_trailing_bytes(self) -> None:
        sniffer = TlsSniffer(CLIENT)
        sniffer.feed(self.record)
        sniffer.feed(b"\x17\x03\x03\x00\x05hello")
        assert sniffer.info is not None
        self.assertTrue(sniffer.info.ech)

    def test_without_ech_streaming_stays_false(self) -> None:
        plain = wrap_record(build_ch_body(sni_ext("plain.example")))
        sniffer = TlsSniffer(CLIENT)
        for start in range(0, len(plain), 3):
            sniffer.feed(plain[start:start + 3])
        self.assertIs(sniffer.state, SniffState.DONE)
        assert sniffer.info is not None
        self.assertFalse(sniffer.info.ech)


class QuicReuseEchTest(unittest.TestCase):
    """风险点 5：QUIC / HTTP3 复用 ``parse_hello``，ECH 判定必须自动生效。"""

    def test_parse_hello_client_body_with_ech(self) -> None:
        body = build_ch_body(
            sni_ext("h3.example") + alpn_ext((b"h3",)) + sv_ext((0x0304,))
            + ech_ext(GREASE_PAYLOAD)
        )
        info = parse_hello(CLIENT, body)
        self.assertTrue(info.ech)
        self.assertEqual(info.alpn, "h3")
        self.assertEqual(info.sni, "h3.example")

    def test_parse_hello_server_body_with_ech(self) -> None:
        # 服务端方向仅 HelloRetryRequest 会明文回带；标记只表示「携带该扩展」
        extensions = ech_ext(bytes.fromhex("00112233"))
        body = (
            b"\x03\x03"
            + bytes(range(32))
            + b"\x20" + bytes(32)
            + b"\x13\x01"
            + b"\x00"
            + len(extensions).to_bytes(2, "big") + extensions
        )
        info = parse_hello(SERVER, body)
        self.assertTrue(info.ech)
        self.assertIsNone(info.sni)

    def test_quic_stack_gets_ech_suffix(self) -> None:
        # 把 QUIC 侧解出的 info 走一遍协议栈：安全层必须带 ECH 后缀。
        # 真 ECH 的外层 SNI 必然是掩护域名，故夹具用 cloudflare-ech.com。
        body = build_ch_body(alpn_ext((b"h3",)) + ech_ext(GREASE_PAYLOAD))
        info = parse_hello(CLIENT, body)
        stack = ProtocolStack(
            sni="cloudflare-ech.com",
            transport="QUIC",
            quic_version="v1",
            tls_version=info.tls_version,
            cipher=info.cipher,
            alpn=info.alpn,
            ech=info.ech,
            ech_ext=info.ech,
        )
        self.assertEqual(stack.transport_label, "QUIC/v1")
        self.assertEqual(stack.security_label, f"{stack.security}{_ECH_TAG}")


class NoEchZeroImpactTest(unittest.TestCase):
    """风险点 4：不带 ECH 时，三层值与统计键必须与改动前逐字一致。"""

    def test_security_label_equals_security(self) -> None:
        for cipher in ("A128GCM", "A256GCM", "0xc02f", UNKNOWN):
            with self.subTest(cipher=cipher):
                stack = ProtocolStack(tls_version="TLS1.3", cipher=cipher, alpn="h2")
                self.assertEqual(stack.security_label, stack.security)

    def test_key_is_exactly_the_legacy_four_tuple(self) -> None:
        stack = ProtocolStack(
            sni="api.example.com", alpn="h2", tls_version="TLS1.3", cipher="A128GCM"
        )
        self.assertEqual(
            stack.key, ("api.example.com", "h2", "TCP", "TLS1.3/A128GCM")
        )
        self.assertIsInstance(stack.key, tuple)
        self.assertEqual(len(stack.key), 4)

    def test_caption_has_no_extra_separator_or_suffix(self) -> None:
        stack = ProtocolStack(
            sni="www.example.org",
            transport="QUIC",
            quic_version="v2",
            tls_version="TLS1.3",
            cipher="A256GCM",
            alpn="h3",
        )
        self.assertEqual(stack.caption(), "h3 · QUIC/v2 · TLS1.3/A256GCM")
        self.assertNotIn(ECH_MARK, stack.caption())
        self.assertFalse(stack.caption().endswith(" "))
        self.assertNotIn("  · ", stack.caption())

    def test_ech_mark_is_empty_string_when_false(self) -> None:
        stack = ProtocolStack(tls_version="TLS1.3", cipher="A128GCM")
        self.assertEqual(stack.ech_mark, "")
        self.assertFalse(stack.ech)
        self.assertFalse(StackRow.from_stack(stack, 1).has_ech)


class StatsEchPartitionTest(unittest.TestCase):
    """风险点 3：统计分键语义 —— 同域名同三层，带 / 不带 ECH 必须两行。"""

    def _stack(self, *, ech: bool, **kwargs: object) -> ProtocolStack:
        base: dict[str, object] = dict(
            sni="api.example.com",
            alpn="h2",
            tls_version="TLS1.3",
            cipher="A128GCM",
            transport="TCP",
        )
        base.update(kwargs)
        return ProtocolStack(**base, ech=ech)  # type: ignore[arg-type]

    def test_same_domain_two_rows(self) -> None:
        stats = Stats()
        stats.add_stack(self._stack(ech=True))
        stats.add_stack(self._stack(ech=False))
        rows = stats.snapshot_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(stats.distinct, 2)
        self.assertEqual({row.domain for row in rows}, {"api.example.com"})
        self.assertEqual({row.security for row in rows},
                         {"TLS1.3/A128GCM", "TLS1.3/A128GCM ECH"})

    def test_ech_hits_matches_sum_of_ech_row_counts(self) -> None:
        stats = Stats()
        for _ in range(4):
            stats.add_stack(self._stack(ech=True))
        for _ in range(3):
            stats.add_stack(self._stack(ech=False))
        self.assertEqual(stats.ech_hits, 4)
        self.assertEqual(stats.total_hits, 7)
        ech_rows = [row for row in stats.snapshot_rows() if row.has_ech]
        self.assertEqual(sum(row.count for row in ech_rows), stats.ech_hits)

    def test_ech_hits_zero_when_never_marked(self) -> None:
        stats = Stats()
        for _ in range(5):
            stats.add_stack(self._stack(ech=False))
        self.assertEqual(stats.ech_hits, 0)
        self.assertEqual(stats.ech_hits, sum(r.count for r in stats.snapshot_rows() if r.has_ech))

    def test_sort_key_is_full_four_tuple_and_idempotent(self) -> None:
        # 构造大量同次数行，验证 (-count, domain, app, transport, security) 全字段参与
        stats = Stats()
        combos = [
            ("b.example", "h2", "TCP", False),
            ("b.example", "h2", "TCP", True),
            ("a.example", "h2", "TCP", True),
            ("a.example", "h3", "TCP", True),
            ("a.example", "h3", "QUIC", True),
            ("a.example", "h3", "QUIC", False),
        ]
        for domain, app, transport, ech in combos:
            kwargs: dict[str, object] = {"alpn": app, "transport": transport}
            if transport == "QUIC":
                kwargs["quic_version"] = "v1"
            stats.add_stack(self._stack(ech=ech, sni=domain, **kwargs))

        rows = stats.snapshot_rows()
        expected = sorted(
            rows, key=lambda r: (-r.count, r.domain, r.app, r.transport, r.security)
        )
        self.assertEqual([r.key for r in rows], [r.key for r in expected])
        # 连续两次快照顺序完全一致（逐帧不跳行）
        self.assertEqual([r.key for r in rows], [r.key for r in stats.snapshot_rows()])
        self.assertEqual(len({r.key for r in rows}), len(rows))  # 键唯一

    def test_ech_does_not_leak_into_domain_app_or_transport(self) -> None:
        stack = self._stack(ech=True)
        row = StackRow.from_stack(stack, 1)
        self.assertEqual(row.domain, "api.example.com")
        self.assertEqual(row.app, "h2")
        self.assertEqual(row.transport, "TCP")
        self.assertTrue(row.security.endswith(_ECH_TAG))


class EchEndToEndTest(ConfigIsolatedCase):
    """风险点 3 + 4：真实字节 → TcpFlow → Stats 全链路。

    夹具用 ``cloudflare-ech.com`` 作为「确证真 ECH」的掩护域名，故继承
    :class:`ech_env_isolation.ConfigIsolatedCase`：开发机导出
    ``SNITAP_ECH_PUBLIC_NAMES`` 时用例先落默认基线再断言。
    """

    def test_ech_bytes_reach_stats_as_separate_row(self) -> None:
        from snitap.flow import TcpFlow

        collected: list[ProtocolStack] = []
        stats = Stats()

        def on_stack(stack: ProtocolStack) -> None:
            collected.append(stack)
            stats.add_stack(stack)

        # 连接 1：外层 SNI 是 ECH 掩护域名 + 携带扩展 → 确证生效
        flow_ech = TcpFlow(on_stack)
        sink = flow_ech.sink("up")
        assert sink is not None
        sink(wrap_record(
            build_ch_body(
                sni_ext("cloudflare-ech.com") + alpn_ext((b"h2",)) + ech_ext(GREASE_PAYLOAD)
            )
        ))
        flow_ech.close()

        # 连接 2：同域名同三层，不带 ECH 扩展
        flow_plain = TcpFlow(on_stack)
        sink = flow_plain.sink("up")
        assert sink is not None
        sink(wrap_record(build_ch_body(sni_ext("cloudflare-ech.com") + alpn_ext((b"h2",)))))
        flow_plain.close()

        self.assertEqual(len(collected), 2)
        self.assertTrue(collected[0].ech)
        self.assertTrue(collected[0].ech_ext)
        self.assertFalse(collected[1].ech)
        self.assertFalse(collected[1].ech_ext)
        rows = stats.snapshot_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(stats.ech_hits, 1)
        self.assertEqual(stats.ech_ext_hits, 1)
        self.assertEqual(stats.total_hits, 2)
        self.assertEqual([r.count for r in rows], [1, 1])


class StatsEventBackwardCompatTest(unittest.TestCase):
    """风险点 6：``StatsEvent.ech_hits`` 默认 0，旧构造方式仍可用。"""

    def test_default_is_zero(self) -> None:
        from snitap.events import StatsEvent

        event = StatsEvent(
            ts="00:00:00", rows=(), tcp_conns=0, udp_sessions=0,
            total_hits=0, distinct=0,
        )
        self.assertEqual(event.ech_hits, 0)

    def test_legacy_positional_construction_still_works(self) -> None:
        from snitap.events import StatsEvent

        # 旧代码按位置传前 6 个字段，第 7 个位置仍是 truncated（不能被打乱）
        event = StatsEvent("00:00:00", (), 1, 2, 3, 4, True)
        self.assertEqual(event.ech_hits, 0)
        self.assertTrue(event.truncated)

    def test_explicit_ech_hits_is_kept(self) -> None:
        from snitap.events import StatsEvent

        event = StatsEvent(
            ts="00:00:00", rows=(), tcp_conns=0, udp_sessions=0,
            total_hits=7, distinct=2, ech_hits=4,
        )
        self.assertEqual(event.ech_hits, 4)


if __name__ == "__main__":
    unittest.main()
