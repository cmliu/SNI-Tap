"""QUIC Initial 嗅探单元测试。

核心夹具：**独立按 RFC 9001 附录 A 实现的加密侧**——密钥派生、AEAD 加密、
header protection 全部在本文件内用 cryptography 原语手写，
绝不调用被测的解密函数（quic_crypto.open_payload / quic_sniffer），
避免夹具与被测代码共享同一份错误导致假通过。

结构 / 降级用例始终运行；需要 cryptography 的加密用例用 skipUnless 跳过。
"""

from __future__ import annotations

import hashlib
import hmac
import pathlib
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from snitap import quic_crypto
from snitap.quic_crypto import KeySet
from snitap.quic_sniffer import (
    INITIAL_MAX_DATAGRAM,
    MAX_ATTEMPTS,
    LongHeader,
    QuicSniffer,
    looks_like_initial,
    parse_crypto_frames,
    parse_long_header,
)
from snitap.tls_sniffer import CLIENT, SERVER
from test_tls_sniffer import build_client_hello, build_server_hello

_V1 = 0x00000001
_V2 = 0x6B3343CF

try:  # 加密夹具依赖；缺失时结构/降级用例照常运行
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - 环境无 cryptography
    _HAS_CRYPTO = False

_CRYPTO_SALT = {
    _V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    _V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
_CRYPTO_LABELS = {
    _V1: (b"quic key", b"quic iv", b"quic hp"),
    _V2: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
}


# ------------------------------------------------------------- 加密夹具（独立实现）

def _varint(value: int) -> bytes:
    """QUIC varint 编码（测试夹具独立实现）。"""
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return bytes([(value >> 8) | 0x40, value & 0xFF])
    if value < 0x40000000:
        return bytes([(value >> 24) | 0x80]) + value.to_bytes(4, "big")[1:]
    return bytes([(value >> 56) | 0xC0]) + value.to_bytes(8, "big")[1:]


def _expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label（夹具独立实现，不 import 被测模块）。

    FIX-6 回归：``info`` 必须按 RFC 8446 §7.1 的 HkdfLabel 编码——
    ``uint16(length) || uint8(len("tls13 "+label)) || "tls13 "+label || uint8(0)``，
    且只能做 HKDF-**Expand**（``secret`` 已是 PRK，再 Extract 会算错）。
    本夹具早期版本与被测代码犯了同一个错，导致 4 个解密用例假通过；
    正确性由 ``Rfc9001VectorTest`` 用官方测试向量锁死。
    """
    full_label = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + b"\x00"
    return _hkdf_expand(secret, info, length)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3 HKDF-Expand（纯 HMAC，不做 Extract）。"""
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def _derive_keys(version: int, dcid: bytes, is_client: bool) -> KeySet:
    """RFC 9001 §5.2 密钥派生（夹具独立实现）。"""
    salt = _CRYPTO_SALT[version]
    labels = _CRYPTO_LABELS[version]
    initial_secret = hmac.new(salt, dcid, hashlib.sha256).digest()
    secret = _expand_label(
        initial_secret, b"client in" if is_client else b"server in", 32
    )
    return KeySet(
        key=_expand_label(secret, labels[0], 16),
        iv=_expand_label(secret, labels[1], 12),
        hp=_expand_label(secret, labels[2], 16),
    )


def _hello_message(record: bytes) -> bytes:
    """完整 TLS record → handshake 消息（type + 3B len + body），QUIC 无 record 头。"""
    hello_len = int.from_bytes(record[6:9], "big")
    body = record[9:9 + hello_len]
    hs_type = 0x01 if record[5] == 0x01 else 0x02
    return bytes([hs_type]) + len(body).to_bytes(3, "big") + body


def _encrypt_initial(
    version: int,
    *,
    header_dcid: bytes,
    header_scid: bytes,
    key_dcid: bytes | None = None,
    is_client: bool = True,
    pn: int = 0,
    crypto_offset: int = 0,
    crypto_data: bytes = b"",
) -> bytes:
    """构造一个加密的 QUIC Initial 数据报（RFC 9001 附录 A 流程）。

    加密顺序：AEAD（aad=未保护头+明文PN）→ 取样本算 HP 掩码 → 打掩码。
    """
    keys = _derive_keys(version, key_dcid if key_dcid is not None else header_dcid, is_client)

    frame = b"\x06" + _varint(crypto_offset) + _varint(len(crypto_data)) + crypto_data
    # payload 区（PN+密文）至少 20 字节，保证 HP 样本可用：不足则补 PADDING
    pn_len = 1
    plaintext = frame + b"\x00" * max(0, 20 - pn_len - (len(frame) + 16))

    unprotected_first = 0xD0 if version == _V2 else 0xC0
    # v1: long+fixed+Initial(00)+reserved 0+PN len 1 → 0xC0
    # v2: Initial 的类型号是 01（RFC 9369 §3.2）→ 0xD0
    body_len = pn_len + len(plaintext) + 16
    header = (
        bytes([unprotected_first])
        + version.to_bytes(4, "big")
        + bytes([len(header_dcid)]) + header_dcid
        + bytes([len(header_scid)]) + header_scid
        + _varint(0)          # 空 token
        + _varint(body_len)   # PN + payload 总长
    )
    pn_offset = len(header)
    pn_bytes = pn.to_bytes(pn_len, "big")

    nonce = bytes(a ^ b for a, b in zip(keys.iv, pn.to_bytes(12, "big")))
    aad = header + pn_bytes
    ct = AESGCM(keys.key).encrypt(nonce, plaintext, aad)

    datagram = header + pn_bytes + ct
    sample = datagram[pn_offset + 4:pn_offset + 20]
    encryptor = Cipher(algorithms.AES(keys.hp), modes.ECB()).encryptor()
    mask = (encryptor.update(sample) + encryptor.finalize())[:5]

    protected = bytes([datagram[0] ^ (mask[0] & 0x0F)])
    protected += header[1:]
    protected += bytes(b ^ m for b, m in zip(pn_bytes, mask[1:1 + pn_len]))
    return protected + ct


def _make_client_hello_record(**kwargs) -> bytes:
    return build_client_hello("quic.example.org", alpn=b"h3", **kwargs)


# ---------------------------------------------------------------- 密钥派生向量


@unittest.skipUnless(_HAS_CRYPTO, "需要 cryptography")
class Rfc9001VectorTest(unittest.TestCase):
    """RFC 9001 附录 A.1 官方测试向量：锁死 Initial 密钥派生。

    FIX-6 背景：``hkdf_expand_label`` 曾同时犯两个错——
    info 缺 label 长度前缀与空 context 长度字节、且用 ``HKDF(...).derive()``
    多做了一次 Extract。两处错误叠加后**任何真实 Initial 都无法解密**，
    而当时的手写加密夹具犯了同一个错，4 个解密用例因此假通过。
    本用例直接比对 RFC 公布的十六进制，夹具再也不能与实现共享同一个 bug。
    """

    DCID = bytes.fromhex("8394c8f03e515708")

    def test_client_and_server_initial_keys(self) -> None:
        client = quic_crypto.initial_keys(_V1, self.DCID, True)
        server = quic_crypto.initial_keys(_V1, self.DCID, False)
        assert client is not None and server is not None
        self.assertEqual(client.key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(client.iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(client.hp.hex(), "9f50449e04a0e810283a1e9933adedd2")
        self.assertEqual(server.key.hex(), "cf3a5331653c364c88f0f379b6067e37")
        self.assertEqual(server.iv.hex(), "0ac1493ca1905853b0bba03e")
        self.assertEqual(server.hp.hex(), "c206b8d9b9f0f37644430b490eeaa314")

    def test_secrets_match_rfc_vectors(self) -> None:
        initial_secret = hmac.new(_CRYPTO_SALT[_V1], self.DCID, hashlib.sha256).digest()
        self.assertEqual(
            initial_secret.hex(),
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
        )
        self.assertEqual(
            quic_crypto.hkdf_expand_label(initial_secret, b"client in", 32).hex(),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
        )
        self.assertEqual(
            quic_crypto.hkdf_expand_label(initial_secret, b"server in", 32).hex(),
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
        )

    def test_fixture_matches_rfc_vectors(self) -> None:
        """夹具自身也必须命中官方向量，否则它无法守门被测实现。"""
        keys = _derive_keys(_V1, self.DCID, True)
        self.assertEqual(keys.key.hex(), "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(keys.iv.hex(), "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(keys.hp.hex(), "9f50449e04a0e810283a1e9933adedd2")


class HkdfExpandBoundaryTest(unittest.TestCase):
    """``hkdf_expand`` 自身的 RFC 5869 向量与长度边界（QA 补充）。

    ``Rfc9001VectorTest`` 只覆盖「label 长度 12/16/32」，恰好都不跨块边界
    （SHA-256 一块 32 字节），因此 counter 递增逻辑没有被真正压到。这里用
    RFC 5869 附录 A.1（Test Case 1，L=42，跨两块）把多块路径钉死。
    """

    # RFC 5869 附录 A.1：IKM/SALT/info 均为十六进制常量
    IKM = bytes.fromhex("0b" * 22)
    SALT = bytes.fromhex("000102030405060708090a0b0c")
    INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    PRK_HEX = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    OKM_HEX = (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    def test_prk_matches_rfc5869(self) -> None:
        prk = hmac.new(self.SALT, self.IKM, hashlib.sha256).digest()
        self.assertEqual(prk.hex(), self.PRK_HEX)

    def test_multi_block_okm_matches_rfc5869(self) -> None:
        """L=42 跨 2 块，验证 T(i) 的 counter 递增与拼接顺序。"""
        prk = hmac.new(self.SALT, self.IKM, hashlib.sha256).digest()
        self.assertEqual(quic_crypto.hkdf_expand(prk, self.INFO, 42).hex(), self.OKM_HEX)

    def test_zero_length_returns_empty(self) -> None:
        """length=0 返回空串（QUIC 不会用到，但不得抛错/返回垃圾）。"""
        self.assertEqual(quic_crypto.hkdf_expand(b"\x01" * 32, b"ctx", 0), b"")

    def test_exactly_255_blocks_is_allowed(self) -> None:
        """RFC 5869 §2.3 上限 L <= 255*HashLen；恰好 255 块必须可算。"""
        out = quic_crypto.hkdf_expand(b"\x01" * 32, b"ctx", 255 * 32)
        self.assertEqual(len(out), 255 * 32)

    def test_over_255_blocks_raises(self) -> None:
        """溢出上限必须显式抛 ValueError，而不是静默截断/无限循环。"""
        with self.assertRaises(ValueError):
            quic_crypto.hkdf_expand(b"\x01" * 32, b"ctx", 255 * 32 + 1)


class CryptoOffsetZeroTest(unittest.TestCase):
    """FIX-7 的语义证明（不依赖 UdpForwarder 实现细节）。

    QUIC 的 CRYPTO 流是**有序字节流**，TLS 握手消息头（type + 3 字节长度）
    在 offset 0。丢掉承载 offset=0 的首个 Initial 后，只靠后续片段永远凑不出
    一条完整握手消息——这正是「只显示 QUIC/v1、域名与签名全是 -」的成因。
    """

    @unittest.skipUnless(_HAS_CRYPTO, "需要 cryptography")
    def test_missing_offset_zero_never_resolves_then_resolves_when_filled(self) -> None:
        quic_crypto.reset_cache()
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        message = _hello_message(_make_client_hello_record())
        split = len(message) // 2

        sniffer = QuicSniffer(CLIENT)
        # 模拟「首包从未喂给嗅探」：只喂 offset=split 的后续片段
        sniffer.feed(
            _encrypt_initial(
                _V1, header_dcid=dcid, header_scid=scid,
                crypto_offset=split, crypto_data=message[split:], pn=1,
            )
        )
        self.assertIsNone(sniffer.info)  # 缺 offset 0，拼不出 hello
        self.assertFalse(sniffer.finished)

        # 补上 offset=0 的片段 → 乱序缓冲被吐出，立刻解出
        sniffer.feed(
            _encrypt_initial(
                _V1, header_dcid=dcid, header_scid=scid,
                crypto_offset=0, crypto_data=message[:split], pn=0,
            )
        )
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "quic.example.org")


# ---------------------------------------------------------------- 结构解析用例


class HeaderStructureTest(unittest.TestCase):
    """长包头 / varint / 帧扫描的结构用例（不依赖 cryptography）。"""

    def test_looks_like_initial(self) -> None:
        self.assertTrue(looks_like_initial(b"\xc0\x00\x00\x00\x01"))
        self.assertFalse(looks_like_initial(b"\xd0\x00\x00\x00\x01"))  # v1 0-RTT
        self.assertFalse(looks_like_initial(b"\xe0\x00\x00\x00\x01"))  # Handshake
        self.assertFalse(looks_like_initial(b"\x40\x00\x00\x00\x01"))  # 短包头
        self.assertFalse(looks_like_initial(b""))
        self.assertFalse(looks_like_initial(b"\xc0\x00"))

    def test_looks_like_initial_v2_type_mapping(self) -> None:
        """RFC 9369 §3.2：v2 的 Initial 是 0b01，0b00 变成 Retry。"""
        self.assertTrue(looks_like_initial(b"\xd2\x6b\x33\x43\xcf"))   # v2 Initial
        self.assertFalse(looks_like_initial(b"\xc2\x6b\x33\x43\xcf"))  # v2 Retry
        self.assertFalse(looks_like_initial(b"\xe2\x6b\x33\x43\xcf"))  # v2 Handshake
        self.assertFalse(looks_like_initial(b"\xf2\x6b\x33\x43\xcf"))  # v2 0-RTT

    def test_parse_long_header(self) -> None:
        dcid, scid = b"\x11" * 8, b"\x22" * 4
        payload = (
            b"\xc0\x00\x00\x00\x01"
            + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid
            + b"\x00"          # token 长度 varint 0
            + b"\x41\x00"      # length varint 256
            + b"\x00" * 256
        )
        header = parse_long_header(payload)
        assert header is not None
        self.assertEqual(header.version, _V1)
        self.assertEqual(header.dcid, dcid)
        self.assertEqual(header.scid, scid)
        self.assertEqual(header.pn_offset, len(payload) - 256)
        self.assertEqual(header.packet_end, len(payload))
        self.assertEqual(header.token_len, 0)

    def test_parse_long_header_token_is_varint(self) -> None:
        # token 长度用 2 字节 varint（0x4040 = 64），不能按定长 1 字节读
        dcid, scid = b"\x11" * 4, b""
        payload = (
            b"\xc0\x00\x00\x00\x01"
            + bytes([len(dcid)]) + dcid
            + bytes([len(scid)])
            + b"\x40\x40"      # token_len = 64
            + b"\x41\x00"      # length = 256
            + b"\x00" * (64 + 256)
        )
        header = parse_long_header(payload)
        assert header is not None
        self.assertEqual(header.token_len, 64)

    def test_parse_long_header_version_negotiation_rejected(self) -> None:
        # version==0 由 feed 层处理为 vneg，本函数应返回 None
        payload = b"\x80\x00\x00\x00\x00\x04\x11\x22\x33\x44" + b"\x00" * 20
        self.assertIsNone(parse_long_header(payload))

    def test_parse_crypto_frames_varint_ack(self) -> None:
        # ACK（0x02）：largest=0x1234(2B varint) delay=0 range_count=0 first_range=0
        payload = (
            b"\x02\x52\x34\x00\x00\x00"  # 4 个 varint，全按 varint 读（FIX-2）
            + b"\x06\x00\x05hello"       # CRYPTO offset=0 len=5
        )
        frames = parse_crypto_frames(payload)
        self.assertEqual(frames, [(0, b"hello")])

    def test_parse_crypto_frames_ack_ecn(self) -> None:
        # ACK_ECN（0x03）：4 个 varint + 3 个 ECN varint，随后还有 CRYPTO
        payload = b"\x03\x01\x01\x00\x00\x01\x01\x01" + b"\x06\x00\x03abc"
        frames = parse_crypto_frames(payload)
        self.assertEqual(frames, [(0, b"abc")])

    def test_parse_crypto_frames_connection_close_stops(self) -> None:
        # CONNECTION_CLOSE 直接终止扫描，不解析字段（FIX-2）
        payload = b"\x1c\xff\xff\xff" + b"\x06\x00\x03abc"
        self.assertEqual(parse_crypto_frames(payload), [])

    def test_parse_crypto_frames_unknown_frame_stops(self) -> None:
        payload = b"\x06\x00\x03abc" + b"\x41\x00"
        self.assertEqual(parse_crypto_frames(payload), [(0, b"abc")])

    def test_parse_crypto_frames_padding_and_ping(self) -> None:
        payload = b"\x00\x00\x01\x06\x00\x03abc"
        self.assertEqual(parse_crypto_frames(payload), [(0, b"abc")])


# ---------------------------------------------------------------- 解密端到端用例


@unittest.skipUnless(_HAS_CRYPTO, "需要 cryptography")
class QuicSnifferDecryptTest(unittest.TestCase):
    def setUp(self) -> None:
        quic_crypto.reset_cache()

    def sniff(self, datagrams: list[bytes], kind: str = CLIENT, **kwargs) -> QuicSniffer:
        sniffer = QuicSniffer(kind, **kwargs)
        for datagram in datagrams:
            sniffer.feed(datagram)
        return sniffer

    def test_client_initial_end_to_end_v1(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        message = _hello_message(_make_client_hello_record())
        datagram = _encrypt_initial(
            _V1, header_dcid=dcid, header_scid=scid, crypto_data=message,
        )
        sniffer = self.sniff([datagram])
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "quic.example.org")
        self.assertEqual(sniffer.info.tls_version, "TLS1.3")
        self.assertEqual(sniffer.info.alpn, "h3")
        self.assertEqual(sniffer.info.cipher, "A128GCM")
        self.assertEqual(sniffer.quic_version, "v1")

    def test_v2_salt_and_labels(self) -> None:
        dcid, scid = b"\xc3" * 8, b"\xd4" * 4
        message = _hello_message(_make_client_hello_record())
        datagram = _encrypt_initial(
            _V2, header_dcid=dcid, header_scid=scid, crypto_data=message,
        )
        sniffer = self.sniff([datagram])
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "quic.example.org")
        self.assertEqual(sniffer.quic_version, "v2")

    def test_server_initial_uses_client_dcid_hint(self) -> None:
        # 服务端 Initial 的 wire DCID 是客户端 SCID，密钥必须从客户端 DCID 派生
        client_dcid, client_scid = b"\xa1" * 8, b"\xb2" * 4
        message = _hello_message(build_server_hello())
        datagram = _encrypt_initial(
            _V1,
            header_dcid=client_scid,       # 服务端包的 DCID = 客户端 SCID
            header_scid=b"\xe5" * 4,       # 服务端自己的 SCID
            key_dcid=client_dcid,          # 密钥从客户端首个 Initial 的 DCID 派生
            is_client=False,
            crypto_data=message,
        )
        sniffer = self.sniff([datagram], kind=SERVER, dcid_hint=client_dcid)
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        self.assertIsNone(sniffer.info.sni)
        self.assertEqual(sniffer.info.tls_version, "TLS1.3")
        self.assertEqual(sniffer.info.alpn, "h2")
        self.assertEqual(sniffer.quic_version, "v1")

    def test_crypto_split_across_datagrams(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        message = _hello_message(_make_client_hello_record())
        split = 40
        datagrams = [
            _encrypt_initial(
                _V1, header_dcid=dcid, header_scid=scid,
                crypto_offset=0, crypto_data=message[:split], pn=0,
            ),
            _encrypt_initial(
                _V1, header_dcid=dcid, header_scid=scid,
                crypto_offset=split, crypto_data=message[split:], pn=1,
            ),
        ]
        sniffer = self.sniff(datagrams)
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "quic.example.org")

    def test_invalid_tag_degrades(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        message = _hello_message(_make_client_hello_record())
        datagram = bytearray(
            _encrypt_initial(_V1, header_dcid=dcid, header_scid=scid, crypto_data=message)
        )
        datagram[-1] ^= 0xFF  # 破坏密文 → InvalidTag
        sniffer = self.sniff([bytes(datagram)] * MAX_ATTEMPTS)
        self.assertTrue(sniffer.finished)  # 尝试耗尽后放弃
        self.assertIsNone(sniffer.info)
        self.assertEqual(sniffer.quic_version, "v1")

    def test_unknown_version_degrades(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        datagram = (
            b"\xc0\xab\xcd\x12\x34"
            + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid
            + b"\x00\x41\x00"
            + b"\x00" * 256
        )
        self.assertGreaterEqual(len(datagram), 60)
        sniffer = self.sniff([datagram] * MAX_ATTEMPTS)
        self.assertTrue(sniffer.finished)
        self.assertIsNone(sniffer.info)
        self.assertEqual(sniffer.quic_version, "0xabcd1234")

    def test_version_negotiation_packet(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        datagram = (
            b"\x80\x00\x00\x00\x00"
            + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid
            + b"\x00\x00\x00\x01"          # 支持版本列表
            + b"\x00" * 40
        )
        self.assertGreaterEqual(len(datagram), 60)
        sniffer = self.sniff([datagram])
        self.assertTrue(sniffer.finished)  # 版本协商包立即完成
        self.assertIsNone(sniffer.info)
        self.assertEqual(sniffer.quic_version, "vneg")

    def test_oversized_datagram_skipped(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        message = _hello_message(_make_client_hello_record())
        datagram = _encrypt_initial(
            _V1, header_dcid=dcid, header_scid=scid, crypto_data=message,
        )
        oversized = datagram + b"\x00" * (INITIAL_MAX_DATAGRAM + 1 - len(datagram))
        sniffer = self.sniff([oversized] * MAX_ATTEMPTS)
        self.assertFalse(sniffer.finished)  # 异常尺寸不消耗尝试次数

    def test_attempts_exhausted_gives_up(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        datagram = (
            b"\xc0\x00\x00\x00\x01"
            + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid
            + b"\x00\x41\x00"
            + b"\x00" * 256
        )
        sniffer = self.sniff([datagram] * (MAX_ATTEMPTS + 1))
        self.assertTrue(sniffer.finished)
        self.assertIsNone(sniffer.info)


@unittest.skipUnless(_HAS_CRYPTO, "需要 cryptography")
class EchAndFragmentationTest(unittest.TestCase):
    """ECH 场景 + 大 ClientHello 分片：外层 SNI 仍可解，且在尝试预算内。

    背景：真 ECH 只加密 **ClientHelloInner**，外层 ClientHelloOuter 的 SNI
    仍是明文（RFC 9849 §5），值是该 ECHConfig 的 ``public_name``
    （Cloudflare 为 ``cloudflare-ech.com``）。因此被动嗅探能拿到的是
    outer SNI + ``0xFE0D`` 扩展是否存在，拿不到用户真正访问的域名。
    另一后果：带 ECH 的 ClientHello 普遍 >1150 字节，会被 QUIC 拆成
    2~3 个 Initial 包，必须靠 CRYPTO 流重组才能凑齐。
    """

    def setUp(self) -> None:
        quic_crypto.reset_cache()

    @staticmethod
    def _ech_payload(size: int) -> bytes:
        """构造一段无结构随机字节，模拟 encrypted_client_hello 扩展体。"""
        return bytes((i * 37 + 11) & 0xFF for i in range(size))

    def _message(self, ech_size: int) -> bytes:
        record = build_client_hello(
            "cloudflare-ech.com", alpn=b"h3", ech=self._ech_payload(ech_size),
        )
        return _hello_message(record)

    def test_ech_outer_sni_single_datagram(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        datagram = _encrypt_initial(
            _V1, header_dcid=dcid, header_scid=scid, crypto_data=self._message(300),
        )
        sniffer = QuicSniffer(CLIENT)
        sniffer.feed(datagram)
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        # 拿得到的是外层掩护域名，而不是用户真实访问的域名
        self.assertEqual(sniffer.info.sni, "cloudflare-ech.com")
        self.assertTrue(sniffer.info.ech)
        self.assertEqual(sniffer.info.alpn, "h3")

    def test_large_ech_hello_split_across_two_initials(self) -> None:
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        message = self._message(1200)  # 远超单个 Initial 的承载能力
        self.assertGreater(len(message), 1200)
        split = 1150
        datagrams = [
            _encrypt_initial(
                _V1, header_dcid=dcid, header_scid=scid,
                crypto_offset=0, crypto_data=message[:split], pn=0,
            ),
            _encrypt_initial(
                _V1, header_dcid=dcid, header_scid=scid,
                crypto_offset=split, crypto_data=message[split:], pn=1,
            ),
        ]
        sniffer = QuicSniffer(CLIENT)
        sniffer.feed(datagrams[0])
        self.assertFalse(sniffer.finished)  # 首片不足以还原 hello
        sniffer.feed(datagrams[1])
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "cloudflare-ech.com")
        self.assertTrue(sniffer.info.ech)

    def test_attempt_budget_covers_max_fragments(self) -> None:
        """尝试预算的边界：MAX_ATTEMPTS 片可解，再多一片就放弃（已知上限）。"""
        dcid, scid = b"\xa1" * 8, b"\xb2" * 4
        message = self._message(1200)
        chunk = -(-len(message) // MAX_ATTEMPTS)  # 向上取整
        datagrams = [
            _encrypt_initial(
                _V1, header_dcid=dcid, header_scid=scid,
                crypto_offset=offset, crypto_data=message[offset:offset + chunk], pn=index,
            )
            for index, offset in enumerate(range(0, len(message), chunk))
        ]
        self.assertEqual(len(datagrams), MAX_ATTEMPTS)
        sniffer = QuicSniffer(CLIENT)
        for datagram in datagrams:
            sniffer.feed(datagram)
        self.assertTrue(sniffer.finished)
        assert sniffer.info is not None
        self.assertEqual(sniffer.info.sni, "cloudflare-ech.com")

    def test_short_header_does_not_consume_attempt_budget(self) -> None:
        """FIX-8：1-RTT 短包头不可能携带 Initial 的 CRYPTO，不能占用尝试预算。"""
        sniffer = QuicSniffer(CLIENT)
        for _ in range(MAX_ATTEMPTS * 3):
            sniffer.feed(b"\x40" + b"\x00" * 300)  # 短包头
        self.assertFalse(sniffer.finished)


@unittest.skipIf(_HAS_CRYPTO, "仅验证依赖缺失时的降级路径")
class NoCryptographyDegradeTest(unittest.TestCase):
    def test_degrades_to_transport_only(self) -> None:
        sniffer = QuicSniffer(CLIENT)
        sniffer.feed(b"\xc0\x00\x00\x00\x01" + b"\x00" * 200)
        self.assertFalse(sniffer.finished)
        self.assertEqual(sniffer.quic_version, "v1")


@unittest.skipUnless(_HAS_CRYPTO, "需要 cryptography")
class AvailableFalseDegradeTest(unittest.TestCase):
    """available() 为 False 时仍设置 quic_version，直到 MAX_ATTEMPTS 耗尽。"""

    def test_degrades_without_finishing_early(self) -> None:
        with mock.patch.object(quic_crypto, "available", return_value=False):
            sniffer = QuicSniffer(CLIENT)
            datagram = b"\xc0\x00\x00\x00\x01\x08" + b"\xa1" * 8 + b"\x00" * 200
            for _ in range(MAX_ATTEMPTS - 1):
                sniffer.feed(datagram)
                self.assertFalse(sniffer.finished)
            sniffer.feed(datagram)
            self.assertTrue(sniffer.finished)
            self.assertEqual(sniffer.quic_version, "v1")
            self.assertIsNone(sniffer.info)


class KeyCacheTest(unittest.TestCase):
    def test_fifo_eviction(self) -> None:
        cache = quic_crypto.KeyCache()
        keys = KeySet(key=b"k", iv=b"i", hp=b"h")
        for i in range(128):
            cache.put(i, b"d", True, keys)
        cache.put(999, b"d", True, keys)  # 第 129 条，挤出最早的第 0 条
        self.assertIsNone(cache.get(0, b"d", True))
        self.assertIsNotNone(cache.get(1, b"d", True))
        self.assertIsNotNone(cache.get(999, b"d", True))


if __name__ == "__main__":
    unittest.main()
