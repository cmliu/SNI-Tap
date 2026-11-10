"""QUIC Initial 包密钥派生与解密（RFC 9001 / RFC 9369）。

全项目**唯一** import ``cryptography`` 的模块，且全部在函数内懒加载——
依赖缺失时 :func:`available` 返回 False，QUIC 嗅探优雅降级为仅传输层，
程序不崩、不噪音。

只做三件事：HKDF 派生 Initial 密钥、header protection 掩码、AEAD 解密。
包级解析逻辑在 ``quic_sniffer``，这里不做任何协议语义判断。
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections import OrderedDict
from dataclasses import dataclass

# Initial Salt（RFC 9001 §5.2）：仅 v1 与 v2；其余版本返回 None 走降级。
SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
# RFC 9369：v2 的 HKDF-Expand-Label 前缀仍是 "tls13 "，但 key/iv/hp 标签带 quicv2。
LABELS = {
    0x00000001: (b"quic key", b"quic iv", b"quic hp"),
    0x6B3343CF: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
}
LABEL_CLIENT, LABEL_SERVER = b"client in", b"server in"
KEY_LEN, IV_LEN, HP_LEN = 16, 12, 16

_AVAILABLE: bool | None = None


@dataclass(frozen=True)
class KeySet:
    """一组 Initial 密钥：AEAD key / nonce iv / header-protection hp。"""

    key: bytes
    iv: bytes
    hp: bytes


def available() -> bool:
    """探测 cryptography 是否可用；首次调用 try import，结果缓存。"""
    global _AVAILABLE
    if _AVAILABLE is None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
            _AVAILABLE = True
        except Exception:
            _AVAILABLE = False
    return _AVAILABLE


def hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）。

    结构（RFC 8446 §7.1 的 HkdfLabel）：

    .. code-block:: text

        struct {
            uint16 length;                      // 输出长度
            opaque label<7..255> = "tls13 " + Label;  // 1 字节长度前缀
            opaque context<0..255> = "";              // QUIC 恒为空，仍需 1 字节长度
        } HkdfLabel;

    两个易错点（FIX-6，均会导致密钥全错、解密恒定 InvalidTag）：
    1. ``info`` 必须带 **label 的 1 字节长度前缀** 与 **context 的 1 字节长度（0）**；
    2. 这里只能做 HKDF-**Expand**。传入的 ``secret`` 已经是 PRK（初始密钥由
       HKDF-Extract 得到），再用 ``HKDF(...).derive()`` 会多做一次 Extract，
       结果与 RFC 9001 附录 A 的测试向量不符。
    """
    full_label = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + b"\x00"
    return hkdf_expand(secret, info, length)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3 HKDF-Expand（纯 HMAC-SHA256，**不做** Extract）。"""
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        if counter > 255:
            raise ValueError("HKDF-Expand 超出 255 块上限")
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def initial_keys(version: int, dcid: bytes, is_client: bool) -> KeySet | None:
    """按 RFC 9001 §5.2 从 (版本, DCID, 方向) 派生 Initial 密钥。

    未收录版本 / 依赖缺失时返回 None。服务端方向传 ``is_client=False``，
    DCID 必须是**客户端首个 Initial 的 DCID**（服务端包的 DCID 是客户端 SCID）。
    """
    if not available():
        return None
    salt = SALTS.get(version)
    labels = LABELS.get(version)
    if salt is None or labels is None or not dcid:
        return None

    # initial_secret = HKDF-Extract(salt, ikm=dcid)（RFC 5869：HMAC 以 salt 为 key）
    initial_secret = hmac.new(salt, dcid, hashlib.sha256).digest()
    secret = hkdf_expand_label(initial_secret, LABEL_CLIENT if is_client else LABEL_SERVER, 32)
    return KeySet(
        key=hkdf_expand_label(secret, labels[0], KEY_LEN),
        iv=hkdf_expand_label(secret, labels[1], IV_LEN),
        hp=hkdf_expand_label(secret, labels[2], HP_LEN),
    )


def header_mask(hp_key: bytes, sample: bytes) -> bytes:
    """AES-128-ECB(hp_key, sample) 的前 5 字节。

    返回 5 字节：``mask[0]`` 用于还原 first byte，``mask[1:5]`` 用于 PN。
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return (encryptor.update(sample) + encryptor.finalize())[:5]


def open_payload(keys: KeySet, pn: int, aad: bytes, ct: bytes) -> bytes | None:
    """AES-GCM 解密 payload；认证失败（InvalidTag 等）返回 None。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # nonce = iv XOR pn（PN 左补零到 12 字节）
    nonce = bytes(a ^ b for a, b in zip(keys.iv, pn.to_bytes(IV_LEN, "big")))
    try:
        return AESGCM(keys.key).decrypt(nonce, ct, aad)
    except Exception:
        return None


class KeyCache:
    """(version, dcid, is_client) → KeySet 的缓存；上限 128 条，FIFO 淘汰。"""

    MAX_ENTRIES = 128

    def __init__(self) -> None:
        self._entries: OrderedDict[tuple[int, bytes, bool], KeySet] = OrderedDict()

    def get(self, version: int, dcid: bytes, is_client: bool) -> KeySet | None:
        return self._entries.get((version, dcid, is_client))

    def put(self, version: int, dcid: bytes, is_client: bool, keys: KeySet) -> None:
        key = (version, dcid, is_client)
        if key in self._entries:
            return
        self._entries[key] = keys
        while len(self._entries) > self.MAX_ENTRIES:
            self._entries.popitem(last=False)


# 模块级默认缓存：QuicSniffer 缺省共用，测试可用 reset_cache() 整体重置。
_DEFAULT_CACHE = KeyCache()


def default_cache() -> KeyCache:
    """返回模块级共享缓存。"""
    return _DEFAULT_CACHE


def reset_cache() -> None:
    """清空模块级密钥缓存（测试用）。"""
    global _DEFAULT_CACHE
    _DEFAULT_CACHE = KeyCache()
