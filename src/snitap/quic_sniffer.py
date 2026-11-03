"""QUIC 长包头嗅探：解密 Initial 包、扫描 CRYPTO 帧、重组 TLS 握手并委托解析。

范围（决策 D3）：只解 Initial，但**双向都解**——服务端 Initial 也用
「客户端首个 Initial 的 DCID」派生密钥（``server in`` 标签），这是 h3
唯一能拿到协商值的路径。Handshake / 1-RTT 全加密，不碰。

关键实现点（FIX-1）：
- PN 长度编码在 first byte 的低 2 位，且必须先 XOR 还原 first byte 再取；
- AAD 是未受保护的头部，first byte 用还原后的值。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from . import quic_crypto
from .protocol import UNKNOWN, quic_version_name
from .tls_sniffer import CLIENT, SERVER, HelloInfo, parse_hello

log = logging.getLogger(__name__)

INITIAL_MAX_DATAGRAM = 1500  # 超过则视作异常尺寸直接跳过
MAX_CRYPTO_BUFFER = 16 * 1024
MAX_ATTEMPTS = 4             # 喂入 MAX_ATTEMPTS 个报文仍无果即放弃
MIN_DATAGRAM = 60            # 小于则视作异常尺寸直接跳过


def _read_varint(data: bytes, pos: int) -> tuple[int, int] | None:
    """QUIC varint：返回 (值, 新偏移)；越界返回 None。

    首字节高 2 位定长度：00=1B 01=2B 10=4B 11=8B。
    """
    if pos >= len(data):
        return None
    first = data[pos]
    length = 1 << (first >> 6)
    if pos + length > len(data):
        return None
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[pos + i]
    return value, pos + length


@dataclass(frozen=True)
class LongHeader:
    """一次长包头解析的产物（不含 PN 与 payload）。"""

    version: int
    dcid: bytes
    scid: bytes
    pn_offset: int
    packet_end: int
    token_len: int


def looks_like_initial(data: bytes) -> bool:
    """首字节判型：long header + fixed bit 且包类型为 Initial(00)。"""
    if not data:
        return False
    return (data[0] & 0xC0) == 0xC0 and ((data[0] & 0x30) >> 4) == 0


def parse_long_header(data: bytes) -> LongHeader | None:
    """解析 QUIC v1/v2 长包头（仅 Initial）；结构矛盾或越界返回 None。

    解析顺序：first byte 判型 → version → DCID → SCID → token(varint!) →
    length(varint，PN+payload 总长)。版本协商包（version==0）无 token/PN，
    由调用方在进入本函数之前处理。
    """
    if len(data) < 6:
        return None
    first = data[0]
    if not looks_like_initial(data):
        return None
    version = int.from_bytes(data[1:5], "big")
    if version == 0:
        return None

    dcid_len = data[5]
    pos = 6
    if pos + dcid_len > len(data):
        return None
    dcid = data[pos:pos + dcid_len]
    pos += dcid_len
    if pos >= len(data):
        return None
    scid_len = data[pos]
    pos += 1
    if pos + scid_len > len(data):
        return None
    scid = data[pos:pos + scid_len]
    pos += scid_len

    token = _read_varint(data, pos)  # token 长度是 varint，不是定长 1 字节
    if token is None:
        return None
    token_len, pos = token
    if pos + token_len > len(data):
        return None
    pos += token_len

    length_field = _read_varint(data, pos)
    if length_field is None:
        return None
    length, pos = length_field
    pn_offset = pos
    packet_end = pn_offset + length
    if packet_end > len(data):  # length 声明超出报文，视作畸形
        return None
    return LongHeader(
        version=version,
        dcid=dcid,
        scid=scid,
        pn_offset=pn_offset,
        packet_end=packet_end,
        token_len=token_len,
    )


def parse_crypto_frames(payload: bytes) -> list[tuple[int, bytes]]:
    """扫描 Initial payload 中的 CRYPTO 帧，返回 (offset, data) 列表。

    FIX-2：ACK 帧全部字段是 varint；CONNECTION_CLOSE 直接终止扫描不解析
    字段（Initial 里出现它意味着连接失败，算长度反而会把后续字节当帧头）。
    未知帧类型同样终止扫描（不报错）。
    """
    frames: list[tuple[int, bytes]] = []
    pos = 0
    end = len(payload)
    while pos < end:
        frame_type = payload[pos]
        if frame_type == 0x00:  # PADDING：单字节，可连续
            pos += 1
            continue
        if frame_type == 0x01:  # PING：单字节
            pos += 1
            continue
        if frame_type in (0x02, 0x03):  # ACK / ACK_ECN：全 varint
            pos = _skip_varints(payload, pos + 1, 4)  # largest/delay/range_count/first_range
            if pos is None:
                break
            if frame_type == 0x03:
                pos = _skip_varints(payload, pos, 3)  # ECT0/ECT1/ECN-CE
                if pos is None:
                    break
            continue
        if frame_type == 0x06:  # CRYPTO：offset(varint) length(varint) data
            offset = _read_varint(payload, pos + 1)
            if offset is None:
                break
            length = _read_varint(payload, offset[1])
            if length is None:
                break
            data_start = length[1]
            if data_start + length[0] > end:
                break
            frames.append((offset[0], payload[data_start:data_start + length[0]]))
            pos = data_start + length[0]
            continue
        # 0x1c/0x1d CONNECTION_CLOSE 与其余未知帧：终止扫描
        break
    return frames


def _skip_varints(data: bytes, pos: int, count: int) -> int | None:
    """连续跳过 count 个 varint，返回新偏移；越界返回 None。"""
    for _ in range(count):
        value = _read_varint(data, pos)
        if value is None:
            return None
        pos = value[1]
    return pos


class QuicSniffer:
    """逐个报文喂入，解密 Initial 并重组 CRYPTO 流，解析首个 hello。"""

    def __init__(
        self,
        kind: str,
        *,
        version_hint: int = 0,
        dcid_hint: bytes = b"",
    ) -> None:
        self._kind = kind
        self._dcid_hint = dcid_hint  # 服务端方向：客户端首个 Initial 的 DCID
        self._finished = False
        self._info: HelloInfo | None = None
        self._quic_version = UNKNOWN
        self._attempts = 0
        # CRYPTO 重组状态
        self._buf = bytearray()
        self._next_offset = 0
        self._pending: dict[int, bytes] = {}
        self._pending_total = 0
        _ = version_hint  # 预留：后续可用于跳过版本识别（当前不参与逻辑）

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def info(self) -> HelloInfo | None:
        return self._info

    @property
    def quic_version(self) -> str:
        """已识别的 QUIC 版本展示名；未见过长包头时为 UNKNOWN。"""
        return self._quic_version

    def feed(self, datagram: bytes) -> None:
        """喂入一个 UDP 数据报；任何异常都在内部吞掉，不影响调用方。"""
        if self._finished or not datagram:
            return
        if len(datagram) < MIN_DATAGRAM or len(datagram) > INITIAL_MAX_DATAGRAM:
            return  # 异常尺寸跳过，不消耗尝试次数
        self._attempts += 1
        try:
            self._process(datagram)
        except Exception:
            log.debug("QUIC 嗅探异常（忽略，继续转发）", exc_info=True)
        if not self._finished and self._attempts >= MAX_ATTEMPTS:
            self._finished = True  # 尝试耗尽，放弃（info 保持 None）

    # ------------------------------------------------------------------ 内部

    def _process(self, data: bytes) -> None:
        first = data[0]
        if not (first & 0x80):
            return  # 短包头（1-RTT），不处理
        version = int.from_bytes(data[1:5], "big")
        if version == 0:
            # 版本协商包：无 PN 无 payload，记 vneg 后完成
            self._set_version(quic_version_name(0))
            self._finished = True
            return
        self._set_version(quic_version_name(version))
        if not quic_crypto.available():
            return  # 优雅降级：保留传输层值，其余等 backstop
        if not looks_like_initial(data):
            return
        header = parse_long_header(data)
        if header is None:
            return
        if len(data) < header.pn_offset + 20:
            return  # 样本不足（HP 需要 pn_offset+4 起 16 字节）
        keys = self._keys_for(header)
        if keys is None:
            return
        payload = self._decrypt(header, data, keys)
        if payload is None:
            return  # InvalidTag / 结构异常，降级
        for offset, chunk in parse_crypto_frames(payload):
            self._on_crypto(offset, chunk)
        self._try_parse_hello()

    def _set_version(self, name: str) -> None:
        if self._quic_version == UNKNOWN:
            self._quic_version = name

    def _keys_for(self, header: LongHeader) -> quic_crypto.KeySet | None:
        """按方向取 Initial 密钥；服务端方向必须用客户端首个 Initial 的 DCID。"""
        if self._kind == CLIENT:
            dcid, is_client = header.dcid, True
        else:
            dcid, is_client = self._dcid_hint, False
        if not dcid:
            return None
        cache = quic_crypto.default_cache()
        keys = cache.get(header.version, dcid, is_client)
        if keys is None:
            keys = quic_crypto.initial_keys(header.version, dcid, is_client)
            if keys is not None:
                cache.put(header.version, dcid, is_client, keys)
        return keys

    def _decrypt(self, header: LongHeader, data: bytes, keys: quic_crypto.KeySet) -> bytes | None:
        """FIX-1 的正确解密流程：还原 first byte → 提取 PN → 构造 AAD → AEAD。"""
        sample = data[header.pn_offset + 4:header.pn_offset + 20]
        mask = quic_crypto.header_mask(keys.hp, sample)

        first = data[0] ^ (mask[0] & 0x0F)  # 还原长包头 first byte 的低 4 位
        pn_len = (first & 0x03) + 1         # PN 长度只在低 2 位

        pn_bytes = bytes(
            b ^ m
            for b, m in zip(
                data[header.pn_offset:header.pn_offset + pn_len],
                mask[1:1 + pn_len],
            )
        )
        pn = int.from_bytes(pn_bytes, "big")

        # AAD 必须是未受保护的头部：first byte 用还原值，PN 用还原后的字节
        aad = bytes([first]) + data[1:header.pn_offset] + pn_bytes
        ct = data[header.pn_offset + pn_len:header.packet_end]
        return quic_crypto.open_payload(keys, pn, aad, ct)

    def _on_crypto(self, offset: int, chunk: bytes) -> None:
        """CRYPTO 帧进重组缓冲：顺序追加、乱序暂存、超限放弃。"""
        if self._finished:
            return
        if offset < self._next_offset:
            skip = self._next_offset - offset
            if skip >= len(chunk):
                return  # 整段都是已收过的旧数据
            offset = self._next_offset
            chunk = chunk[skip:]
        if offset > self._next_offset:
            if self._pending_total + len(chunk) > MAX_CRYPTO_BUFFER:
                log.debug("QUIC CRYPTO 乱序缓冲超限，放弃重组")
                self._finished = True
                return
            self._pending[offset] = chunk
            self._pending_total += len(chunk)
            return
        self._buf.extend(chunk)
        self._next_offset += len(chunk)
        while self._next_offset in self._pending:  # 连续吐出后续缓存
            following = self._pending.pop(self._next_offset)
            self._pending_total -= len(following)
            self._buf.extend(following)
            self._next_offset += len(following)
        self._try_parse_hello()

    def _try_parse_hello(self) -> None:
        """CRYPTO 流凑够一个完整 handshake 消息就解析（type 0x01/0x02 与 TCP 侧一致）。"""
        while not self._finished and len(self._buf) >= 4:
            if len(self._buf) > MAX_CRYPTO_BUFFER:
                self._finished = True
                return
            hs_len = int.from_bytes(self._buf[1:4], "big")
            if 4 + hs_len > len(self._buf):
                return  # 还没拼够，等下一个 CRYPTO 帧
            expected_type = 0x01 if self._kind == CLIENT else 0x02
            if self._buf[0] != expected_type:
                self._finished = True  # 首条消息就不是期待方向的 hello，放弃
                return
            body = bytes(self._buf[4:4 + hs_len])
            try:
                self._info = parse_hello(self._kind, body)
            except Exception:
                log.debug("QUIC TLS hello 解析异常（放弃）", exc_info=True)
            self._finished = True
            return
