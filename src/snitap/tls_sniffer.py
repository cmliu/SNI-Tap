"""TLS 双向握手嗅探：流式提取 ClientHello / ServerHello 的三层信息。

纯函数（``parse_client_hello`` / ``parse_server_hello`` / ``parse_hello``）
负责一次性解析 hello 主体，QUIC 侧直接复用（QUIC 的 TLS 握手没有 5 字节
record 头，不能复用 record 状态机）；``TlsSniffer`` 是流式外壳，处理
TCP 字节流的 record / handshake 分段。

只读旁路设计：输入字节流，输出 :class:`HelloInfo` 或「非 TLS」结论，
不持有任何 IO，不会干扰数据流。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from .protocol import UNKNOWN, alpn_name, cipher_name, is_grease, tls_version_name

# ClientHello 实测通常 < 4KB（浏览器普遍 2KB 上下），留足余量。
MAX_BUFFER = 20 * 1024
MAX_HELLO = 16 * 1024

CLIENT, SERVER = "client", "server"

_TLS_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_HANDSHAKE_SERVER_HELLO = 0x02
_EXT_SERVER_NAME = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_ECH = 0xFE0D      # encrypted_client_hello（RFC 9849），只判存在、不解析内容
_SNI_HOST_NAME = 0


class SniffState(Enum):
    NEED_RECORD = auto()     # 等 TLS record 头（5 字节）
    NEED_HANDSHAKE = auto()  # 等 handshake 头（4 字节）
    COLLECT_HELLO = auto()   # 等 hello 主体
    DONE = auto()            # 解析完成（可能带 SNI，也可能无 SNI 扩展）
    NOT_TLS = auto()         # 放弃：非 TLS / 跨 record 分片 / 超限


class _ParseError(Exception):
    """长度字段矛盾或越界，说明不是可解析的 hello。"""


@dataclass(frozen=True)
class HelloInfo:
    """一次 hello 解析的结果快照。"""

    kind: str                       # "client" | "server"
    sni: str | None = None          # 仅 ClientHello 有；ServerHello 恒为 None
    tls_version: str = UNKNOWN
    tls_version_raw: int = 0
    cipher: str = UNKNOWN
    cipher_raw: int = 0
    cipher_count: int = 0           # 仅 client：cipher_suites 列表总条数
    alpn: str = UNKNOWN
    ext_count: int = 0
    # 本次 hello 携带 ECH 扩展（只做布尔判定，绝不解析扩展体——GREASE ECH
    # 的 payload 是随机字节，解析只会炸掉嗅探路径）。
    # 语义边界：仅表示「扩展存在」，**可能是 GREASE ECH**（RFC 9849 §6.2 允许
    # 无 ECHConfig 的客户端发送假扩展，§10.10.4 明确两者对被动观察者不可区分）；
    # 是否确证生效由上层 ``flow._merge`` 按外层 SNI 是否命中 ECH 掩护域名判定，
    # 本层不做、也无法做该判定。
    ech: bool = False


class TlsSniffer:
    """逐段喂入 TCP 字节流，解析首个 hello（方向由 kind 决定）。"""

    def __init__(self, kind: str = CLIENT) -> None:
        self._kind = kind
        self._buf = bytearray()
        self.state = SniffState.NEED_RECORD
        self._info: HelloInfo | None = None
        self._record_end = 0
        self._hello_end = 0

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def finished(self) -> bool:
        return self.state in (SniffState.DONE, SniffState.NOT_TLS)

    @property
    def info(self) -> HelloInfo | None:
        """仅 DONE 状态非空；NOT_TLS / 未决均为 None。"""
        return self._info

    def feed(self, data: bytes) -> None:
        """喂入新收到的字节；终态后不再累积，避免无意义的内存占用。"""
        if self.finished or not data:
            return
        self._buf.extend(data)
        self._advance()

    # ------------------------------------------------------------------ 内部

    def _advance(self) -> None:
        while not self.finished:
            if len(self._buf) > MAX_BUFFER:
                self._fail()
                return

            if self.state is SniffState.NEED_RECORD:
                if len(self._buf) < 5:
                    return
                if self._buf[0] != _TLS_HANDSHAKE:
                    self._fail()
                    return
                record_len = int.from_bytes(self._buf[3:5], "big")
                if record_len <= 4 or record_len > MAX_HELLO:
                    self._fail()
                    return
                self._record_end = 5 + record_len
                self.state = SniffState.NEED_HANDSHAKE

            elif self.state is SniffState.NEED_HANDSHAKE:
                if len(self._buf) < 9:
                    return
                expected = (
                    _HANDSHAKE_CLIENT_HELLO
                    if self._kind == CLIENT
                    else _HANDSHAKE_SERVER_HELLO
                )
                if self._buf[5] != expected:
                    self._fail()
                    return
                hello_len = int.from_bytes(self._buf[6:9], "big")
                if hello_len <= 0 or hello_len > MAX_HELLO:
                    self._fail()
                    return
                self._hello_end = 9 + hello_len
                if self._hello_end > self._record_end:
                    # hello 跨越了多个 TLS record（罕见分片），放弃嗅探。
                    self._fail()
                    return
                self.state = SniffState.COLLECT_HELLO

            elif self.state is SniffState.COLLECT_HELLO:
                if len(self._buf) < self._hello_end:
                    return
                body = bytes(self._buf[9:self._hello_end])
                try:
                    self._info = parse_hello(self._kind, body)
                except _ParseError:
                    self._fail()
                    return
                self.state = SniffState.DONE
                self._buf.clear()
                return

            else:  # pragma: no cover - 终态由 while 条件拦截
                return

    def _fail(self) -> None:
        self.state = SniffState.NOT_TLS
        self._buf.clear()


def parse_hello(kind: str, body: bytes) -> HelloInfo:
    """按方向分发到对应的纯函数解析器（QUIC 侧复用入口）。"""
    if kind == CLIENT:
        return parse_client_hello(body)
    return parse_server_hello(body)


def parse_client_hello(body: bytes) -> HelloInfo:
    """解析 ClientHello 主体（不含 4 字节 handshake 头）。

    版本依据：有 supported_versions（过滤 GREASE 后取 max）时以它为唯一
    依据——TLS1.3 客户端的 legacy_version 恒为 0x0303，不能因此误判 1.2；
    无 supported_versions 或全 GREASE 时回退 legacy_version。
    cipher 取列表里第一个非 GREASE 套件。
    ``ech`` 只判 ``0xFE0D`` 扩展是否存在（外层 ClientHelloOuter 明文携带），
    绝不解析扩展体——GREASE ECH 的 payload 是随机字节。
    """
    end = len(body)
    if end < 34:  # legacy_version(2) + random(32)
        raise _ParseError

    legacy_version = int.from_bytes(body[0:2], "big")
    pos = 34
    pos = _skip_vector_u8(body, pos)   # session_id
    cipher_start, cipher_end = _vector_u16_span(body, pos)  # cipher_suites
    pos = cipher_end
    pos = _skip_vector_u8(body, pos)   # compression_methods

    sni: str | None = None
    alpn = UNKNOWN
    sv_candidates: list[int] = []
    ext_count = 0
    ech = False

    if pos != end:
        ext_total = _read_u16(body, pos)
        pos += 2
        ext_end = pos + ext_total
        if ext_end > end:
            raise _ParseError

        while pos + 4 <= ext_end:
            ext_type = _read_u16(body, pos)
            ext_len = _read_u16(body, pos + 2)
            pos += 4
            if pos + ext_len > ext_end:
                raise _ParseError
            ext_count += 1
            data = body[pos:pos + ext_len]
            if ext_type == _EXT_SERVER_NAME:
                sni = _parse_server_name(data)
            elif ext_type == _EXT_ALPN:
                alpn = _parse_alpn(data)
            elif ext_type == _EXT_SUPPORTED_VERSIONS:
                sv_candidates = _parse_client_supported_versions(data)
            elif ext_type == _EXT_ECH:
                # 只判存在：扩展体是 HPKE 密文（GREASE ECH 时是随机字节），
                # 不解析内容，避免随机字节把嗅探路径带进异常分支。
                ech = True
            pos += ext_len

    ciphers = [
        int.from_bytes(body[i:i + 2], "big") for i in range(cipher_start, cipher_end, 2)
    ]
    cipher_raw = 0
    for value in ciphers:
        if not is_grease(value):
            cipher_raw = value
            break

    if sv_candidates:
        version_raw = max(sv_candidates)
    else:
        version_raw = legacy_version

    return HelloInfo(
        kind=CLIENT,
        sni=sni,
        tls_version=tls_version_name(version_raw),
        tls_version_raw=version_raw,
        cipher=cipher_name(cipher_raw) if cipher_raw else UNKNOWN,
        cipher_raw=cipher_raw,
        cipher_count=len(ciphers),
        alpn=alpn,
        ext_count=ext_count,
        ech=ech,
    )


def parse_server_hello(body: bytes) -> HelloInfo:
    """解析 ServerHello 主体（含 HelloRetryRequest，两者 handshake type 相同）。

    与 ClientHello 的差异：cipher 是定长 2 字节直读（服务端不会选 GREASE）；
    supported_versions 是裸 2 字节（无长度前缀）；SNI 恒为 None。
    """
    end = len(body)
    if end < 40:  # legacy_version(2) + random(32) + sid<1B> + cipher(2) + comp(1)
        raise _ParseError

    legacy_version = int.from_bytes(body[0:2], "big")
    pos = 34
    pos = _skip_vector_u8(body, pos)                  # session_id
    cipher_raw = _read_u16(body, pos)                 # cipher_suite 定长 2 字节
    pos += 2
    pos = _skip_vector_u8(body, pos)                  # compression_methods

    alpn = UNKNOWN
    sv_raw = 0
    ext_count = 0
    ech = False

    if pos != end:
        ext_total = _read_u16(body, pos)
        pos += 2
        ext_end = pos + ext_total
        if ext_end > end:
            raise _ParseError

        while pos + 4 <= ext_end:
            ext_type = _read_u16(body, pos)
            ext_len = _read_u16(body, pos + 2)
            pos += 4
            if pos + ext_len > ext_end:
                raise _ParseError
            ext_count += 1
            data = body[pos:pos + ext_len]
            if ext_type == _EXT_ALPN:
                alpn = _parse_alpn(data)
            elif ext_type == _EXT_SUPPORTED_VERSIONS:
                # 裸 2 字节，与 ClientHello 的 list 格式不同
                if ext_len != 2:
                    raise _ParseError
                sv_raw = _read_u16(data, 0)
            elif ext_type == _EXT_ECH:
                # 服务端仅 HelloRetryRequest 场景会明文回带该扩展（罕见）；
                # 正常 ServerHello 的 accept_confirmation 埋在 random[24..32]，
                # 其推导依赖不可见的 ClientHelloInner.random，故这里**不代表**
                # 服务端已接受 ECH——标记语义只有「本次 hello 携带 ECH 扩展」。
                ech = True
            pos += ext_len

    version_raw = sv_raw if sv_raw else legacy_version
    return HelloInfo(
        kind=SERVER,
        sni=None,
        tls_version=tls_version_name(version_raw),
        tls_version_raw=version_raw,
        cipher=cipher_name(cipher_raw) if cipher_raw else UNKNOWN,
        cipher_raw=cipher_raw,
        cipher_count=1,
        alpn=alpn,
        ext_count=ext_count,
        ech=ech,
    )


# -------------------------------------------------------------- 扩展子解析

def _parse_server_name(data: bytes) -> str | None:
    """解析 server_name 扩展，取第一个 host_name 条目。"""
    if len(data) < 2:
        raise _ParseError
    list_len = _read_u16(data, 0)
    pos = 2
    end = pos + list_len
    if end > len(data):
        raise _ParseError

    while pos + 3 <= end:
        name_type = data[pos]
        name_len = _read_u16(data, pos + 1)
        pos += 3
        if pos + name_len > end:
            raise _ParseError
        if name_type == _SNI_HOST_NAME:
            return data[pos:pos + name_len].decode("ascii", "replace")
        pos += name_len
    return None


def _parse_alpn(data: bytes) -> str:
    """解析 ALPN 扩展，取第一个协议名偏好。"""
    if len(data) < 2:
        raise _ParseError
    list_len = _read_u16(data, 0)
    pos = 2
    end = pos + list_len
    if end > len(data):
        raise _ParseError
    while pos < end:
        proto_len = data[pos]
        pos += 1
        if pos + proto_len > end:
            raise _ParseError
        return alpn_name(data[pos:pos + proto_len])
    return UNKNOWN


def _parse_client_supported_versions(data: bytes) -> list[int]:
    """ClientHello 的 supported_versions：1B list_len + N×2B，保留非 GREASE。"""
    if len(data) < 1:
        raise _ParseError
    list_len = data[0]
    pos = 1
    if pos + list_len > len(data):
        raise _ParseError
    values: list[int] = []
    for i in range(list_len // 2):
        value = int.from_bytes(data[pos + i * 2:pos + i * 2 + 2], "big")
        if not is_grease(value):
            values.append(value)
    return values


# ---------------------------------------------------------------- 字节工具

def _read_u8(buf: bytes, pos: int) -> int:
    if pos >= len(buf):
        raise _ParseError
    return buf[pos]


def _read_u16(buf: bytes, pos: int) -> int:
    if pos + 2 > len(buf):
        raise _ParseError
    return (buf[pos] << 8) | buf[pos + 1]


def _skip_vector_u8(buf: bytes, pos: int) -> int:
    length = _read_u8(buf, pos)
    pos += 1
    if pos + length > len(buf):
        raise _ParseError
    return pos + length


def _vector_u16_span(buf: bytes, pos: int) -> tuple[int, int]:
    """返回 u16 长度前缀 vector 的 (start, end) 字节区间。"""
    length = _read_u16(buf, pos)
    pos += 2
    if pos + length > len(buf):
        raise _ParseError
    return pos, pos + length
