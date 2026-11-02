"""TLS ClientHello 流式 SNI 解析器。

只读旁路设计：输入字节流，输出 SNI 域名或"非 TLS"结论，不持有任何 IO。
调用方（TCP 转发引擎）把收到的每段字节喂进来，无论解析结果如何，
同一份字节都会原样转发出去——嗅探器没有写路径，不会干扰数据流。
"""

from __future__ import annotations

from enum import Enum, auto

# ClientHello 实测通常 < 4KB（浏览器普遍 2KB 上下），留足余量。
MAX_BUFFER = 20 * 1024
MAX_HELLO = 16 * 1024

_TLS_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_EXT_SERVER_NAME = 0x0000
_SNI_HOST_NAME = 0


class SniffState(Enum):
    NEED_RECORD = auto()     # 等 TLS record 头（5 字节）
    NEED_HANDSHAKE = auto()  # 等 handshake 头（4 字节）
    COLLECT_HELLO = auto()   # 等 ClientHello 主体
    DONE = auto()            # 解析完成（可能带 SNI，也可能无 SNI 扩展）
    NOT_TLS = auto()         # 放弃：非 TLS / 跨 record 分片 / 超限


class _ParseError(Exception):
    """长度字段矛盾或越界，说明不是可解析的 ClientHello。"""


class SniSniffer:
    """逐段喂入字节，解析首个 TLS ClientHello 中的 SNI。"""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.state = SniffState.NEED_RECORD
        self.sni: str | None = None
        self._record_end = 0
        self._hello_end = 0

    @property
    def finished(self) -> bool:
        return self.state in (SniffState.DONE, SniffState.NOT_TLS)

    @property
    def result(self) -> str | None:
        return self.sni if self.state is SniffState.DONE else None

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
                if self._buf[5] != _HANDSHAKE_CLIENT_HELLO:
                    self._fail()
                    return
                hello_len = int.from_bytes(self._buf[6:9], "big")
                if hello_len <= 0 or hello_len > MAX_HELLO:
                    self._fail()
                    return
                self._hello_end = 9 + hello_len
                if self._hello_end > self._record_end:
                    # ClientHello 跨越了多个 TLS record（罕见分片），放弃嗅探。
                    self._fail()
                    return
                self.state = SniffState.COLLECT_HELLO

            elif self.state is SniffState.COLLECT_HELLO:
                if len(self._buf) < self._hello_end:
                    return
                body = bytes(self._buf[9:self._hello_end])
                try:
                    self.sni = _parse_client_hello(body)
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


def _parse_client_hello(body: bytes) -> str | None:
    """解析 ClientHello 主体，返回 SNI；无 SNI 扩展时返回 None。"""
    end = len(body)
    if end < 34:  # legacy_version(2) + random(32)
        raise _ParseError

    pos = 34
    pos = _skip_vector_u8(body, pos)   # session_id
    pos = _skip_vector_u16(body, pos)  # cipher_suites
    pos = _skip_vector_u8(body, pos)   # compression_methods

    if pos == end:
        return None  # 老式 ClientHello，没有 extensions

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
        if ext_type == _EXT_SERVER_NAME:
            return _parse_server_name(body[pos:pos + ext_len])
        pos += ext_len
    return None


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


def _skip_vector_u16(buf: bytes, pos: int) -> int:
    length = _read_u16(buf, pos)
    pos += 2
    if pos + length > len(buf):
        raise _ParseError
    return pos + length
