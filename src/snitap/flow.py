"""每连接 / 每会话的嗅探聚合器：合并双向握手为一条 ProtocolStack。

核心决策 D1：每条连接 / 会话**至多发出一条事件**——若 ClientHello 与
ServerHello 各发一次，同一域名会先以「客户端最高支持」入库、再以「实际
协商」入库，统计必然脏。嗅探窗口闭合时（双向 finished / 连接关闭 /
backstop 兜底）合并成一条。

合并规则：
- 拿到 ServerHello / 服务端 Initial → 三层一律取协商值，provisional=False；
- 只拿到客户端方向 → 退回客户端偏好，provisional=True；
- ``sni`` 只能来自客户端方向；QUIC 版本取自长包头（与 hello 无关）。

生命周期：``__init__`` 用 running loop 的 ``call_later(backstop, _finish)``
挂兜底定时器（取不到 running loop 时跳过，便于纯单测）；``_finish`` 幂等
（``_done`` 标志 + 定时器 cancel）；``close()`` 必然调 ``_finish()``。
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from .protocol import UNKNOWN, LayerSource, ProtocolStack
from .quic_sniffer import QuicSniffer, parse_long_header
from .tls_sniffer import CLIENT, SERVER, HelloInfo, TlsSniffer

log = logging.getLogger(__name__)

TCP_BACKSTOP = 3.0
QUIC_BACKSTOP = 3.0


def _merge(
    client_info: HelloInfo | None,
    server_info: HelloInfo | None,
    *,
    transport: str,
    quic_version: str,
) -> ProtocolStack | None:
    """合并双向 hello 为一条快照；两个方向都没解出时返回 None（零上报）。"""
    if client_info is None and server_info is None:
        return None
    if server_info is not None:
        source = LayerSource.NEGOTIATED
        info = server_info
        provisional = False
    else:
        source = LayerSource.CLIENT
        info = client_info
        provisional = True
    return ProtocolStack(
        sni=client_info.sni if client_info is not None else None,
        transport=transport,
        quic_version=quic_version,
        tls_version=info.tls_version,
        tls_source=source,
        cipher=info.cipher,
        cipher_source=source,
        alpn=info.alpn,
        alpn_source=source,
        provisional=provisional,
    )


class TcpFlow:
    """单条 TCP 连接的聚合器：上行挂 ClientHello 嗅探，下行挂 ServerHello 嗅探。"""

    def __init__(
        self,
        on_stack: Callable[[ProtocolStack], None],
        *,
        backstop: float = TCP_BACKSTOP,
    ) -> None:
        self._on_stack = on_stack
        self._client = TlsSniffer(CLIENT)
        self._server = TlsSniffer(SERVER)
        self._done = False
        self._timer: asyncio.TimerHandle | None = None
        try:
            loop = asyncio.get_running_loop()
            self._timer = loop.call_later(backstop, self._finish)
        except RuntimeError:
            self._timer = None  # 无 running loop（纯单测场景），跳过兜底定时器

    def sink(self, direction: str) -> Callable[[bytes], None] | None:
        """取一个方向的嗅探 sink；该方向已 finished 或整条流已 emit 时返回 None，
        调用方（``_pump``）据此实现零开销旁路。

        Args:
            direction: ``"up"``（客户端方向）或 ``"down"``（服务端方向）。
        """
        if self._done:
            return None
        sniffer = self._client if direction == "up" else self._server
        if sniffer.finished:
            return None
        return lambda data: self._feed(sniffer, data)

    def close(self) -> None:
        """连接结束；必然触发一次（且仅一次）合并尝试。"""
        self._finish()

    # ------------------------------------------------------------------ 内部

    def _feed(self, sniffer: TlsSniffer, data: bytes) -> None:
        try:
            sniffer.feed(data)
        except Exception:
            # 嗅探绝不能影响转发：解析异常吞掉并记 debug
            log.debug("TLS 嗅探异常（忽略，继续转发）", exc_info=True)
            return
        if self._client.finished and self._server.finished:
            self._finish()

    def _finish(self) -> None:
        if self._done:
            return
        self._done = True
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        stack = _merge(
            self._client.info, self._server.info, transport="TCP", quic_version=UNKNOWN,
        )
        if stack is None:
            return  # 非 TLS：零上报
        try:
            self._on_stack(stack)
        except Exception:
            log.debug("on_stack 回调异常", exc_info=True)


class QuicFlow:
    """单个 UDP 会话的聚合器：客户端方向喂 client sniffer，回程喂 server sniffer。"""

    def __init__(
        self,
        on_stack: Callable[[ProtocolStack], None],
        *,
        backstop: float = QUIC_BACKSTOP,
    ) -> None:
        self._on_stack = on_stack
        self._client = QuicSniffer(CLIENT)
        self._server: QuicSniffer | None = None  # 惰性创建：需要客户端 Initial 的 DCID
        self._initial_dcid = b""
        self._done = False
        self._timer: asyncio.TimerHandle | None = None
        try:
            loop = asyncio.get_running_loop()
            self._timer = loop.call_later(backstop, self._finish)
        except RuntimeError:
            self._timer = None

    def feed_client(self, datagram: bytes) -> None:
        """客户端 → 上游方向的报文；首个 Initial 的 DCID 会被记住。"""
        if self._done:
            return
        if not self._initial_dcid:
            header = parse_long_header(datagram)
            if header is not None and header.version != 0:
                self._initial_dcid = header.dcid
        self._client.feed(datagram)
        self._maybe_finish()

    def feed_server(self, datagram: bytes) -> None:
        """上游 → 客户端方向的报文；server sniffer 用客户端 DCID 派生密钥。"""
        if self._done:
            return
        if self._server is None:
            self._server = QuicSniffer(SERVER, dcid_hint=self._initial_dcid)
        self._server.feed(datagram)
        self._maybe_finish()

    def close(self) -> None:
        """会话结束（清理 / 停止）；必然触发一次合并尝试。"""
        self._finish()

    # ------------------------------------------------------------------ 内部

    def _maybe_finish(self) -> None:
        if self._client.finished and self._server is not None and self._server.finished:
            self._finish()

    def _finish(self) -> None:
        if self._done:
            return
        self._done = True
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        stack = self._build_stack()
        if stack is None:
            return  # 非 QUIC 的 UDP 会话：零上报
        try:
            self._on_stack(stack)
        except Exception:
            log.debug("on_stack 回调异常", exc_info=True)

    def _build_stack(self) -> ProtocolStack | None:
        version = self._client.quic_version
        if version == UNKNOWN and self._server is not None:
            version = self._server.quic_version
        if version == UNKNOWN:
            return None  # 从未见过 QUIC 长包头：纯 UDP，零上报
        stack = _merge(
            self._client.info,
            self._server.info if self._server is not None else None,
            transport="QUIC",
            quic_version=version,
        )
        if stack is None:
            # 见过长包头但没解出 hello（vneg / 未知版本 / 解密失败）：仍上报传输层值
            stack = ProtocolStack(transport="QUIC", quic_version=version)
        return stack
