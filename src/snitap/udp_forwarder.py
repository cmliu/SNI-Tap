"""UDP 转发引擎：每个客户端地址一条上游 socket，回程按地址映射表路由。

v2 起每个会话挂一个 :class:`QuicFlow`（QUIC Initial 双向嗅探）。
零干扰原则：**先 ``sendto`` 后 ``_inspect``**——嗅探是纯内存旁路，
任何异常都吞在内部，绝不影响转发字节与时机。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time
from collections.abc import Callable

from .config import LISTEN_HOST, AppConfig
from .flow import QuicFlow
from .protocol import ProtocolStack

log = logging.getLogger(__name__)

SESSION_IDLE_SECONDS = 60.0
CLEANUP_INTERVAL = 30.0


class _UpstreamProtocol(asyncio.DatagramProtocol):
    """单客户端专用的上游 socket：收到回包后按客户端地址回送。"""

    def __init__(self, owner: "UdpForwarder", client_addr: tuple[str, int]) -> None:
        self._owner = owner
        self._client_addr = client_addr

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._owner.route_back(self._client_addr, data)

    def error_received(self, exc: Exception) -> None:
        log.debug("UDP 上游错误: %s", exc)


class UdpForwarder(asyncio.DatagramProtocol):
    """本地 UDP 监听 + 客户端地址到上游 socket 的映射表 + QUIC 会话嗅探。"""

    def __init__(
        self,
        config: AppConfig,
        on_stack: Callable[[ProtocolStack], None],
        on_session_change: Callable[[int], None],
        on_error: Callable[[str], None],
    ) -> None:
        self._config = config
        self._on_stack = on_stack
        self._on_session_change = on_session_change
        self._on_error = on_error
        self._transport: asyncio.DatagramTransport | None = None
        self._sessions: dict[tuple[str, int], dict] = {}
        self._session_tasks: set[asyncio.Task[None]] = set()
        self._cleanup_task: asyncio.Task[None] | None = None
        self._target_ip: str = ""

    @property
    def local_port(self) -> int:
        if self._transport is None:
            return 0
        return self._transport.get_extra_info("sockname")[1]

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            self._config.target_host,
            self._config.target_port,
            type=socket.SOCK_DGRAM,
            family=socket.AF_INET,
        )
        if not infos:
            raise RuntimeError(f"无法解析目标 {self._config.target_host}")
        self._target_ip = infos[0][4][0]

        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=(LISTEN_HOST, self._config.listen_port),
        )
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._cleanup_task
            self._cleanup_task = None

        for task in list(self._session_tasks):
            task.cancel()
        if self._session_tasks:
            await asyncio.gather(*self._session_tasks, return_exceptions=True)
        self._session_tasks.clear()

        for session in self._sessions.values():
            flow: QuicFlow | None = session.get("flow")
            if flow is not None:
                flow.close()  # 兜底合并 / 释放兜底定时器
            transport = session.get("transport")
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()
        self._sessions.clear()

        if self._transport is not None:
            with contextlib.suppress(Exception):
                self._transport.close()
            self._transport = None
        self._safe_session_change()

    # -------------------------------------------------------------- 数据路径

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        session = self._sessions.get(addr)
        if session is not None:
            session["last_seen"] = time.monotonic()
            transport = session.get("transport")
            if transport is not None and not transport.is_closing():
                transport.sendto(data)  # 先转发
                self._inspect(session, data)  # 后嗅探（零干扰）
            else:
                session["pending"].append(data)
                self._inspect(session, data)
            return

        # 新客户端：先登记并缓存首包，上游 socket 建好后补发。
        session = {
            "transport": None,
            "last_seen": time.monotonic(),
            "pending": [data],
            "flow": QuicFlow(self._on_stack),
        }
        self._sessions[addr] = session
        # FIX-7：首包**必须**也喂给嗅探。客户端首个 UDP 数据报就是承载
        # ClientHello 的 Initial（CRYPTO offset 0），漏掉它整条会话永远解不出
        # SNI（后续 Initial 的 CRYPTO 片段只有 offset>0，无法拼出 hello）。
        # 此处虽与「先转发后嗅探」的书写顺序相反，但上游 socket 尚未建好、
        # 转发必然延后，嗅探依旧是纯内存旁路，不改变转发字节与时序。
        self._inspect(session, data)
        self._safe_session_change()
        task = asyncio.ensure_future(self._open_session(addr))
        self._session_tasks.add(task)
        task.add_done_callback(self._session_tasks.discard)

    def route_back(self, client_addr: tuple[str, int], data: bytes) -> None:
        session = self._sessions.get(client_addr)
        if session is not None:
            session["last_seen"] = time.monotonic()
        if self._transport is not None and not self._transport.is_closing():
            with contextlib.suppress(Exception):
                self._transport.sendto(data, client_addr)  # 先转发
        if session is not None:
            flow: QuicFlow | None = session.get("flow")
            if flow is not None:
                try:
                    flow.feed_server(data)  # 后嗅探（零干扰）
                except Exception:
                    log.debug("QUIC 回程嗅探异常（忽略）", exc_info=True)

    async def _open_session(self, addr: tuple[str, int]) -> None:
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UpstreamProtocol(self, addr),
                remote_addr=(self._target_ip, self._config.target_port),
            )
        except Exception as exc:
            session = self._sessions.pop(addr, None)
            if session is not None:
                flow: QuicFlow | None = session.get("flow")
                if flow is not None:
                    flow.close()
                self._safe_session_change()
            self._on_error_safe(f"UDP 上游创建失败：{exc}")
            return

        session = self._sessions.get(addr)
        if session is None:  # 建立期间会话被清理或已停止
            with contextlib.suppress(Exception):
                transport.close()
            return

        session["transport"] = transport
        for chunk in session["pending"]:
            with contextlib.suppress(Exception):
                transport.sendto(chunk)
        session["pending"].clear()

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL)
            now = time.monotonic()
            stale = [
                addr
                for addr, session in self._sessions.items()
                if now - session["last_seen"] > SESSION_IDLE_SECONDS
            ]
            for addr in stale:
                session = self._sessions.pop(addr, None)
                if session is not None:
                    flow: QuicFlow | None = session.get("flow")
                    if flow is not None:
                        flow.close()
                    if session.get("transport") is not None:
                        with contextlib.suppress(Exception):
                            session["transport"].close()
            if stale:
                self._safe_session_change()

    # ------------------------------------------------------------- 嗅探与回调

    def _inspect(self, session: dict, data: bytes) -> None:
        """把客户端方向报文喂给会话的 QuicFlow；异常绝不外抛。"""
        flow: QuicFlow | None = session.get("flow")
        if flow is None:
            return
        try:
            flow.feed_client(data)
        except Exception:
            log.debug("QUIC 嗅探异常（忽略，继续转发）", exc_info=True)

    def _safe_session_change(self) -> None:
        try:
            self._on_session_change(len(self._sessions))
        except Exception:
            log.debug("UDP 会话数回调异常", exc_info=True)

    def _on_error_safe(self, message: str) -> None:
        log.debug(message)
        try:
            self._on_error(message)
        except Exception:
            log.debug("错误回调异常", exc_info=True)
