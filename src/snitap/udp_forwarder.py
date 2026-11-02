"""UDP 转发引擎：每个客户端地址一条上游 socket，回程按地址映射表路由。

v1 仅做透明转发（QUIC/h3 不断流）；嗅探器接口预留为可插拔钩子，v2 再解 QUIC Initial。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time
from collections.abc import Callable

from .config import LISTEN_HOST, AppConfig

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
    """本地 UDP 监听 + 客户端地址到上游 socket 的映射表。"""

    def __init__(
        self,
        config: AppConfig,
        on_session_change: Callable[[int], None],
        on_error: Callable[[str], None],
    ) -> None:
        self._config = config
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
                transport.sendto(data)
            else:
                session["pending"].append(data)
            return

        # 新客户端：先登记并缓存首包，上游 socket 建好后补发。
        self._sessions[addr] = {
            "transport": None,
            "last_seen": time.monotonic(),
            "pending": [data],
        }
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
                self._transport.sendto(data, client_addr)

    async def _open_session(self, addr: tuple[str, int]) -> None:
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UpstreamProtocol(self, addr),
                remote_addr=(self._target_ip, self._config.target_port),
            )
        except Exception as exc:
            if self._sessions.pop(addr, None) is not None:
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
                if session is not None and session.get("transport") is not None:
                    with contextlib.suppress(Exception):
                        session["transport"].close()
            if stale:
                self._safe_session_change()

    # ------------------------------------------------------------- 回调保护

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
