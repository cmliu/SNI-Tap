"""TCP 转发引擎：监听本地端口，逐条连接转发到目标，并在前向数据上挂只读 SNI 嗅探。"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable

from .config import LISTEN_HOST, AppConfig
from .sni_sniffer import SniSniffer

log = logging.getLogger(__name__)

_CHUNK = 65536
_CONNECT_TIMEOUT = 10.0


class TcpForwarder:
    """监听 -> 建上游连接 -> 双向 pump；嗅探只发生在客户端到上游方向的前几个包。"""

    def __init__(
        self,
        config: AppConfig,
        on_sni: Callable[[str], None],
        on_conn_change: Callable[[int], None],
        on_error: Callable[[str], None],
    ) -> None:
        self._config = config
        self._on_sni = on_sni
        self._on_conn_change = on_conn_change
        self._on_error = on_error
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._active = 0

    @property
    def port(self) -> int:
        """实际监听端口（listen_port=0 时由系统分配，测试用）。"""
        if self._server is None:
            return 0
        return self._server.sockets[0].getsockname()[1]

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=LISTEN_HOST,
            port=self._config.listen_port,
            backlog=128,
            reuse_address=True,
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

        for writer in list(self._writers):
            _close_writer(writer)
        if self._writers:
            await asyncio.gather(*(w.wait_closed() for w in list(self._writers)), return_exceptions=True)

        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._writers.clear()
        self._active = 0
        self._safe_conn_change()

    # ------------------------------------------------------------------ 连接

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self._writers.add(writer)
        self._active += 1
        self._safe_conn_change()

        upstream_writer: asyncio.StreamWriter | None = None
        try:
            try:
                up_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(self._config.target_host, self._config.target_port),
                    timeout=_CONNECT_TIMEOUT,
                )
            except Exception as exc:
                self._on_error_safe(f"连接目标 {self._config.target_host}:{self._config.target_port} 失败：{exc}")
                return
            self._writers.add(upstream_writer)

            sniffer = SniSniffer()
            await asyncio.gather(
                self._pump(reader, upstream_writer, sniffer),
                self._pump(up_reader, writer, None),
                return_exceptions=True,
            )
        finally:
            if upstream_writer is not None:
                self._writers.discard(upstream_writer)
                _close_writer(upstream_writer)
            self._writers.discard(writer)
            _close_writer(writer)
            if task is not None:
                self._tasks.discard(task)
            self._active = max(0, self._active - 1)
            self._safe_conn_change()

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        sniffer: SniSniffer | None,
    ) -> None:
        """单向搬运字节；sniffer 非空时同步喂入（纯内存解析，不阻塞转发）。"""
        try:
            while True:
                data = await reader.read(_CHUNK)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                if sniffer is not None and not sniffer.finished:
                    self._sniff(sniffer, data)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(Exception):
                if not writer.is_closing():
                    writer.write_eof()

    # ------------------------------------------------------------ 嗅探与回调

    def _sniff(self, sniffer: SniSniffer, data: bytes) -> None:
        try:
            sniffer.feed(data)
        except Exception:  # 嗅探绝不能影响转发
            log.debug("SNI 解析异常（忽略，继续转发）", exc_info=True)
            return
        if sniffer.finished and sniffer.sni:
            try:
                self._on_sni(sniffer.sni)
            except Exception:
                log.debug("SNI 回调异常", exc_info=True)

    def _safe_conn_change(self) -> None:
        try:
            self._on_conn_change(self._active)
        except Exception:
            log.debug("连接数回调异常", exc_info=True)

    def _on_error_safe(self, message: str) -> None:
        log.debug(message)
        try:
            self._on_error(message)
        except Exception:
            log.debug("错误回调异常", exc_info=True)


def _close_writer(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
