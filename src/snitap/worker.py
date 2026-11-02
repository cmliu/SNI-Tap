"""asyncio worker 线程：唯一拥有事件循环的宿主，管理各引擎生命周期。

对 GUI 只暴露三样东西：start(config)、stop()、events（queue.Queue）。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import queue
import threading

from .config import LISTEN_HOST, AppConfig
from .events import NoticeEvent, SniEvent, StateEvent, StatsEvent, TcpingEvent, now_ts
from .stats import Stats
from .tcp_forwarder import TcpForwarder
from .tcping import Tcping
from .udp_forwarder import UdpForwarder

log = logging.getLogger(__name__)

_EVENT_QUEUE_MAX = 20000


class Worker:
    """每次 start 新建一个线程与事件循环；stop 后整体回收。"""

    def __init__(self) -> None:
        self.events: queue.Queue = queue.Queue(maxsize=_EVENT_QUEUE_MAX)
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stats = Stats()
        self._tcp: TcpForwarder | None = None
        self._udp: UdpForwarder | None = None
        self._tcping: Tcping | None = None
        self._stats_task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------- 生命周期

    def start(self, config: AppConfig) -> None:
        if self.running:
            return
        self._stats = Stats()
        self._thread = threading.Thread(target=self._run, args=(config,), name="snitap-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        loop = self._loop
        thread = self._thread
        if loop is not None and loop.is_running():
            with contextlib.suppress(Exception):
                future = asyncio.run_coroutine_threadsafe(self._shutdown(), loop)
                future.result(timeout=timeout)
            with contextlib.suppress(Exception):
                loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=timeout)
        self._thread = None
        self._loop = None

    def _run(self, config: AppConfig) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._startup(config))
        except BaseException as exc:  # 启动失败（端口占用、目标解析失败等）
            log.warning("启动失败: %s", exc)
            self._emit(StateEvent(state="error", message=f"启动失败：{exc}"))
            with contextlib.suppress(Exception):
                loop.run_until_complete(self._teardown())
            with contextlib.suppress(Exception):
                loop.close()
            self._loop = None
            return

        try:
            loop.run_forever()
        finally:
            with contextlib.suppress(Exception):
                loop.run_until_complete(self._teardown())
            with contextlib.suppress(Exception):
                loop.run_until_complete(loop.shutdown_asyncgens())
            with contextlib.suppress(Exception):
                loop.close()
            self._loop = None

    async def _startup(self, config: AppConfig) -> None:
        self._tcp = TcpForwarder(
            config,
            on_sni=self._on_sni,
            on_conn_change=self._on_conn_change,
            on_error=self._on_error,
        )
        await self._tcp.start()

        self._udp = UdpForwarder(
            config,
            on_session_change=self._on_udp_sessions,
            on_error=self._on_error,
        )
        try:
            await self._udp.start()
        except BaseException:
            with contextlib.suppress(Exception):
                await self._tcp.stop()
            raise

        self._tcping = Tcping(config, on_result=self._on_tcping)
        self._tcping.start()
        self._stats_task = asyncio.ensure_future(self._stats_loop())
        self._emit(StateEvent(state="running", message=f"监听 {LISTEN_HOST}:{config.listen_port}"))

    async def _shutdown(self) -> None:
        await self._teardown()
        self._emit(StateEvent(state="stopped"))

    async def _teardown(self) -> None:
        if self._stats_task is not None:
            self._stats_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._stats_task
            self._stats_task = None
        if self._tcping is not None:
            with contextlib.suppress(Exception):
                await self._tcping.stop()
            self._tcping = None
        if self._tcp is not None:
            with contextlib.suppress(Exception):
                await self._tcp.stop()
            self._tcp = None
        if self._udp is not None:
            with contextlib.suppress(Exception):
                await self._udp.stop()
            self._udp = None

    # ------------------------------------------------------------ 统计与事件

    async def _stats_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self._emit(
                StatsEvent(
                    ts=now_ts(),
                    domains=self._stats.snapshot_domains(),
                    tcp_conns=self._stats.tcp_conns,
                    udp_sessions=self._stats.udp_sessions,
                    total_hits=self._stats.total_hits,
                )
            )

    def _on_sni(self, domain: str) -> None:
        self._stats.add_domain(domain)
        self._emit(SniEvent(ts=now_ts(), domain=domain))

    def _on_conn_change(self, active: int) -> None:
        self._stats.tcp_conns = active

    def _on_udp_sessions(self, count: int) -> None:
        self._stats.udp_sessions = count

    def _on_tcping(self, latency_ms: float | None, peer: str | None) -> None:
        self._emit(TcpingEvent(ts=now_ts(), latency_ms=latency_ms, peer=peer))

    def _on_error(self, message: str) -> None:
        self._emit(NoticeEvent(ts=now_ts(), level="error", message=message))

    def _emit(self, event) -> None:
        try:
            self.events.put_nowait(event)
        except queue.Full:
            log.debug("事件队列已满，丢弃事件: %r", event)
