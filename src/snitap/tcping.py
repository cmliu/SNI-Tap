"""tcping：周期性对转发目标的 TCP 端口做握手测速。"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable

from .config import AppConfig

log = logging.getLogger(__name__)

INTERVAL_SECONDS = 3.0
TIMEOUT_SECONDS = 2.0


class Tcping:
    """每 3 秒 connect 一次目标端口，只测握手延迟，不发送任何数据。"""

    def __init__(self, config: AppConfig, on_result: Callable[[float | None, str | None], None]) -> None:
        self._config = config
        self._on_result = on_result
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._task
        self._task = None

    async def _loop(self) -> None:
        while True:
            await self._probe()
            await asyncio.sleep(INTERVAL_SECONDS)

    async def _probe(self) -> None:
        latency_ms: float | None = None
        peer: str | None = None
        start = time.perf_counter()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._config.target_host, self._config.target_port),
                timeout=TIMEOUT_SECONDS,
            )
            latency_ms = (time.perf_counter() - start) * 1000.0
            info = writer.get_extra_info("peername")
            if info:
                peer = f"{info[0]}:{info[1]}"
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        except asyncio.CancelledError:
            raise
        except Exception:
            latency_ms = None
            peer = None

        try:
            self._on_result(latency_ms, peer)
        except Exception:
            log.debug("tcping 回调异常", exc_info=True)
