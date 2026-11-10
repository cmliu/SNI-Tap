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

# ---------------------------------------------------------------- 地址格式化
#
# asyncio 的 "peername" / "sockname" 在 IPv6 上是 4 元组
# ``(host, port, flowinfo, scope_id)``，其中 host **不含方括号**，链路本地地址
# 还带 ``%zone`` 后缀（如 ``fe80::1%eth0``）。若直接 ``f"{host}:{port}"``，
# IPv6 场景会拼出 ``2606:4700:3030::6815:47f9:443`` —— 地址与端口粘连，
# 肉眼无法切分。这里统一按 RFC 3986 的方括号写法渲染：
# ``[2606:4700:3030::6815:47f9]:443``。
#
# IPv4 / 域名的输出与旧实现完全一致（``104.16.132.229:443``），不额外加括号。


def _is_ipv6_literal(address: str) -> bool:
    """判断（已剥掉方括号的）地址文本是否为 IPv6 字面量。

    判据：含 ``:`` 即视为 IPv6。IPv4 点分十进制、主机名、域名都不含冒号；
    zone id 形如 ``fe80::1%eth0`` 也含冒号，因此天然走方括号分支，且 zone id
    会原样保留在方括号内。

    Args:
        address: 已 ``strip()``、且已剥掉外层方括号的地址文本。

    Returns:
        地址文本形如 IPv6 时为 ``True``，否则 ``False``。
    """
    return ":" in address


def format_host_port(host: object, port: object = None) -> str:
    """把 ``(host, port)`` 渲染成无歧义的 ``host:port`` 文本。

    纯函数：无 I/O、无副作用、不抛异常（对任意输入都返回 ``str``）。

    规则：

    - IPv6 字面量（含 ``::``、完整 8 段、``%zone``、``::ffff:1.2.3.4``）→ 地址
      包进方括号：``[::1]:443``；
    - 已带方括号的 host（``"[::1]"``）→ 剥掉旧括号后再包一次，避免
      ``[[::1]]:443``；
    - 其他 host（IPv4 / 域名）→ 原样拼接，``104.16.132.229:443``；
    - ``port`` 为 ``None`` 或空白字符串 → 只输出地址部分（IPv6 仍带方括号）。

    Args:
        host: 地址部分；可为任意对象（内部 ``str()`` 归一），``None`` 视作空串。
        port: 端口部分；``None`` / 空串表示省略端口。

    Returns:
        格式化后的 ``host:port`` 文本；host 为空时形如 ``":443"``。
    """
    address = "" if host is None else str(host).strip()
    # 已含方括号：先剥掉，统一在下面按判据重新包一次（幂等）。
    if len(address) > 2 and address.startswith("[") and address.endswith("]"):
        address = address[1:-1].strip()
    body = f"[{address}]" if _is_ipv6_literal(address) else address
    port_text = "" if port is None else str(port).strip()
    if not port_text:
        return body
    return f"{body}:{port_text}"


def _format_peer_text(text: str) -> str | None:
    """格式化「整段字符串」形态的对端地址。

    asyncio 通常给元组，但 ``get_extra_info("peername")`` 在部分传输实现
    （以及第三方/socket 对象）上可能是已拼好的字符串。这里做稳健兜底，
    绝不再产出 ``::1:443`` 这类地址与端口粘连的歧义输出。

    规则：

    - 空白字符串 → ``None``；
    - 以 ``[`` 开头（``[::1]`` / ``[::1]:443`` / ``[fe80::1%eth0]:443``）→
      认为调用方已按规范格式化，原样返回；
    - 冒号 ≥ 2（``::1`` / ``2001:db8::1`` / ``fe80::1%eth0`` /
      ``::ffff:1.2.3.4``）→ 整体视为 IPv6 字面量，包一层方括号；
    - 冒号 0 或 1 个（``host`` / ``host:443`` / ``1.2.3.4:443``）→ 原样返回。

    Args:
        text: 待格式化的地址字符串。

    Returns:
        格式化后的文本；输入为空白时返回 ``None``。
    """
    stripped = text.strip()
    if not stripped:
        return None
    if stripped.startswith("["):
        return stripped
    if stripped.count(":") >= 2:
        return f"[{stripped}]"
    return stripped


def format_peer(peername: object) -> str | None:
    """把 asyncio 的 ``peername`` 渲染成 GUI 可读的 ``host:port`` 文本。

    纯函数：无 I/O、无副作用。覆盖以下输入形态：

    - ``None`` / 空序列 / 空字符串 → ``None``（GUI 侧据此隐藏 peer 片段）；
    - IPv4 元组 ``("104.16.132.229", 443)`` → ``"104.16.132.229:443"``；
    - IPv6 元组 ``("2606:4700:3030::6815:47f9", 443, 0, 0)`` →
      ``"[2606:4700:3030::6815:47f9]:443"``（忽略 flowinfo / scope_id 两个尾项）；
    - 带 zone id：``("fe80::1%eth0", 443, 0, 2)`` → ``"[fe80::1%eth0]:443"``；
    - 直接给字符串：``"1.2.3.4:443"`` → 原样；``"::1"`` → ``"[::1]"``。

    Args:
        peername: ``StreamWriter.get_extra_info("peername")`` 的返回值。

    Returns:
        格式化后的对端标识；无有效对端信息时返回 ``None``。
    """
    if peername is None:
        return None
    if isinstance(peername, str):
        return _format_peer_text(peername)
    if isinstance(peername, (tuple, list)):
        if not peername:
            return None
        host = peername[0]
        port = peername[1] if len(peername) > 1 else None
        if host is None or (isinstance(host, str) and not host.strip()):
            return None
        return format_host_port(host, port)
    # 其他对象（如自定义 socket 地址对象）：退化为字符串兜底，绝不抛异常。
    return _format_peer_text(str(peername))


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
            # IPv6 的 peername 是 4 元组且 host 不带方括号，统一交给
            # format_peer() 渲染，避免 "2606:...:47f9:443" 这种粘连输出。
            peer = format_peer(writer.get_extra_info("peername"))
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
