"""worker 线程与 GUI 线程之间的事件契约。

全部事件为不可变 dataclass：worker 线程产生后放入队列，GUI 只读消费，
统计信息以快照形式整体下发，避免跨线程共享可变状态。
"""

from __future__ import annotations

import time
from dataclasses import dataclass


def now_ts() -> str:
    """当天时间戳，格式 HH:mm:ss。"""
    return time.strftime("%H:%M:%S")


@dataclass(frozen=True)
class SniEvent:
    """嗅探到一个 SNI 域名。"""

    ts: str
    domain: str


@dataclass(frozen=True)
class TcpingEvent:
    """一次 tcping 结果；latency_ms 为 None 表示超时/失败。"""

    ts: str
    latency_ms: float | None
    peer: str | None = None


@dataclass(frozen=True)
class StateEvent:
    """worker 生命周期状态：running / stopped / error（仅启动失败使用 error）。"""

    state: str
    message: str = ""


@dataclass(frozen=True)
class StatsEvent:
    """统计快照：域名计数（按次数降序）+ 连接数 + 嗅探总数。"""

    ts: str
    domains: tuple[tuple[str, int], ...]
    tcp_conns: int
    udp_sessions: int
    total_hits: int


@dataclass(frozen=True)
class NoticeEvent:
    """运行期提示（如单个连接的上游失败），不改变监听状态。"""

    ts: str
    level: str  # "info" | "error"
    message: str
