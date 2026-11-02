"""会话统计：域名计数器、TCP 连接数、UDP 映射数、嗅探总数。

只在 worker 线程内修改，GUI 只读取 snapshot 出来的不可变数据。
"""

from __future__ import annotations

from collections import Counter


class Stats:
    """单次启动内的累计统计。"""

    def __init__(self) -> None:
        self._counter: Counter[str] = Counter()
        self._total_hits = 0
        self.tcp_conns = 0
        self.udp_sessions = 0

    def add_domain(self, domain: str) -> None:
        self._counter[domain] += 1
        self._total_hits += 1

    def snapshot_domains(self) -> tuple[tuple[str, int], ...]:
        """按次数降序、同次数按域名升序排列的（域名, 次数）元组。"""
        return tuple(sorted(self._counter.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def total_hits(self) -> int:
        return self._total_hits
