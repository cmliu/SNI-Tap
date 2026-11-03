"""会话统计：四元组 (域名, 应用层, 传输层, 安全层) 计数、TCP 连接数、UDP 会话数。

只在 worker 线程内修改，GUI 只读取 snapshot 出来的不可变数据。
排序键 ``(-count, domain, app, transport, security)`` 全字段参与，
保证快照逐帧稳定、不跳行。
"""

from __future__ import annotations

from collections import Counter

from .protocol import ProtocolStack, StackRow

# 统计键：(domain, app, transport_label, security)
_Key = tuple[str, str, str, str]


class Stats:
    """单次启动内的累计统计。"""

    MAX_ROWS = 300

    def __init__(self) -> None:
        self._counter: Counter[_Key] = Counter()
        self._total_hits = 0
        self.tcp_conns = 0
        self.udp_sessions = 0

    def add_stack(self, stack: ProtocolStack) -> None:
        """按四元组键累加一次嗅探结果。"""
        self._counter[stack.key] += 1
        self._total_hits += 1

    def snapshot_rows(self) -> tuple[StackRow, ...]:
        """按次数降序、同次数按四元组字典序升序的统计行。"""
        items = sorted(self._counter.items(), key=lambda kv: (-kv[1], *kv[0]))
        return tuple(
            StackRow(domain=key[0], app=key[1], transport=key[2], security=key[3], count=count)
            for key, count in items
        )

    @property
    def distinct(self) -> int:
        """当前不同协议栈组合数。"""
        return len(self._counter)

    @property
    def total_hits(self) -> int:
        return self._total_hits
