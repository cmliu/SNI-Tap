"""会话统计：四元组 (域名, 应用层, 传输层, 安全层) 计数、TCP 连接数、UDP 会话数。

安全层字段取 ``ProtocolStack.security_label``，因此带 `` ECH`` 后缀的组合与
非 ECH 组合天然落在两个不同的键上，统计表里独立成行。

两个 ECH 计数语义不同，不可混用：

- ``ech_hits``：**确证生效**的累计次数（``stack.ech``），与统计表里带
  `` ECH`` 后缀的行一一对应；
- ``ech_ext_hits``：**扩展存在**的累计次数（``stack.ech_ext``），包含 GREASE
  ECH；两者之差即「携带扩展但 SNI 非掩护域名」的疑似 GREASE 数。

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
        self.ech_hits = 0          # 确证生效（ECH 标记）的次数
        self.ech_ext_hits = 0      # 携带 0xFE0D 扩展的次数（含疑似 GREASE）
        self.tcp_conns = 0
        self.udp_sessions = 0

    def add_stack(self, stack: ProtocolStack) -> None:
        """按四元组键累加一次嗅探结果。

        ``ech_hits`` 只统计 ``stack.ech``（确证生效，安全层带 `` ECH`` 后缀），
        ``ech_ext_hits`` 统计 ``stack.ech_ext``（扩展存在，可能是 GREASE）；
        两者差值即疑似 GREASE 数，由 GUI footer 的 ``ech?`` 段呈现。
        """
        self._counter[stack.key] += 1
        self._total_hits += 1
        if stack.ech_ext:
            self.ech_ext_hits += 1
        if stack.ech:
            self.ech_hits += 1

    def snapshot_rows(self) -> tuple[StackRow, ...]:
        """按次数降序、同次数按四元组字典序升序的统计行。

        键的第 4 元素已是 ``security_label``，故 ECH 行与非 ECH 行各自成行。
        """
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
