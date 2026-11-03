"""统计聚合（``stats.Stats``）单元测试。

覆盖：四元组累计、排序稳定性、``ech_hits``（确证生效）与 ``ech_ext_hits``
（扩展存在，含疑似 GREASE）双计数、ECH 行与非 ECH 行独立成行、
distinct 语义、快照不可变性、``StatsEvent`` 字段追加的向后兼容性。
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from snitap.protocol import UNKNOWN, ProtocolStack
from snitap.stats import Stats


def make_stack(
    sni: str | None = "api.example.com",
    *,
    alpn: str = "h2",
    tls_version: str = "TLS1.3",
    cipher: str = "A128GCM",
    transport: str = "TCP",
    quic_version: str = UNKNOWN,
    ech: bool = False,
    ech_ext: bool | None = None,
    provisional: bool = False,
) -> ProtocolStack:
    """构造一条用于统计的协议栈快照。

    ``ech`` 是确证生效（决定安全层是否带 `` ECH`` 后缀），``ech_ext`` 是扩展
    存在的原始观测；GREASE 场景 = ``ech_ext=True, ech=False``。
    ``ech_ext`` 省略（``None``）时跟随 ``ech``——确证生效必然伴随扩展存在，
    这样既有夹具自动保持一致。
    """
    ext = ech if ech_ext is None else ech_ext
    return ProtocolStack(
        sni=sni,
        transport=transport,
        quic_version=quic_version,
        tls_version=tls_version,
        cipher=cipher,
        alpn=alpn,
        provisional=provisional,
        ech=ech,
        ech_ext=ext,
    )


class StatsAddStackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stats = Stats()

    def test_same_key_accumulates(self) -> None:
        self.stats.add_stack(make_stack())
        self.stats.add_stack(make_stack())
        rows = self.stats.snapshot_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count, 2)
        self.assertEqual(self.stats.total_hits, 2)
        self.assertEqual(self.stats.distinct, 1)

    def test_provisional_does_not_split_rows(self) -> None:
        self.stats.add_stack(make_stack(provisional=True))
        self.stats.add_stack(make_stack(provisional=False))
        self.assertEqual(self.stats.distinct, 1)
        self.assertEqual(self.stats.snapshot_rows()[0].count, 2)

    def test_ech_hits_accumulate(self) -> None:
        self.stats.add_stack(make_stack(ech=True))
        self.stats.add_stack(make_stack(ech=True))
        self.stats.add_stack(make_stack(ech=False))
        self.assertEqual(self.stats.ech_hits, 2)
        self.assertEqual(self.stats.total_hits, 3)

    def test_ech_hits_default_zero(self) -> None:
        self.assertEqual(self.stats.ech_hits, 0)
        self.stats.add_stack(make_stack())
        self.assertEqual(self.stats.ech_hits, 0)

    def test_ech_ext_hits_counts_extension_presence(self) -> None:
        # 确证 1 条 + GREASE 2 条 = 扩展存在 3 条；确证只算 1 条
        self.stats.add_stack(make_stack(ech=True, ech_ext=True))
        self.stats.add_stack(make_stack(ech=False, ech_ext=True))
        self.stats.add_stack(make_stack(ech=False, ech_ext=True))
        self.stats.add_stack(make_stack())  # 无扩展
        self.assertEqual(self.stats.ech_hits, 1)
        self.assertEqual(self.stats.ech_ext_hits, 3)
        self.assertEqual(self.stats.total_hits, 4)

    def test_ech_ext_hits_default_zero(self) -> None:
        self.assertEqual(self.stats.ech_ext_hits, 0)
        self.stats.add_stack(make_stack())
        self.assertEqual(self.stats.ech_ext_hits, 0)

    def test_difference_is_suspected_grease(self) -> None:
        # ech_ext_hits - ech_hits 即「携带扩展但 SNI 非掩护域名」的疑似 GREASE 数
        for _ in range(2):
            self.stats.add_stack(make_stack(ech=True, ech_ext=True))
        for _ in range(5):
            self.stats.add_stack(make_stack(ech=False, ech_ext=True))
        self.assertEqual(self.stats.ech_ext_hits - self.stats.ech_hits, 5)

    def test_grease_only_row_has_no_ech_suffix(self) -> None:
        # GREASE 行（扩展存在但未确证）与纯明文行同键 → 同一行累计，且无 ECH 后缀
        self.stats.add_stack(make_stack(ech=False, ech_ext=True))
        self.stats.add_stack(make_stack(ech=False, ech_ext=False))
        rows = self.stats.snapshot_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count, 2)
        self.assertFalse(rows[0].has_ech)
        self.assertEqual(rows[0].security, "TLS1.3/A128GCM")
        self.assertEqual(self.stats.ech_ext_hits, 1)
        self.assertEqual(self.stats.ech_hits, 0)

    def test_ech_row_is_separate_from_non_ech_row(self) -> None:
        self.stats.add_stack(make_stack(ech=True))
        self.stats.add_stack(make_stack(ech=False))
        rows = self.stats.snapshot_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(self.stats.distinct, 2)
        ech_rows = [row for row in rows if row.has_ech]
        plain_rows = [row for row in rows if not row.has_ech]
        self.assertEqual(len(ech_rows), 1)
        self.assertEqual(len(plain_rows), 1)
        self.assertEqual(ech_rows[0].security, "TLS1.3/A128GCM ECH")
        self.assertEqual(ech_rows[0].caption(), "h2 · TCP · TLS1.3/A128GCM ECH")
        self.assertEqual(plain_rows[0].security, "TLS1.3/A128GCM")

    def test_sort_uses_full_key_for_stability(self) -> None:
        # 同次数时按 (domain, app, transport, security) 字典序升序
        self.stats.add_stack(make_stack("b.example", ech=True))
        self.stats.add_stack(make_stack("b.example", ech=False))
        self.stats.add_stack(make_stack("a.example", ech=True))
        rows = self.stats.snapshot_rows()
        self.assertEqual([row.domain for row in rows], ["a.example", "b.example", "b.example"])
        # 同一域名下 "TLS1.3/A128GCM" < "TLS1.3/A128GCM ECH"（前缀更短者在前）
        self.assertEqual(rows[1].security, "TLS1.3/A128GCM")
        self.assertEqual(rows[2].security, "TLS1.3/A128GCM ECH")

    def test_count_descending(self) -> None:
        for _ in range(3):
            self.stats.add_stack(make_stack("hot.example"))
        self.stats.add_stack(make_stack("cold.example"))
        rows = self.stats.snapshot_rows()
        self.assertEqual(rows[0].domain, "hot.example")
        self.assertEqual(rows[0].count, 3)
        self.assertEqual(rows[1].domain, "cold.example")

    def test_snapshot_rows_is_tuple(self) -> None:
        self.stats.add_stack(make_stack())
        self.assertIsInstance(self.stats.snapshot_rows(), tuple)

    def test_unknown_domain_uses_single_placeholder(self) -> None:
        self.stats.add_stack(make_stack(sni=None, alpn=UNKNOWN, transport="QUIC", quic_version="v1"))
        rows = self.stats.snapshot_rows()
        self.assertEqual(rows[0].domain, UNKNOWN)
        self.assertEqual(rows[0].transport, "QUIC/v1")


class StatsEventContractTest(unittest.TestCase):
    """``StatsEvent.ech_hits`` / ``ech_ext_hits`` 均追加在字段表末尾，保证向后兼容。"""

    def test_ech_hits_defaults_to_zero(self) -> None:
        from snitap.events import StatsEvent

        event = StatsEvent(
            ts="00:00:00",
            rows=(),
            tcp_conns=0,
            udp_sessions=0,
            total_hits=0,
            distinct=0,
        )
        self.assertEqual(event.ech_hits, 0)
        self.assertEqual(event.ech_ext_hits, 0)
        self.assertFalse(event.truncated)

    def test_legacy_positional_construction_keeps_truncated(self) -> None:
        # 旧签名的第 7 个位置是 truncated；ech_hits / ech_ext_hits 必须追加在它之后，
        # 否则 truncated 会被静默顶掉、回落到 False。
        from snitap.events import StatsEvent

        event = StatsEvent("00:00:00", (), 1, 2, 3, 4, True)
        self.assertTrue(event.truncated)
        self.assertEqual(event.ech_hits, 0)
        self.assertEqual(event.ech_ext_hits, 0)
        self.assertEqual(event.tcp_conns, 1)
        self.assertEqual(event.distinct, 4)

    def test_ninth_positional_is_ech_ext_hits(self) -> None:
        # 第 9 个位置参数是 ech_ext_hits（尾序：truncated(7) → ech_hits(8) →
        # ech_ext_hits(9)）
        from snitap.events import StatsEvent

        event = StatsEvent("00:00:00", (), 0, 0, 9, 1, False, 3, 7)
        self.assertEqual(event.ech_hits, 3)
        self.assertEqual(event.ech_ext_hits, 7)
        self.assertFalse(event.truncated)

    def test_field_order_appends_after_ech_hits(self) -> None:
        import dataclasses

        from snitap.events import StatsEvent

        names = [field.name for field in dataclasses.fields(StatsEvent)]
        self.assertEqual(names[-2:], ["ech_hits", "ech_ext_hits"])
        # 尾序固定：truncated(7) → ech_hits(8) → ech_ext_hits(9)
        self.assertEqual(names[6:], ["truncated", "ech_hits", "ech_ext_hits"])


if __name__ == "__main__":
    unittest.main()
