"""parse_target() 行为表：锁定迁移前后语义完全一致（GUI 框架迁移回归护栏）。

期望值全部取自迁移前的 Qt 版实现（``git show HEAD:src/snitap/gui/main_window.py``），
逐条对拍后固化于此。``QUIRK_CASES`` 记录的是**迁移前就存在**的历史语义
（例如 ``host:abc`` 整体当 host、全角数字被 ``str.isdigit`` 放行），
这些不是本次迁移引入的缺陷，但必须保持原样，否则构成行为回归。
"""

from __future__ import annotations

import unittest

from snitap.gui.main_window import parse_target

# 常规行为：(输入, 期望)
NORMAL_CASES: list[tuple[str, tuple[str, int] | None]] = [
    ("cf.090227.xyz", ("cf.090227.xyz", 443)),
    ("cf.090227.xyz:8443", ("cf.090227.xyz", 8443)),
    ("cf.090227.xyz:0", None),
    ("cf.090227.xyz:65536", None),
    ("[::1]", ("::1", 443)),
    ("[::1]:8443", ("::1", 8443)),
    ("2001:db8::1", ("2001:db8::1", 443)),
    ("a:b:c", ("a:b:c", 443)),
    ("", None),
    ("   ", None),
    (":443", None),
    ("1.2.3.4:80", ("1.2.3.4", 80)),
    ("a.b.c:1", ("a.b.c", 1)),
    ("a.b.c:65535", ("a.b.c", 65535)),
    ("[2001:db8::1]:8443", ("2001:db8::1", 8443)),
    ("[::]", ("::", 443)),
    ("[]", None),
    ("[]:443", None),
    ("[::1]:0", None),
    ("[::1]:abc", None),
    (" host:8443 ", ("host", 8443)),
    ("host", ("host", 443)),
]

# 迁移前既有语义（保持原样即视为通过）
QUIRK_CASES: list[tuple[str, tuple[str, int] | None]] = [
    # 冒号后不是 1-5 位纯数字 → 整体当 host，端口回落 443
    ("cf.090227.xyz:abc", ("cf.090227.xyz:abc", 443)),
    # 6 位数字超出 1-5 位窗口 → 同样整体当 host，不报错
    ("host:123456", ("host:123456", 443)),
    ("a.b.c:000443", ("a.b.c:000443", 443)),
    ("host:", ("host:", 443)),
    ("a.b.c:", ("a.b.c:", 443)),
    ("host: 443", ("host: 443", 443)),
    ("a.b.c:-1", ("a.b.c:-1", 443)),
    # 方括号后不是冒号 → 整体当 host，不视为非法
    ("[::1]8443", ("[::1]8443", 443)),
    ("[::1]x", ("[::1]x", 443)),
    # 冒号多于一个且非方括号 → 视作 IPv6 字面量
    ("a:b:443", ("a:b:443", 443)),
    # 全角数字被 str.isdigit 与 int() 接受
    ("a.b.c:１２３", ("a.b.c", 123)),
]


class ParseTargetContractTest(unittest.TestCase):
    """逐条锁定 parse_target 的返回值（含 None 分支）。"""

    def test_normal_cases(self) -> None:
        """常规输入解析结果与迁移前的 Qt 版一致。"""
        for text, expected in NORMAL_CASES:
            with self.subTest(text=text):
                self.assertEqual(parse_target(text), expected)

    def test_preexisting_quirks_preserved(self) -> None:
        """迁移前既有语义必须原样保留，不得在迁移中「顺手修正」。"""
        for text, expected in QUIRK_CASES:
            with self.subTest(text=text):
                self.assertEqual(parse_target(text), expected)

    def test_returns_none_type_for_invalid(self) -> None:
        """非法输入统一返回 None（而不是抛异常或返回空 tuple）。"""
        for text in ("", "   ", ":443", "cf.090227.xyz:0", "[]", "[::1]:65536"):
            with self.subTest(text=text):
                self.assertIsNone(parse_target(text))

    def test_default_port_override(self) -> None:
        """省略端口时使用传入的 default_port。"""
        self.assertEqual(parse_target("host"), ("host", 443))
        self.assertEqual(parse_target("host", default_port=8443), ("host", 8443))
        self.assertEqual(parse_target("[::1]", default_port=8080), ("::1", 8080))
        # 显式端口优先于 default_port
        self.assertEqual(parse_target("host:1234", default_port=8443), ("host", 1234))

    def test_port_boundaries(self) -> None:
        """端口 1 与 65535 可接受，0 与 65536 拒绝。"""
        self.assertEqual(parse_target("h:1"), ("h", 1))
        self.assertEqual(parse_target("h:65535"), ("h", 65535))
        self.assertIsNone(parse_target("h:0"))
        self.assertIsNone(parse_target("h:65536"))
        self.assertEqual(parse_target("[::1]:1"), ("::1", 1))
        self.assertEqual(parse_target("[::1]:65535"), ("::1", 65535))
        self.assertIsNone(parse_target("[::1]:0"))
        self.assertIsNone(parse_target("[::1]:65536"))

    def test_whitespace_stripped(self) -> None:
        """首尾空白被 strip，内部空白原样保留。"""
        self.assertEqual(parse_target("  host  "), ("host", 443))
        self.assertEqual(parse_target("  host:8443  "), ("host", 8443))
        self.assertEqual(parse_target("ho st"), ("ho st", 443))


if __name__ == "__main__":
    unittest.main()
