"""ECH 掩护域名（``public_name``）判定与端到端语义收紧的验证。

背景（RFC 9849）：
- §6.2「GREASE ECH」：客户端**没有可用 ECHConfig 时 SHOULD 发送一个假的**
  encrypted_client_hello 扩展（随机 config_id / 合法 HPKE cipher_suite /
  合法的 KEM 输出 enc / 长度伪装成 L+C 的随机 payload）。
- §10.10.4：真 ECH 与 GREASE ECH 对被动观察者**设计上不可区分**——消息长度、
  明文扩展码点与顺序都不构成区分特征。因此「扩展存在」在单连接上无法判真伪。

唯一可用的现实判据：真 ECH 的外层 SNI 必然是该 ECHConfig 的 ``public_name``
（Cloudflare 为 ``cloudflare-ech.com``），GREASE ECH 的外层 SNI 就是用户正在
访问的真实域名。故语义拆成两个字段：

- ``ech_ext``：ClientHello 携带 ``0xFE0D`` 扩展（原始观测，可能是 GREASE）；
- ``ech``：确证生效 = ``ech_ext`` ∧ 外层 SNI 命中掩护域名名单。

本文件覆盖：精确匹配 / 大小写 / 空白 / 非法输入 / 相似域名 / 名单为空 /
环境变量覆盖，以及用户截图场景（两域名、两行统计）的端到端断言。

**环境隔离**：所有断言「默认名单包含 ``cloudflare-ech.com``」的用例都继承
:class:`ech_env_isolation.ConfigIsolatedCase`——开发机若按 README 导出了
``SNITAP_ECH_PUBLIC_NAMES``，用例先落默认基线再断言，结束后把环境原样还回去，
不会假红、也不会把名单泄漏给其它测试模块。
"""

from __future__ import annotations

import importlib
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from ech_env_isolation import ENV_NAME, ConfigIsolatedCase
from snitap import config
from snitap.flow import TcpFlow
from snitap.protocol import ProtocolStack
from snitap.stats import Stats
from test_tls_sniffer import build_client_hello

DEFAULT_PUBLIC_NAME = "cloudflare-ech.com"
REAL_DOMAIN = "test.cmliussss.dpdns.org"


class EchPublicNameMatchTest(ConfigIsolatedCase):
    """默认名单下的精确匹配语义（不做后缀 / 包含匹配）。"""

    def test_exact_default_name_hits(self) -> None:
        self.assertTrue(config.is_ech_public_name(DEFAULT_PUBLIC_NAME))

    def test_case_insensitive(self) -> None:
        for variant in (
            "Cloudflare-ECH.com",
            "CLOUDFLARE-ECH.COM",
            "cLoUdFlArE-eCh.CoM",
        ):
            with self.subTest(sni=variant):
                self.assertTrue(config.is_ech_public_name(variant))

    def test_surrounding_whitespace_is_ignored(self) -> None:
        for variant in (
            " cloudflare-ech.com",
            "cloudflare-ech.com ",
            "\tcloudflare-ech.com\r\n",
            "   CloudFlare-ECH.com  ",
        ):
            with self.subTest(sni=variant):
                self.assertTrue(config.is_ech_public_name(variant))

    def test_none_and_empty_are_false(self) -> None:
        for value in (None, "", "   ", "\t\n"):
            with self.subTest(sni=value):
                self.assertFalse(config.is_ech_public_name(value))

    def test_real_domain_is_false(self) -> None:
        # 用户实际访问的真实域名：GREASE ECH 场景，绝不是掩护域名
        self.assertFalse(config.is_ech_public_name(REAL_DOMAIN))
        self.assertFalse(config.is_ech_public_name("cf.090227.xyz"))
        self.assertFalse(config.is_ech_public_name("api.cloudflare.com"))

    def test_similar_domains_do_not_hit(self) -> None:
        """精确匹配：相似域名一律不命中，避免伪造域名冒充掩护域名。"""
        for value in (
            "evil-cloudflare-ech.com",
            "cloudflare-ech.com.evil.tld",
            "cloudflare-ech.com.evil",
            "xcloudflare-ech.com",
            "cloudflare-ech.co",
            "cloudflare-ech.com:443",
            "cloudflare-ech",
        ):
            with self.subTest(sni=value):
                self.assertFalse(config.is_ech_public_name(value))

    def test_trailing_dot_is_not_matched(self) -> None:
        """DNS 绝对名（尾点）不命中——这是**正确**行为，不做去尾点归一化。

        RFC 6066 §3 规定 SNI 的 ``HostName`` 不得带尾点，带尾点的 hello 属
        不可达输入；为它放宽匹配只会扩大「相似域名误判」的面。
        """
        self.assertFalse(config.is_ech_public_name(f"{DEFAULT_PUBLIC_NAME}."))

    def test_non_string_input_returns_false_without_raising(self) -> None:
        # 嗅探路径的硬约束：任意输入都返回 bool、绝不抛异常
        for value in (b"cloudflare-ech.com", 123, object(), ["cloudflare-ech.com"]):
            with self.subTest(value=value):
                self.assertIs(config.is_ech_public_name(value), False)  # type: ignore[arg-type]

    def test_default_names_constant(self) -> None:
        self.assertEqual(config.ECH_PUBLIC_NAMES, (DEFAULT_PUBLIC_NAME,))
        self.assertTrue(all(name == name.lower() for name in config.ECH_PUBLIC_NAMES))


class EchPublicNameEnvTest(ConfigIsolatedCase):
    """``SNITAP_ECH_PUBLIC_NAMES`` 环境变量覆盖（import 时求值一次）。

    环境隔离由 :class:`ConfigIsolatedCase` 提供：``setUp`` 落默认基线，
    ``tearDown`` 复原调用者的环境变量并按**复算值**自检，故本类可安全地在
    导出了该变量的开发机上运行。
    """

    def test_baseline_without_env_is_default(self) -> None:
        self.assertEqual(config.ECH_PUBLIC_NAMES, (DEFAULT_PUBLIC_NAME,))
        self.assertTrue(config.is_ech_public_name(DEFAULT_PUBLIC_NAME))

    def test_env_override_replaces_list(self) -> None:
        self.reload_with("ech.example.net,Public.Example.ORG")
        self.assertEqual(
            config.ECH_PUBLIC_NAMES, ("ech.example.net", "public.example.org")
        )
        self.assertTrue(config.is_ech_public_name("ech.example.net"))
        self.assertTrue(config.is_ech_public_name("PUBLIC.example.org"))
        # 默认值被整体替换，不再命中
        self.assertFalse(config.is_ech_public_name(DEFAULT_PUBLIC_NAME))

    def test_env_override_strips_whitespace_and_drops_empty_items(self) -> None:
        self.reload_with("  a.example , ,b.example,  ")
        self.assertEqual(config.ECH_PUBLIC_NAMES, ("a.example", "b.example"))

    def test_empty_env_disables_detection(self) -> None:
        # 空串 / 全逗号 → 名单为空 → 恒 False（用户可据此关闭该判定）
        for raw in ("", " ", ",", " , , ", "\t,"):
            with self.subTest(raw=raw):
                self.reload_with(raw)
                self.assertEqual(config.ECH_PUBLIC_NAMES, ())
                self.assertFalse(config.is_ech_public_name(DEFAULT_PUBLIC_NAME))
                self.assertFalse(config.is_ech_public_name("any.example"))

    def test_missing_env_uses_default(self) -> None:
        # 显式清掉变量再 reload → 回到默认名单
        self.reload_with("temp.example")           # 先制造非默认状态
        self.assertEqual(config.ECH_PUBLIC_NAMES, ("temp.example",))
        os.environ.pop(ENV_NAME, None)
        importlib.reload(config)
        self.assertEqual(config.ECH_PUBLIC_NAMES, (DEFAULT_PUBLIC_NAME,))
        self.assertTrue(config.is_ech_public_name(DEFAULT_PUBLIC_NAME))


class EchFieldSemanticsTest(unittest.TestCase):
    """``ech_ext`` / ``ech`` 的默认值与相互独立性（协议层契约，与环境无关）。"""

    def test_both_default_false(self) -> None:
        stack = ProtocolStack()
        self.assertFalse(stack.ech)
        self.assertFalse(stack.ech_ext)

    def test_extension_only_does_not_mark(self) -> None:
        stack = ProtocolStack(
            sni=REAL_DOMAIN, tls_version="TLS1.3", cipher="A128GCM", ech_ext=True
        )
        self.assertTrue(stack.ech_ext)
        self.assertFalse(stack.ech)
        self.assertEqual(stack.ech_mark, "")
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM")

    def test_both_true_adds_mark(self) -> None:
        stack = ProtocolStack(
            sni=DEFAULT_PUBLIC_NAME,
            tls_version="TLS1.3",
            cipher="A128GCM",
            ech=True,
            ech_ext=True,
        )
        self.assertEqual(stack.security_label, "TLS1.3/A128GCM ECH")
        self.assertEqual(stack.key[3], "TLS1.3/A128GCM ECH")


class ScreenshotScenarioTest(ConfigIsolatedCase):
    """用户截图场景的端到端复现（本轮 Bug 的验收用例）。

    同一会话里两个域名各一条 ProtocolStack：
    - ``cloudflare-ech.com`` + 扩展 → 确证真 ECH，安全层带 `` ECH``；
    - ``test.cmliussss.dpdns.org``（用户已关闭 ECH）+ 扩展 → GREASE，不标记。
    Stats 得到两行，``ech_hits=1``、``ech_ext_hits=2``。
    """

    def _run(self, sni: str, *, ech_payload: bytes | None) -> ProtocolStack:
        stacks: list[ProtocolStack] = []
        flow = TcpFlow(stacks.append)
        sink = flow.sink("up")
        assert sink is not None
        sink(build_client_hello(sni, alpn=b"h2", ech=ech_payload))
        flow.close()
        self.assertEqual(len(stacks), 1)
        return stacks[0]

    def test_two_domains_one_confirmed_one_grease(self) -> None:
        payload = bytes.fromhex("3f9c11d702e84baa5c6e0d91b7")
        confirmed = self._run(DEFAULT_PUBLIC_NAME, ech_payload=payload)
        grease = self._run(REAL_DOMAIN, ech_payload=payload)

        # 确证：扩展存在 + SNI 是掩护域名
        self.assertTrue(confirmed.ech_ext)
        self.assertTrue(confirmed.ech)
        self.assertEqual(confirmed.security_label, "TLS1.3/A128GCM ECH")
        self.assertEqual(confirmed.domain, DEFAULT_PUBLIC_NAME)

        # GREASE：扩展存在但 SNI 是真实域名 → 不标记
        self.assertTrue(grease.ech_ext)
        self.assertFalse(grease.ech)
        self.assertEqual(grease.security_label, "TLS1.3/A128GCM")
        self.assertEqual(grease.domain, REAL_DOMAIN)
        self.assertNotIn("ECH", grease.caption())

        stats = Stats()
        stats.add_stack(confirmed)
        stats.add_stack(grease)
        rows = stats.snapshot_rows()

        self.assertEqual(len(rows), 2)
        self.assertEqual(stats.distinct, 2)
        self.assertEqual(stats.total_hits, 2)
        self.assertEqual(stats.ech_hits, 1)
        self.assertEqual(stats.ech_ext_hits, 2)
        self.assertEqual(stats.ech_ext_hits - stats.ech_hits, 1)  # 1 条疑似 GREASE

        by_domain = {row.domain: row for row in rows}
        self.assertTrue(by_domain[DEFAULT_PUBLIC_NAME].has_ech)
        self.assertFalse(by_domain[REAL_DOMAIN].has_ech)
        self.assertEqual(by_domain[DEFAULT_PUBLIC_NAME].security, "TLS1.3/A128GCM ECH")
        self.assertEqual(by_domain[REAL_DOMAIN].security, "TLS1.3/A128GCM")
        # 两行都是同一网络安全层 + 同一应用层，唯一差异就是 ECH 后缀
        self.assertEqual(
            {row.caption() for row in rows},
            {"h2 · TCP · TLS1.3/A128GCM", "h2 · TCP · TLS1.3/A128GCM ECH"},
        )

    def test_same_domain_repeat_is_idempotent_for_counters(self) -> None:
        # 同一域名连两次 GREASE：不进 ech_hits，但 ech_ext_hits 每次都累加
        stats = Stats()
        for _ in range(2):
            stats.add_stack(self._run(REAL_DOMAIN, ech_payload=b"\x01\x02\x03"))
        self.assertEqual(stats.ech_hits, 0)
        self.assertEqual(stats.ech_ext_hits, 2)
        rows = stats.snapshot_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count, 2)
        self.assertFalse(rows[0].has_ech)


if __name__ == "__main__":
    unittest.main()
