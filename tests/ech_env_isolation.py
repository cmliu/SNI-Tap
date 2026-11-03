"""测试用配置隔离：把 ``snitap.config`` 固定到「环境变量未设置」的默认名单基线。

为什么需要：README 明确教用户用 ``SNITAP_ECH_PUBLIC_NAMES`` 覆盖掩护域名名单
（甚至「设为空串即关闭标记」）。开发者一旦照着做并在 shell 里 export，凡是
「断言默认名单含 ``cloudflare-ech.com``」的用例都会在开发机上假红——被测代码
没错，是测试夹具默认了进程环境干净。

隔离语义（逐用例生效，不留残余）：

- ``setUp``：暂存环境变量现值 → ``pop`` → ``importlib.reload(snitap.config)``
  落到默认基线；
- ``tearDown``：恢复暂存值 → 再 reload → 用**按暂存值独立复算出的期望**自检
  复原是否成功。**禁止硬编码默认名单**——那正是开发机上假红的根因。

``importlib.reload`` 在原命名空间内重新执行模块代码，因此 ``flow`` 早期
``from .config import is_ech_public_name`` 拿到的旧函数对象也会看到新名单，
本隔离对真实嗅探路径同样有效。

本模块文件名不以 ``test`` 开头，``unittest discover`` 不会把它当用例收集。
"""

from __future__ import annotations

import importlib
import os
import unittest

from snitap import config

ENV_NAME = "SNITAP_ECH_PUBLIC_NAMES"
DEFAULT_NAMES: tuple[str, ...] = ("cloudflare-ech.com",)


def expected_names_from_env(raw: str | None) -> tuple[str, ...]:
    """独立复算「环境变量取值 → 名单」的期望值（不复用源码的私有实现）。"""
    if raw is None:
        return DEFAULT_NAMES
    return tuple(part.strip().lower() for part in raw.split(",") if part.strip())


class ConfigIsolatedCase(unittest.TestCase):
    """在默认名单基线上跑用例，结束后把调用者的环境原样还回去。

    子类若重写 ``setUp``，**必须先调 ``super().setUp()``**（否则环境没被隔离，
    在导出了 ``SNITAP_ECH_PUBLIC_NAMES`` 的开发机上会假红）；``tearDown``
    无需重写。
    """

    #: 标记「setUp 尚未执行」，避免 setUp 抛错时 tearDown 二次崩溃掩盖真因
    _UNSET = object()

    def setUp(self) -> None:
        self._saved: object = os.environ.get(ENV_NAME)
        os.environ.pop(ENV_NAME, None)
        importlib.reload(config)

    def tearDown(self) -> None:
        saved = getattr(self, "_saved", self._UNSET)
        if saved is self._UNSET:
            return  # setUp 未跑完（已由 unittest 报告原始异常），不做无意义复原
        if saved is None:
            os.environ.pop(ENV_NAME, None)
        else:
            os.environ[ENV_NAME] = str(saved)
        importlib.reload(config)
        # 复原自检：期望值按暂存值独立复算，不硬编码默认名单
        self.assertEqual(config.ECH_PUBLIC_NAMES, expected_names_from_env(saved))  # type: ignore[arg-type]

    def reload_with(self, raw: str) -> None:
        """设置环境变量并真正 ``reload`` ``snitap.config``（覆盖路径专用）。"""
        os.environ[ENV_NAME] = raw
        importlib.reload(config)
