"""应用配置。"""

from __future__ import annotations

import os
from dataclasses import dataclass

# 本地监听地址：只绑定本机回环，避免把流量转发能力暴露到局域网。
LISTEN_HOST = "127.0.0.1"

DEFAULT_LISTEN_PORT = 1234
DEFAULT_TARGET_HOST = "cf.090227.xyz"
DEFAULT_TARGET_PORT = 443

# ECH 掩护域名（ECHConfig.contents.public_name）。
# 真 ECH 握手的外层 SNI 必然是其中之一；GREASE ECH 的外层 SNI 则是真实域名。
# 可用环境变量 SNITAP_ECH_PUBLIC_NAMES 覆盖（逗号分隔，大小写不敏感）。
_ECH_PUBLIC_NAMES_ENV = "SNITAP_ECH_PUBLIC_NAMES"
_DEFAULT_ECH_PUBLIC_NAMES: tuple[str, ...] = ("cloudflare-ech.com",)


def _load_ech_public_names() -> tuple[str, ...]:
    """读取 ECH 掩护域名名单。

    环境变量 ``SNITAP_ECH_PUBLIC_NAMES`` 存在时按 ``,`` 切分、去首尾空白、
    转小写、丢弃空项（因此设成空串 / 全逗号等价于「名单为空 = 关闭判定」）；
    否则使用 Cloudflare 的默认掩护域名。

    Returns:
        小写化的掩护域名元组；可能为空元组（表示恒不命中）。
    """
    raw = os.environ.get(_ECH_PUBLIC_NAMES_ENV)
    if raw is None:
        return _DEFAULT_ECH_PUBLIC_NAMES
    names: list[str] = []
    for part in raw.split(","):
        name = part.strip().lower()
        if name:
            names.append(name)
    return tuple(names)


# import 时求值一次即可：名单是进程级常量，运行期不热更新（GUI 不提供入口）。
ECH_PUBLIC_NAMES: tuple[str, ...] = _load_ech_public_names()


def is_ech_public_name(sni: str | None) -> bool:
    """判断一个外层 SNI 是否为 ECH 掩护域名（public_name）。

    真 ECH 握手的 ``ClientHelloOuter`` 明文 SNI 是 ECHConfig 里的
    ``public_name``（Cloudflare 为 ``cloudflare-ech.com``）；GREASE ECH 的
    外层 SNI 则是用户正在访问的真实域名。这是被动观察下唯一可用的区分依据。

    匹配规则：``strip().lower()`` 后与 :data:`ECH_PUBLIC_NAMES` 做**精确匹配**，
    不做后缀 / 包含匹配（否则 ``evil-cloudflare-ech.com`` 会被误判为真 ECH）。

    本函数必须对任意输入返回 ``bool`` 且**绝不抛异常**——它位于嗅探路径上。

    Args:
        sni: 外层 ClientHello 的 SNI；``None`` / 空串 / 非字符串一律 False。

    Returns:
        命中掩护域名名单时为 ``True``，否则 ``False``（名单为空时恒 False）。
    """
    if not isinstance(sni, str):
        return False
    candidate = sni.strip().lower()
    if not candidate:
        return False
    return candidate in ECH_PUBLIC_NAMES


@dataclass(frozen=True)
class AppConfig:
    """一次转发会话的配置快照。"""

    listen_port: int = DEFAULT_LISTEN_PORT
    target_host: str = DEFAULT_TARGET_HOST
    target_port: int = DEFAULT_TARGET_PORT
