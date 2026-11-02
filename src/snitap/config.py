"""应用配置。"""

from __future__ import annotations

from dataclasses import dataclass

# 本地监听地址：只绑定本机回环，避免把流量转发能力暴露到局域网。
LISTEN_HOST = "127.0.0.1"

DEFAULT_LISTEN_PORT = 1234
DEFAULT_TARGET_HOST = "cf.090227.xyz"
DEFAULT_TARGET_PORT = 443


@dataclass(frozen=True)
class AppConfig:
    """一次转发会话的配置快照。"""

    listen_port: int = DEFAULT_LISTEN_PORT
    target_host: str = DEFAULT_TARGET_HOST
    target_port: int = DEFAULT_TARGET_PORT
