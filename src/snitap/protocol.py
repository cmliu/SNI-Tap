"""共享契约模块：三层（应用层 / 传输层 / 安全层）的名称映射与协议栈快照。

本模块是全项目唯一的「未知值」来源（``UNKNOWN == "-"``），禁止其他文件
再定义第二种占位写法；同时不依赖任何其他项目模块。

核心约定：
- 统计键 = ``(domain, app, transport_label, security)`` 有序四元组，
  ``provisional`` 与各 ``*_source`` 不进键——统计表是聚合真值，日志是单次观测；
  安全层可能带 `` ECH`` 后缀（见 :attr:`ProtocolStack.security_label`），
  ECH 与非 ECH 的同一组合因此天然分成两行统计；
- 名称表必须单射（不同 ID 不得映射到同一字符串），否则「任一层不同即
  独立成行」的语义会被短名合并破坏；
- 三层顺序固定：应用层 → 传输层 → 安全层，日志、摘要、表头、文档全部同序。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# 全项目唯一未知占位符；禁止 "" / None / "?" / "N/A" / "unknown"。
# ``sni is None`` 只在 ProtocolStack 内部表达，对外经 domain 属性转成 UNKNOWN。
UNKNOWN = "-"
CAPTION_SEP = " · "
LOG_SEP = "  "  # 两个空格
PROVISIONAL_MARK = "?"
ECH_MARK = "ECH"  # 安全层后缀：确证客户端发起真 ECH（扩展存在 ∧ SNI 是掩护域名）


class LayerSource(str, Enum):
    """一个层值的来源：未观测 / 客户端偏好 / 服务端协商。"""

    NONE = "none"
    CLIENT = "client"          # 来自 ClientHello（客户端偏好 / 最高支持）
    NEGOTIATED = "negotiated"  # 来自 ServerHello / 服务端 Initial


# 只收录 TLS1.3 的 5 套（名字天然唯一）。TLS 1.2 的套件一律走 0x%04x，
# 避免短名把 0xc02f(ECDHE-RSA-AES128-GCM-SHA256) 与 0x009c(RSA-AES128-GCM-SHA256)
# 这类仅靠不同前置条件区分的同名套件合并进同一个统计键。
_TLS_VERSIONS = {
    0x0304: "TLS1.3",
    0x0303: "TLS1.2",
    0x0302: "TLS1.1",
    0x0301: "TLS1.0",
    0x0300: "SSL3.0",
}
_QUIC_VERSIONS = {
    0x00000001: "v1",
    0x6B3343CF: "v2",
    0xFF00001D: "draft-29",
    0x00000000: "vneg",
}
_CIPHERS = {
    0x1301: "A128GCM",
    0x1302: "A256GCM",
    0x1303: "CHACHA20",
    0x1304: "A128CCM",
    0x1305: "A128CCM8",
}


def is_grease(value: int) -> bool:
    """判定一个 16 位值是否为 TLS GREASE（RFC 8701）。

    GREASE 形如 0x?a?a：两个字节相同且低半字节为 0xa
    （0x0a0a, 0x1a1a, … 0xfafa 共 16 个值）。
    """
    return (value >> 8) == (value & 0xFF) and (value & 0x0F) == 0x0A


def tls_version_name(version: int) -> str:
    """TLS legacy/supported 版本号 → 展示名；未收录 → ``0x%04x``。"""
    return _TLS_VERSIONS.get(version, "0x%04x" % version)


def quic_version_name(version: int) -> str:
    """QUIC 版本号 → 展示名；版本协商包(0) → vneg；未收录 → ``0x%08x``。"""
    return _QUIC_VERSIONS.get(version, "0x%08x" % version)


def cipher_name(value: int) -> str:
    """TLS 密码套件 → 展示名；未收录 → ``0x%04x``。"""
    return _CIPHERS.get(value, "0x%04x" % value)


def alpn_name(raw: bytes) -> str:
    """ALPN 协议名字节串 → 展示名。

    可打印 ASCII 原样保留；含控制字符 / 非 ASCII → 十六进制；空 → UNKNOWN。
    """
    if not raw:
        return UNKNOWN
    if all(0x20 <= b <= 0x7E for b in raw):
        return raw.decode("ascii")
    return raw.hex()


def transport_label(transport: str, quic_version: str) -> str:
    """把内部传输层值规格化为展示名（FIX-5 的唯一出处）。

    - TCP 连接 → ``"TCP"``
    - QUIC 版本已识别 → ``"QUIC/v1"`` / ``"QUIC/v2"`` / ``"QUIC/draft-29"`` /
      ``"QUIC/0x%08x"``（未收录版本）
    - QUIC 版本协商包 → ``"QUIC/vneg"``
    - QUIC 版本未解出 → ``"QUIC/-"``
    - 纯 UDP 非 QUIC → ``"UDP"``

    禁止出现裸 ``"QUIC"`` 字符串。
    """
    if transport == "TCP":
        return "TCP"
    if transport == "QUIC":
        if quic_version == UNKNOWN:
            return "QUIC/-"
        return f"QUIC/{quic_version}"
    return "UDP"


def _caption(app: str, transport: str, security: str) -> str:
    """统计摘要拼装（``ProtocolStack`` 与 ``StackRow`` 共用，保证同 key 同文案）。"""
    return f"{app}{CAPTION_SEP}{transport}{CAPTION_SEP}{security}"


@dataclass(frozen=True)
class ProtocolStack:
    """一次连接 / 会话合并出的三层协议栈快照（每连接至多一条）。"""

    sni: str | None = None
    transport: str = "TCP"  # 内部值："TCP" | "QUIC" | "UDP"
    quic_version: str = UNKNOWN
    tls_version: str = UNKNOWN
    tls_source: LayerSource = LayerSource.NONE
    cipher: str = UNKNOWN
    cipher_source: LayerSource = LayerSource.NONE
    alpn: str = UNKNOWN
    alpn_source: LayerSource = LayerSource.NONE
    provisional: bool = False
    # **确证生效**：即 ``ech_ext`` 为真 **且** 外层 SNI 命中 ECH 掩护域名
    # （ECHConfig 的 ``public_name``，见 ``config.ECH_PUBLIC_NAMES``）。
    # 只有该字段为真才允许在日志 / 统计摘要里出现 ``ECH`` 标记：
    # 真 ECH 的外层 SNI 必然是掩护域名，而 GREASE ECH 的外层 SNI 是真实域名，
    # 故「扩展存在 ∧ SNI 是掩护域名」是单连接上唯一可用的区分依据。
    # 语义边界：即便确证客户端发起了真 ECH，服务端是否接受在明文里仍不可判定
    # （accept_confirmation 埋在 ServerHello.random[24..32]，推导依赖不可见的
    # ClientHelloInner.random），因此不得表述为「服务端已接受」。
    ech: bool = False
    # **原始观测**：外层 ClientHelloOuter 明文携带 ``0xFE0D``
    # encrypted_client_hello 扩展，**可能是 GREASE ECH**。
    # RFC 9849 §6.2 规定没有可用 ECHConfig 的客户端 SHOULD 发送一个假的
    # encrypted_client_hello 扩展（随机 payload 伪装成 L+C），§10.10.4 又明确
    # 真 ECH 与 GREASE ECH 对被动观察者设计上不可区分——因此本字段单独存在
    # 不构成「ECH 生效」，只用于底栏的疑似 GREASE 计数（``ech? X``）。
    ech_ext: bool = False

    @property
    def domain(self) -> str:
        """SNI 域名；未知时为 UNKNOWN（对外不存在 None）。"""
        return self.sni if self.sni else UNKNOWN

    @property
    def app(self) -> str:
        """应用层值（ALPN）。"""
        return self.alpn

    @property
    def transport_label(self) -> str:
        """传输层展示名（TCP / QUIC/v1 / QUIC/- / UDP …）。"""
        return transport_label(self.transport, self.quic_version)

    @property
    def security(self) -> str:
        """安全层展示名：``tls/cipher``；cipher 未知时只留 tls_version。"""
        if self.cipher == UNKNOWN:
            return self.tls_version
        return f"{self.tls_version}/{self.cipher}"

    @property
    def ech_mark(self) -> str:
        """ECH 标记：确证生效（``ech`` 为真）时为 ``"ECH"``，否则空串。"""
        return ECH_MARK if self.ech else ""

    @property
    def security_label(self) -> str:
        """安全层展示名（带可选的 `` ECH`` 后缀），统计键与日志用它。"""
        mark = self.ech_mark
        return f"{self.security} {mark}" if mark else self.security

    @property
    def key(self) -> tuple[str, str, str, str]:
        """统计键：(域名, 应用层, 传输层, 安全层)；provisional/source 不进键。

        安全层用 :attr:`security_label`，故带 `` ECH`` 后缀的行与非 ECH 行
        天然是不同键、独立统计。
        """
        return (self.domain, self.app, self.transport_label, self.security_label)

    @property
    def has_content(self) -> bool:
        """三层至少一层不是 UNKNOWN 时为真（决定是否值得上报）。"""
        return (
            self.alpn != UNKNOWN
            or self.transport_label != UNKNOWN
            or self.security != UNKNOWN
        )

    def caption(self) -> str:
        """统计摘要文案：``app · transport · security``（security 含 ECH 后缀）。"""
        return _caption(self.app, self.transport_label, self.security_label)


@dataclass(frozen=True)
class StackRow:
    """统计表中的一行：四元组键 + 聚合次数。"""

    domain: str
    app: str
    transport: str  # 已规格化的 transport_label
    security: str   # 可能是带 `` ECH`` 后缀的 security_label
    count: int

    @property
    def key(self) -> tuple[str, str, str, str]:
        """统计键，与 ProtocolStack.key 同构。"""
        return (self.domain, self.app, self.transport, self.security)

    @property
    def has_ech(self) -> bool:
        """该行是否带 ECH 标记（供统计表给 ECH 上色）。"""
        return self.security.endswith(f" {ECH_MARK}")

    def caption(self) -> str:
        """统计摘要文案，与同键 ProtocolStack 的 caption 完全一致。"""
        return _caption(self.app, self.transport, self.security)

    @classmethod
    def from_stack(cls, stack: ProtocolStack, count: int) -> "StackRow":
        """从协议栈快照构造统计行（count 为该键的累计次数）。"""
        return cls(
            domain=stack.domain,
            app=stack.app,
            transport=stack.transport_label,
            security=stack.security_label,
            count=count,
        )
