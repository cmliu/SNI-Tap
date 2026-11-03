# SNI-Tap · SNI 域名探测器

把本地指定端口的 **TCP + UDP** 流量转发到目标（默认 `cf.090227.xyz:443`），
同时在转发过程中嗅探 TLS/QUIC 握手，实时显示每次访问的
**应用层 / 传输层 / 安全层** 三层协议栈，并按四元组聚合统计。

[![build-release](https://github.com/cmliu/SNI-Tap/actions/workflows/build-release.yml/badge.svg)](https://github.com/cmliu/SNI-Tap/actions/workflows/build-release.yml)

**下载**（Windows 10 / 11 x64，单文件免安装，无需 Python）：
[最新正式版](https://github.com/cmliu/SNI-Tap/releases/latest/download/SNI-Tap.exe) ·
[滚动构建 nightly](https://github.com/cmliu/SNI-Tap/releases/tag/nightly) ·
[SHA256 校验文件](https://github.com/cmliu/SNI-Tap/releases/latest/download/SNI-Tap.exe.sha256)

## 功能

| 功能 | 说明 |
|---|---|
| TCP 转发 + TLS 双向嗅探 | 监听本地端口（默认 1234），逐连接转发；上行解析 ClientHello（SNI / 支持版本 / 套件 / ALPN），下行解析 ServerHello（协商值） |
| UDP 转发 + QUIC Initial 嗅探 | 按客户端地址建立上游 socket 映射；双向解密 QUIC Initial（RFC 9001），重组 CRYPTO 帧还原 TLS 握手，兼容 QUIC / HTTP3（h3） |
| 三层协议栈日志 | `HH:mm:ss  域名  应用层  传输层  安全层`，等宽字体，上限 5000 行自动滚动；仅有客户端方向时行尾加 `?`（provisional） |
| ECH 识别 | **确证**真 ECH 时，日志安全层后追加琥珀色 `ECH`、统计行紧跟安全层标注 `ECH`、状态栏 footer 追加 `· ech K`。判据 = ClientHello 携带 `encrypted_client_hello`（`0xFE0D`）**且** 外层 SNI 命中 ECH 掩护域名名单（`ECHConfig.public_name`，默认 `cloudflare-ech.com`，可用环境变量 `SNITAP_ECH_PUBLIC_NAMES` 覆盖）。只看「扩展存在」会把 GREASE ECH 误当成真 ECH，故仅扩展存在的行**不标记**，只在 footer 计入 `· ech? X`。不解析密文；QUIC / HTTP3 同样覆盖 |
| 四元组统计 | 统计键 = (域名, 应用层, 传输层, 安全层)，任一层不同即独立成行；安全层带 ` ECH` 后缀的行与非 ECH 行独立统计（后缀只加在确证行上，GREASE 行与普通行同键）；行内单行布局：域名 · 应用层 · 传输层 · 安全层 [· ECH] + 条形 + 次数，双击复制 TSV（可粘进 Excel） |
| tcping 实时延迟 | 每 3 秒对目标 TCP 端口做一次握手测速（2 秒超时），状态区大字号显示 |
| 零干扰 | 嗅探器是只读旁路、没有写路径；TCP 下行、UDP 均先转发后嗅探，解析成功/失败/放弃都不影响转发字节与时机 |
| 优雅降级 | `cryptography` 缺失时 QUIC 仍输出传输层值（如 `QUIC/v1`），其余为 `-`，不崩不噪音 |

## 快速开始

**运行时依赖**：仅 `cryptography`（QUIC 解密用，缺失自动降级）：

```powershell
pip install -r requirements.txt
```

GUI 用 Python 标准库 `tkinter`，TCP 嗅探为纯字节解析，网络部分只用
`asyncio` / `socket`。

环境要求：Python 3.10+（实测 3.13），且**该 CPython 必须自带 tkinter**。
Windows 官方安装包默认包含；精简版 / 嵌入式发行版常常没有。

> ⚠️ WorkBuddy 内置解释器未编译 tkinter，**不能**用来运行 GUI 或打包。
> 请使用系统安装的 CPython，例如
> `C:\Users\<user>\AppData\Local\Programs\Python\Python313\python.exe`。

```powershell
python main.py
```

或以模块方式运行：

```powershell
$env:PYTHONPATH = "src"
python -m snitap
```

## 使用说明

1. **本地监听端口**：默认 `1234`
2. **转发目标域名 / IP**：默认 `cf.090227.xyz`
3. **目标端口**：默认 `443`
4. 点击「转发监听」开始 —— 按钮变为「■ 停止」，状态灯变绿，输入框锁定；再次点击停止全部工作

把本地应用的访问目标指向 `127.0.0.1:1234` 即可（浏览器代理、`curl --connect-to`、hosts 改写等）。

> 监听地址固定为 `127.0.0.1`，仅本机可用、不暴露到局域网。如需变更，改 `src/snitap/config.py` 的 `LISTEN_HOST`。

## 日志样例

```
14:32:05  api.cloudflare.com  h2  TCP  TLS1.3/A128GCM
14:32:05  api.cloudflare.com  h2  TCP  TLS1.3/A128GCM?
15:04:11  www.example.org  h3  QUIC/v1  TLS1.3/A128GCM
15:04:12  -  -  QUIC/0xff00001d  -
14:33:20  cloudflare-ech.com  h2  TCP  TLS1.3/A128GCM  ECH
14:33:21  cloudflare-ech.com  h2  TCP  TLS1.3/A128GCM  ECH?
14:33:40  test.cmliussss.dpdns.org  h2  TCP  TLS1.3/A128GCM
```

行尾 `?` 表示只观测到客户端方向（客户端偏好而非服务端协商值）。

安全层后的 `ECH` 表示**确证本次握手是真正的 ECH**：外层 SNI 是 ECH 掩护域名
（`ECHConfig` 的 `public_name`，Cloudflare 为 `cloudflare-ech.com`），且
ClientHello 明文携带了 `encrypted_client_hello` 扩展（`0xFE0D`）。

它**不**表示服务端已经接受 ECH：接受确认写在 `ServerHello.random[24..32]`，
其推导依赖不可见的 `ClientHelloInner.random`，被动嗅探无法判定（详见「已知限制」）。

只为「扩展存在」不够：没有可用 ECHConfig 的客户端会按 RFC 9849 §6.2 发送**假的**
ECH 扩展（GREASE ECH），两种情况的密文对旁观者不可区分（§10.10.4）。因此
`test.cmliussss.dpdns.org` 这类「已关闭 ECH 却仍带扩展」的连接按 GREASE 处理，
**不出 `ECH` 标记**，只计入底栏的疑似计数：

```
total 128 · 6 组 · ech 9 · ech? 4
```

`ech 9` = 确证真 ECH 9 次；`ech? 4` = 携带 ECH 扩展但外层 SNI 不是掩护域名
（疑似 GREASE）4 次。掩护域名名单默认 `cloudflare-ech.com`，可用环境变量
`SNITAP_ECH_PUBLIC_NAMES`（逗号分隔，大小写不敏感）覆盖，设为空串即关闭标记。

## 界面布局

```
┌ 配置行：listen [1234] → [cf.090227.xyz 或 host:port]                    [▶ 转发监听 / ■ 停止]
├ 状态行：● 监听中   ping 23.4ms │ peer 104.16.x.x:443                     提示信息
├ 主区（上下分栏，可拖动，初始约 40:60）
│   ├ 中：协议栈统计 · 本次启动（行内单行：域名 · 应用层 · 传输层 · 安全层 [· ECH]
│   │      + 条形 + 次数，按次数降序，双击复制 TSV）
│   └ 下：stack log（等宽字体，时间戳/传输层弱化 / 域名青色 / 应用层灰 / 安全层绿 /
│          ECH 琥珀，5000 行上限，自动滚动，[清除]）
└ 状态栏：tcp N │ udp N │ sni N                              Ctrl + L 清屏 · Enter 启停
```

配色跟随系统亮暗（每 2 秒轮询一次注册表），暗色为终端风，亮色为日间版。

统计面板底部 footer 显示累计摘要：`total 总条数 · M 组`，确证 ECH 时追加
`· ech K`，存在「携带 ECH 扩展但 SNI 非掩护域名」（疑似 GREASE）时再追加
`· ech? X`，统计行被截断时最后追加 `· 仅显示前 300 组`。

## 测试

```powershell
python -m unittest discover -s tests -v
```

- `tests/test_protocol.py` —— 命名映射单射性、GREASE 判定、统计键与快照契约、ECH 标记（`security_label` / 键分离 / `has_ech`）
- `tests/test_tls_sniffer.py` —— TLS 双向 hello 解析：分段重组 / GREASE 过滤 / supported_versions 优先级 / ALPN 首偏好 / 扩展区截断 / ECH 扩展只判存在
- `tests/test_quic_sniffer.py` —— QUIC Initial：独立 RFC 9001 加密夹具端到端、v2 salt/label、CRYPTO 分包重组、版本协商包、InvalidTag 降级
- `tests/test_flow.py` —— TcpFlow / QuicFlow 聚合、provisional 语义、ECH 双字段语义（掩护域名 → 确证；真实域名 → GREASE 不标记）、幂等性、零上报
- `tests/test_stats.py` —— 四元组累计与排序稳定性、`ech_hits` / `ech_ext_hits` 双计数、ECH 行独立成行、`StatsEvent` 字段追加的向后兼容性
- `tests/test_ech_public_name.py` —— ECH 掩护域名判定（精确匹配 / 大小写 / 空白 / 非法输入 / 相似域名 / `SNITAP_ECH_PUBLIC_NAMES` 覆盖 / 名单为空）与端到端验收场景
- `tests/test_ech_integration.py` —— ECH 扩展的异常面（只允许 `_ParseError`）、流式分段、QUIC 复用、统计分键
- `tests/test_gui_ech.py` —— 无头 GUI 断言：日志 `ech` tag 区间、统计表标记去重、footer `ech` / `ech?` 顺序
- `tests/test_ech_audit.py` —— QA 独立复核：环境变量真 reload 覆盖、判定边界矩阵、位置参数兼容、footer 四组合、原始字节端到端、文档前缀逐字节校验
- `tests/ech_env_isolation.py` —— 测试支撑（非用例）：把 `snitap.config` 隔离到默认名单基线，避免开发机导出 `SNITAP_ECH_PUBLIC_NAMES` 时假红
- `tests/test_forwarders.py` —— TCP / UDP 转发集成测试：本地 echo 服务作目标，验证字节零干扰、三层栈上报、连接计数；停止 teardown 限时回归（活跃 / 停滞连接下 stop 秒级完成且端口可重绑，防 Python 3.12+ `Server.wait_closed()` 死锁导致 GUI 停止即卡死）
- `tests/test_parse_target.py` —— 目标输入解析

> 若你在 shell 里导出了 `SNITAP_ECH_PUBLIC_NAMES`（README 教的做法），
> 断言默认名单的用例会自动隔离到默认基线再跑，无需临时 unset 即可全绿。

## 打包为单文件 exe

打包是**唯一**需要额外安装工具的环节：

```powershell
pip install pyinstaller
pyinstaller snitap.spec
```

产物：`dist/SNI-Tap.exe`（无控制台窗口），预期约 **14~16 MB**。
体积主要来自 Tcl/Tk 运行时、CPython 解释器与 cryptography/OpenSSL
（QUIC Initial 解密依赖，`snitap.spec` 已解除 `ssl/_ssl/_hashlib` 排除，
并在 `hiddenimports` 显式声明 cryptography 的懒加载子模块）。

## 自动构建与发布（GitHub Actions）

`.github/workflows/build-release.yml` 在推送时自动跑单元测试 → PyInstaller 打包 → 发布 exe：

| 触发 | 发布到 | 下载地址 |
|---|---|---|
| push `main`（跳过纯文档变更）、手动 Run workflow | 滚动预发布，固定 tag `nightly`，每次覆盖资产 | `releases/download/nightly/SNI-Tap.exe` |
| push tag `v*` | 正式 Release，用该 tag，标记 latest | `releases/download/<tag>/SNI-Tap.exe` |

资产名固定为 `SNI-Tap.exe`（无版本后缀，链接长期有效）与 `SNI-Tap.exe.sha256`
（PowerShell 用 `Get-FileHash -Algorithm SHA256`，Git Bash 用 `sha256sum -c`）。Release 正文含版本号、
提交号、构建时间与 Python / PyInstaller 版本；单元测试不通过则不打包、不发布。

> 前置条件：仓库**不要**启用 Release immutability，也**不要**给 `refs/tags/nightly` 配 tag
> 保护规则——nightly 通道依赖「移动同名 tag + 覆盖同名资产」，两者都会让 nightly 必然失败。

## 目录结构

```
SNI-Tap/
├── main.py                     # 便捷入口：python main.py
├── requirements.txt            # cryptography>=44.0（QUIC 解密；缺失自动降级）
├── snitap.spec                 # PyInstaller 打包配置
├── tests/
│   ├── test_protocol.py
│   ├── test_tls_sniffer.py
│   ├── test_quic_sniffer.py
│   ├── test_flow.py
│   ├── test_stats.py
│   ├── test_ech_public_name.py
│   ├── test_ech_integration.py
│   ├── test_ech_audit.py
│   ├── test_gui_ech.py
│   ├── ech_env_isolation.py
│   ├── test_forwarders.py
│   └── test_parse_target.py
└── src/snitap/
    ├── __main__.py             # python -m snitap 入口
    ├── config.py               # AppConfig、监听地址、默认值、ECH 掩护域名名单
    ├── protocol.py             # 共享契约：UNKNOWN、名称映射、ProtocolStack、StackRow
    ├── tls_sniffer.py          # TLS 双向 hello 嗅探（纯函数 + 流式外壳）
    ├── quic_crypto.py          # QUIC Initial 密钥派生与解密（唯一 import cryptography）
    ├── quic_sniffer.py         # QUIC 长包头 → Initial 解密 → CRYPTO 重组
    ├── flow.py                 # TcpFlow / QuicFlow 聚合器（每连接至多一条事件）
    ├── events.py               # 跨线程事件契约（不可变 dataclass）
    ├── tcp_forwarder.py        # TCP 转发引擎（双向嗅探旁路注入）
    ├── udp_forwarder.py        # UDP 转发引擎（地址映射 + 回程路由 + 先转发后嗅探）
    ├── tcping.py               # 周期性握手测速
    ├── stats.py                # 四元组计数器与统计快照
    ├── worker.py               # asyncio 事件循环宿主线程
    └── gui/
        ├── main_window.py      # 主窗口（配置区/状态区/主区/状态栏）
        ├── log_panel.py        # 协议栈日志面板（LogEntry + 5 条批量 tag_add）
        ├── stats_table.py      # 协议栈统计表（Canvas 自绘单行式布局）
        ├── theme.py            # 暗/亮两套配色令牌 + 系统亮暗探测
        └── widgets.py          # 共用件：DPI 缩放、极细滚动条、输入框工厂
```

## 实现要点

**三层模型**：应用层 = ALPN；传输层 = TCP / QUIC/v1 / QUIC/- / UDP；安全层 = `TLS版本/套件`。
每条连接 / 会话只发**一条**事件：拿到 ServerHello（或服务端 Initial）取协商值，
否则退回客户端偏好并标记 `provisional`（日志行尾 `?`）。

**QUIC Initial 解密**（仅 Initial、双向）：从客户端首个 Initial 的 DCID 按
RFC 9001 派生双向密钥，header protection 按 FIX 正确处理（PN 长度在还原后
first byte 的低 2 位，AAD 用未受保护头部），CRYPTO 帧乱序重组后委托与 TCP
侧共享的 hello 纯函数解析。Handshake / 1-RTT 全加密，不碰。

**ECH 判定依据**（两级，只有第二级才允许出 `ECH` 标记）：

1. `ProtocolStack.ech_ext`（**原始观测**）= 外层 `ClientHelloOuter` 明文扩展区携带
   `encrypted_client_hello`（扩展类型 `0xFE0D`，RFC 9849）。嗅探器**只判该扩展是否
   存在**，把结果记成 `HelloInfo.ech`（布尔），并**完全不解析扩展体**——扩展体是
   HPKE 密文，GREASE ECH 场景下更是客户端随机填充的假密文，一旦尝试解析就会把随机
   字节带进异常分支、冒犯「嗅探绝不影响转发」的红线。
2. `ProtocolStack.ech`（**确证生效**）= `ech_ext` **且** 外层 SNI 命中 ECH 掩护域名
   （`config.ECH_PUBLIC_NAMES`，默认 `cloudflare-ech.com`；可用 `SNITAP_ECH_PUBLIC_NAMES`
   覆盖；`is_ech_public_name` 精确匹配、对任意输入返回 bool 且不抛异常）。真 ECH 的
   外层 SNI 必然是该 ECHConfig 的 `public_name`，而 GREASE ECH 的外层 SNI 是用户正在
   访问的真实域名——这是单连接上唯一可用的现实判据，因为 RFC 9849 §10.10.4 明确真 ECH
   与 GREASE ECH 对被动观察者不可区分。

该判定经 `flow._merge()` 只取客户端方向（服务端仅在 HelloRetryRequest 这类罕见场景会
明文回带同号扩展，不参与判定），最终 `ech` 落到 `security_label`（安全层追加 ` ECH`）
→ 统计键第 4 元素、日志 `ECH` 段与 footer 的 `ech K` 计数；`ech_ext_hits - ech_hits`
的差值以 `ech?` 计入 footer（疑似 GREASE）。QUIC / HTTP3 走同一对 hello 纯函数，自动覆盖。

**线程模型**：Tk 主线程只做界面；asyncio 事件循环跑在独立 worker 线程。
worker → GUI 走 `queue.Queue`（GUI 每 100 ms 批量拉取，StackEvent 逐条、
StatsEvent 每秒快照）；GUI → worker 走 `loop.call_soon_threadsafe`。
统计只在 worker 线程修改，GUI 只读快照。

## 已知限制

- 每条连接只嗅探首个握手；连接复用、TLS 1.3 会话恢复不会重复记录
- **`ECH` = 确证客户端发起了真 ECH，仍不能判定服务端是否接受**：判据是「扩展存在
  ∧ 外层 SNI 是掩护域名」。外层 `ClientHelloOuter` 的 SNI 是 ECHConfig 里的
  `public_name` 掩护域名，而不是被加密的 inner 域名（inner 无密钥不可恢复）；
  服务端的接受确认写在 `ServerHello.random[24..32]`，其推导依赖不可见的
  `ClientHelloInner.random`，被动嗅探没有这个输入，明文唯一例外是 HelloRetryRequest
  携带该扩展（罕见）。因此界面上的 `ECH` 一律表示「确证本次握手是真 ECH」，
  不表示「服务端已接受」
- **GREASE ECH 不会被标记，但判据是近似而非精确**：① 掩护域名名单是封闭枚举，
  其他厂商的 `public_name` 未通过 `SNITAP_ECH_PUBLIC_NAMES` 增补时，其真 ECH 会被归入
  `ech?`（疑似 GREASE）而不标记——宁可少标也不错标；② 用户直接访问掩护域名本身的
  普通握手理论上也会被标记。名单为空（`SNITAP_ECH_PUBLIC_NAMES=""`）等于关闭标记
- QUIC 只解 Initial 包（密钥轮换后不可用）；Handshake / 1-RTT 不处理
- QUIC 服务端 Initial 与客户端 Initial 不在同一 UDP 会话窗口内时拿不到协商值（退化为 provisional）
- 非 TLS 明文流量不做 Host 嗅探，原样透传（零上报）
- UDP 目标 IP 在启动时解析一次；目标域名换 IP 后需重新启动监听
- 应用层信息仅来自 ALPN；HTTP/2 HPACK 不可旁路解，明文 HTTP 不嗅探
