# SNI-Tap · SNI 域名探测器

把本地指定端口的 **TCP + UDP** 流量转发到目标（默认 `cf.090227.xyz:443`），
同时在转发过程中嗅探 TLS/QUIC 握手，实时显示每次访问的
**应用层 / 传输层 / 安全层** 三层协议栈，并按四元组聚合统计。

## 功能

| 功能 | 说明 |
|---|---|
| TCP 转发 + TLS 双向嗅探 | 监听本地端口（默认 1234），逐连接转发；上行解析 ClientHello（SNI / 支持版本 / 套件 / ALPN），下行解析 ServerHello（协商值） |
| UDP 转发 + QUIC Initial 嗅探 | 按客户端地址建立上游 socket 映射；双向解密 QUIC Initial（RFC 9001），重组 CRYPTO 帧还原 TLS 握手，兼容 QUIC / HTTP3（h3） |
| 三层协议栈日志 | `HH:mm:ss  域名  应用层  传输层  安全层`，等宽字体，上限 5000 行自动滚动；仅有客户端方向时行尾加 `?`（provisional） |
| 四元组统计 | 统计键 = (域名, 应用层, 传输层, 安全层)，任一层不同即独立成行；行内两行布局：域名/条形/次数 + 全宽摘要，双击复制 TSV（可粘进 Excel） |
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
```

行尾 `?` 表示只观测到客户端方向（客户端偏好而非服务端协商值）。

## 界面布局

```
┌ 配置行：listen [1234] → [cf.090227.xyz 或 host:port]                    [▶ 转发监听 / ■ 停止]
├ 状态行：● 监听中   ping 23.4ms │ peer 104.16.x.x:443                     提示信息
├ 主区（上下分栏，可拖动，初始约 40:60）
│   ├ 中：协议栈统计 · 本次启动（行内两行：域名 / 条形 / 次数 + 全宽摘要，
│   │      按次数降序，双击复制 TSV）
│   └ 下：stack log（等宽字体，时间戳/传输层弱化 / 域名青色 / 应用层灰 / 安全层绿，
│          5000 行上限，自动滚动，[清除]）
└ 状态栏：tcp N │ udp N │ sni N                              Ctrl + L 清屏 · Enter 启停
```

配色跟随系统亮暗（每 2 秒轮询一次注册表），暗色为终端风，亮色为日间版。

## 测试

```powershell
python -m unittest discover -s tests -v
```

- `tests/test_protocol.py` —— 命名映射单射性、GREASE 判定、统计键与快照契约
- `tests/test_tls_sniffer.py` —— TLS 双向 hello 解析：分段重组 / GREASE 过滤 / supported_versions 优先级 / ALPN 首偏好 / 扩展区截断等
- `tests/test_quic_sniffer.py` —— QUIC Initial：独立 RFC 9001 加密夹具端到端、v2 salt/label、CRYPTO 分包重组、版本协商包、InvalidTag 降级
- `tests/test_flow.py` —— TcpFlow / QuicFlow 聚合、provisional 语义、幂等性、零上报
- `tests/test_forwarders.py` —— TCP / UDP 转发集成测试：本地 echo 服务作目标，验证字节零干扰、三层栈上报、连接计数
- `tests/test_parse_target.py` —— 目标输入解析

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
├── docs/ARCHITECTURE.md        # 架构设计文档（含决策记录）
├── tests/
│   ├── test_protocol.py
│   ├── test_tls_sniffer.py
│   ├── test_quic_sniffer.py
│   ├── test_flow.py
│   ├── test_forwarders.py
│   └── test_parse_target.py
└── src/snitap/
    ├── __main__.py             # python -m snitap 入口
    ├── config.py               # AppConfig、监听地址、默认值
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
        ├── log_panel.py        # 协议栈日志面板（LogEntry + 4 条批量 tag_add）
        ├── stats_table.py      # 协议栈统计表（Canvas 自绘两行式布局）
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

**线程模型**：Tk 主线程只做界面；asyncio 事件循环跑在独立 worker 线程。
worker → GUI 走 `queue.Queue`（GUI 每 100 ms 批量拉取，StackEvent 逐条、
StatsEvent 每秒快照）；GUI → worker 走 `loop.call_soon_threadsafe`。
统计只在 worker 线程修改，GUI 只读快照。

## 已知限制

- 每条连接只嗅探首个握手；连接复用、TLS 1.3 会话恢复不会重复记录
- 启用 ECH（Encrypted Client Hello）的流量无法嗅探 SNI
- QUIC 只解 Initial 包（密钥轮换后不可用）；Handshake / 1-RTT 不处理
- QUIC 服务端 Initial 与客户端 Initial 不在同一 UDP 会话窗口内时拿不到协商值（退化为 provisional）
- 非 TLS 明文流量不做 Host 嗅探，原样透传（零上报）
- UDP 目标 IP 在启动时解析一次；目标域名换 IP 后需重新启动监听
- 应用层信息仅来自 ALPN；HTTP/2 HPACK 不可旁路解，明文 HTTP 不嗅探
