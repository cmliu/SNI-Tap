# SNI-Tap · SNI 域名探测器

把本地指定端口的 **TCP + UDP** 流量转发到目标（默认 `cf.090227.xyz:443`），
同时在转发过程中嗅探 TLS ClientHello 里的 **SNI 域名**，实时显示访问记录与累计次数。

## 功能

| 功能 | 说明 |
|---|---|
| TCP 转发 + SNI 嗅探 | 监听本地端口（默认 1234），逐连接转发到目标，旁路解析前向流量中的 TLS ClientHello |
| UDP 透明转发 | 按客户端地址建立上游 socket 映射，兼容 QUIC / HTTP3（h3），v1 仅转发不嗅探 |
| tcping 实时延迟 | 每 3 秒对目标 TCP 端口做一次握手测速（2 秒超时），状态区大字号显示 |
| 嗅探日志 | `HH:mm:ss  域名` 格式，等宽字体，上限 5000 行自动滚动 |
| 域名统计 | 本次启动以来所有域名及累计次数，按次数降序，双击复制 |
| 零干扰 | 嗅探器是只读旁路、没有写路径；解析成功/失败/放弃都不影响转发字节与时机 |

## 快速开始

环境要求：Python 3.10+（实测 3.13），Windows / macOS / Linux。

```powershell
pip install -r requirements.txt
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

## 界面布局

```
┌ 配置区：本地监听端口 [1234]  转发目标域名/IP [cf.090227.xyz]  目标端口 [443]  [转发监听/■ 停止]
├ 状态区：● 监听中   23.4 ms  → 104.16.x.x:443            提示信息  [清除日志]
├ 主区（上下分割，可拖动）
│   ├ 上：域名统计 · 本次启动（域名 / 次数，按次数降序，双击复制）
│   └ 下：SNI 嗅探日志（等宽字体，5000 行上限，自动滚动）
└ 状态栏：TCP 连接 N   UDP 映射 N   嗅探总数 N                     目标 host:port
```

## 测试

```powershell
python -m unittest discover -s tests -v
```

- `tests/test_sni_sniffer.py` —— ClientHello 解析：整包 / 逐字节 / 跨段 / 非 TLS / 无 SNI 扩展 / 超限等
- `tests/test_forwarders.py` —— TCP、UDP 转发集成测试：本地 echo 服务作目标，验证字节零干扰、SNI 上报、连接计数

## 打包为单文件 exe

```powershell
pip install pyinstaller
pyinstaller snitap.spec
```

产物：`dist/SNI-Tap.exe`（无控制台窗口）。

## 目录结构

```
SNI-Tap/
├── main.py                     # 便捷入口：python main.py
├── requirements.txt
├── snitap.spec                 # PyInstaller 打包配置
├── docs/ARCHITECTURE.md        # 架构设计文档（含决策记录）
├── tests/
│   ├── test_sni_sniffer.py
│   └── test_forwarders.py
└── src/snitap/
    ├── __main__.py             # python -m snitap 入口
    ├── config.py               # AppConfig、监听地址、默认值
    ├── events.py               # 跨线程事件契约（不可变 dataclass）
    ├── sni_sniffer.py          # TLS ClientHello 流式 SNI 解析状态机
    ├── tcp_forwarder.py        # TCP 转发引擎（嗅探旁路注入）
    ├── udp_forwarder.py        # UDP 转发引擎（地址映射 + 回程路由）
    ├── tcping.py               # 周期性握手测速
    ├── stats.py                # 域名计数器与统计快照
    ├── worker.py               # asyncio 事件循环宿主线程
    └── gui/
        ├── main_window.py      # 主窗口（配置区/状态区/主区/状态栏）
        ├── log_panel.py        # SNI 嗅探日志面板
        └── stats_table.py      # 域名统计表
```

## 实现要点

**嗅探状态机**：`TLS record(5B 头, type=0x16)` → `handshake(4B 头, type=0x01)` → ClientHello 主体 → 遍历 extensions 命中 `0x0000` 取 `server_name`。
支持 ClientHello 跨 TCP 分段重组；缓冲上限 20 KB；首字节非 0x16、长度矛盾、跨 record 分片等情况立即放弃并转入纯转发。

**为什么 v1 不嗅探 UDP**：QUIC 的 SNI 在 Initial 包的加密载荷里，需要从 DCID 派生初始密钥（HKDF）并处理 header protection 才能解密，实现量是 TCP 侧的 5~10 倍。v1 的 UDP 只做透明转发保证 h3 不断流，接口已预留为 v2 可插拔钩子。

**线程模型**：Qt 主线程只做界面；asyncio 事件循环跑在独立 worker 线程。
worker → GUI 走 `queue.Queue`（GUI 每 100 ms 批量拉取，SniEvent 逐条、StatsEvent 每秒快照）；
GUI → worker 走 `loop.call_soon_threadsafe`。统计只在 worker 线程修改，GUI 只读快照。

## 已知限制

- 每条 TCP 连接只嗅探首个 ClientHello；连接复用、TLS 1.3 会话恢复不会重复记录
- 启用 ECH（Encrypted Client Hello）的流量无法嗅探 SNI
- ClientHello 被拆到多个 TLS record 的少见情况下放弃嗅探（继续纯转发）
- 非 TLS 明文流量不做 Host 嗅探，原样透传
- UDP 目标 IP 在启动时解析一次；目标域名换 IP 后需重新启动监听
