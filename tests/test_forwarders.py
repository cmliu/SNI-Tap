"""TCP / UDP 转发引擎集成测试。

做法：本地起 echo 服务当"目标"，转发引擎指过去；验证
1) 字节完整往返（嗅探不干扰转发）；
2) 真实 ClientHello 能上报完整三层协议栈（provisional 语义）；
3) 非 TLS 流量零上报；
4) UDP 数据报往返。
"""

from __future__ import annotations

import asyncio
import contextlib
import pathlib
import queue
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from snitap.config import AppConfig
from snitap.protocol import ProtocolStack
from snitap.tcp_forwarder import TcpForwarder
from snitap.udp_forwarder import UdpForwarder
from snitap.worker import Worker
from test_tls_sniffer import build_client_hello


class TcpForwarderTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()

        self.echo_server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.echo_port = self.echo_server.sockets[0].getsockname()[1]

        self.stacks: list[ProtocolStack] = []
        self.errors: list[str] = []
        self.conn_counts: list[int] = []
        self.forwarder = TcpForwarder(
            AppConfig(listen_port=0, target_host="127.0.0.1", target_port=self.echo_port),
            on_stack=self.stacks.append,
            on_conn_change=self.conn_counts.append,
            on_error=self.errors.append,
        )
        await self.forwarder.start()
        self.port = self.forwarder.port

    async def asyncTearDown(self) -> None:
        await self.forwarder.stop()
        self.echo_server.close()
        await self.echo_server.wait_closed()

    async def test_client_hello_passes_through_and_stack_reported(self) -> None:
        payload = build_client_hello("cf.090227.xyz")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(payload)
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=3.0)
            self.assertEqual(echoed, payload)  # 零干扰：字节完全一致
            await asyncio.sleep(0.2)
            self.assertEqual(len(self.stacks), 1)
            stack = self.stacks[0]
            self.assertEqual(stack.sni, "cf.090227.xyz")
            self.assertTrue(stack.provisional)  # echo 回的是 ClientHello，服务端解不出 ServerHello
            self.assertEqual(stack.transport, "TCP")
            self.assertEqual(stack.app, "-")
            self.assertEqual(stack.security, "TLS1.3/A128GCM")
            self.assertEqual(self.errors, [])
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_non_tls_bytes_forwarded_without_report(self) -> None:
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(data)
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(len(data)), timeout=3.0)
            self.assertEqual(echoed, data)
            await asyncio.sleep(0.15)
            self.assertEqual(self.stacks, [])
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_connection_count_tracks_lifecycle(self) -> None:
        _reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        await asyncio.sleep(0.15)
        self.assertEqual(self.conn_counts[-1], 1)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)
        self.assertEqual(self.conn_counts[-1], 0)


class UdpForwarderTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        class EchoProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport) -> None:  # noqa: ANN001
                self.transport = transport

            def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
                self.transport.sendto(b"echo:" + data, addr)

        loop = asyncio.get_running_loop()
        self.echo_transport, _ = await loop.create_datagram_endpoint(
            EchoProtocol, local_addr=("127.0.0.1", 0)
        )
        self.echo_port = self.echo_transport.get_extra_info("sockname")[1]

        self.stacks: list[ProtocolStack] = []
        self.errors: list[str] = []
        self.session_counts: list[int] = []
        self.forwarder = UdpForwarder(
            AppConfig(listen_port=0, target_host="127.0.0.1", target_port=self.echo_port),
            on_stack=self.stacks.append,
            on_session_change=self.session_counts.append,
            on_error=self.errors.append,
        )
        await self.forwarder.start()
        self.port = self.forwarder.local_port

    async def asyncTearDown(self) -> None:
        await self.forwarder.stop()
        self.echo_transport.close()

    async def test_datagram_roundtrip(self) -> None:
        loop = asyncio.get_running_loop()

        class ClientProtocol(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.future: asyncio.Future[bytes] = loop.create_future()

            def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
                if not self.future.done():
                    self.future.set_result(data)

        transport, protocol = await loop.create_datagram_endpoint(
            ClientProtocol, local_addr=("127.0.0.1", 0)
        )
        try:
            transport.sendto(b"hello-quic", ("127.0.0.1", self.port))
            data = await asyncio.wait_for(protocol.future, timeout=3.0)
            self.assertEqual(data, b"echo:hello-quic")
            self.assertGreaterEqual(max(self.session_counts, default=0), 1)
            self.assertEqual(self.errors, [])
            # 非 QUIC 的 UDP 会话在嗅探窗口闭合前不会上报
            await asyncio.sleep(0.2)
            self.assertEqual(self.stacks, [])
        finally:
            transport.close()


class TcpForwarderStopTest(unittest.IsolatedAsyncioTestCase):
    """回归：有活跃连接时 stop() 必须限时完成并释放监听端口。

    背景：Python 3.12+ 的 ``Server.wait_closed()`` 会等待全部 handler 退出，
    旧实现「先 wait 后 cancel」与尚在的 handler 互相等待——GUI 停止即冻结
    6 秒、监听 socket 不释放、重启必报端口占用（WinError 10048）。
    """

    async def asyncSetUp(self) -> None:
        self.release = asyncio.Event()
        self.accepted: list[asyncio.StreamWriter] = []
        self.spam_sockets: list[socket.socket] = []

        async def blackhole(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            """目标端：接受后永不读不写（模拟停滞对端）。"""
            self.accepted.append(writer)
            with contextlib.suppress(asyncio.CancelledError):
                await self.release.wait()

        self.target_server = await asyncio.start_server(blackhole, "127.0.0.1", 0)
        target_port = self.target_server.sockets[0].getsockname()[1]
        self.forwarder = TcpForwarder(
            AppConfig(listen_port=0, target_host="127.0.0.1", target_port=target_port),
            on_stack=lambda stack: None,
            on_conn_change=lambda n: None,
            on_error=lambda m: None,
        )
        await self.forwarder.start()
        self.port = self.forwarder.port

    async def asyncTearDown(self) -> None:
        self.release.set()  # 放行黑洞 handler，让靶机侧 socket 正常关闭
        await self.forwarder.stop()  # 幂等：测试内已 stop 则立即返回
        for s in self.spam_sockets:
            with contextlib.suppress(OSError):
                s.close()
        for writer in self.accepted:
            writer.close()
        self.target_server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.target_server.wait_closed(), timeout=2.0)

    async def _assert_port_reusable(self) -> None:
        """监听端口必须已释放：同端口重新绑定成功。"""
        rebind = await asyncio.start_server(
            lambda r, w: None, "127.0.0.1", self.port, reuse_address=True
        )
        rebind.close()
        await rebind.wait_closed()

    async def test_stop_with_live_connections_is_fast_and_frees_port(self) -> None:
        conns = [await asyncio.open_connection("127.0.0.1", self.port) for _ in range(5)]
        try:
            await asyncio.sleep(0.2)  # 让全部 handler 挂起在 read 上
            t0 = time.perf_counter()
            await self.forwarder.stop()
            elapsed = time.perf_counter() - t0
            self.assertLess(elapsed, 1.5)
        finally:
            for _, w in conns:
                w.close()
        await self._assert_port_reusable()

    async def test_stop_with_stalled_flush_is_bounded(self) -> None:
        def spam() -> None:
            s: socket.socket | None = None
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=3)
                payload = b"x" * 65536
                for _ in range(512):  # 32MB：塞满沿途缓冲，pump 停在 drain()
                    s.send(payload)
            except OSError:
                pass
            finally:
                if s is not None:
                    self.spam_sockets.append(s)  # 保持停滞状态直到 tearDown

        threading.Thread(target=spam, daemon=True).start()
        await asyncio.sleep(1.5)
        t0 = time.perf_counter()
        await self.forwarder.stop()  # 旧实现在此永久挂起
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 3.0)
        await self._assert_port_reusable()


class WorkerStopTest(unittest.TestCase):
    """回归：worker 有活跃连接时 stop() 不得长时间阻塞调用线程。

    GUI 的停止按钮在 Tk 主线程调用 ``worker.stop()``：旧实现因 teardown
    死锁会阻塞 6 秒以上（future.result(3) + join(3) 双双超时），窗口即
    「未响应」。修复后必须远小于 1.5 秒。
    """

    def test_stop_with_active_connection_returns_quickly(self) -> None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        target_port = srv.getsockname()[1]
        accepted: list[socket.socket] = []
        accept_run = threading.Event()

        def accept_loop() -> None:
            srv.settimeout(0.2)
            while accept_run.is_set():
                try:
                    accepted.append(srv.accept()[0])
                except OSError:
                    pass

        threading.Thread(target=accept_loop, daemon=True).start()

        probe = socket.socket()  # 预占一个空闲监听端口
        probe.bind(("127.0.0.1", 0))
        listen_port = probe.getsockname()[1]
        probe.close()

        worker = Worker()
        worker.start(AppConfig(listen_port=listen_port, target_host="127.0.0.1", target_port=target_port))
        client: socket.socket | None = None
        try:
            deadline = time.time() + 5.0
            running = False
            while time.time() < deadline:
                try:
                    event = worker.events.get(timeout=0.2)
                except queue.Empty:
                    continue
                if type(event).__name__ == "StateEvent" and event.state == "running":
                    running = True
                    break
            self.assertTrue(running, "worker 未在 5 秒内进入 running")

            client = socket.create_connection(("127.0.0.1", listen_port), timeout=3)
            time.sleep(0.3)  # 建立一条活跃的转发连接

            t0 = time.perf_counter()
            worker.stop(timeout=3.0)
            elapsed = time.perf_counter() - t0
            self.assertLess(elapsed, 1.5)
        finally:
            if client is not None:
                client.close()
            accept_run.set()
            worker.stop(timeout=1.0)  # 幂等兜底
            for conn in accepted:
                with contextlib.suppress(OSError):
                    conn.close()
            srv.close()


if __name__ == "__main__":
    unittest.main()
