"""TCP / UDP 转发引擎集成测试。

做法：本地起 echo 服务当"目标"，转发引擎指过去；验证
1) 字节完整往返（嗅探不干扰转发）；
2) 真实 ClientHello 能上报 SNI；
3) 非 TLS 流量不误报；
4) UDP 数据报往返。
"""

from __future__ import annotations

import asyncio
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from snitap.config import AppConfig
from snitap.tcp_forwarder import TcpForwarder
from snitap.udp_forwarder import UdpForwarder
from test_sni_sniffer import build_client_hello


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

        self.snis: list[str] = []
        self.errors: list[str] = []
        self.conn_counts: list[int] = []
        self.forwarder = TcpForwarder(
            AppConfig(listen_port=0, target_host="127.0.0.1", target_port=self.echo_port),
            on_sni=self.snis.append,
            on_conn_change=self.conn_counts.append,
            on_error=self.errors.append,
        )
        await self.forwarder.start()
        self.port = self.forwarder.port

    async def asyncTearDown(self) -> None:
        await self.forwarder.stop()
        self.echo_server.close()
        await self.echo_server.wait_closed()

    async def test_client_hello_passes_through_and_sni_reported(self) -> None:
        payload = build_client_hello("cf.090227.xyz")
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(payload)
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=3.0)
            self.assertEqual(echoed, payload)  # 零干扰：字节完全一致
            await asyncio.sleep(0.2)
            self.assertEqual(self.snis, ["cf.090227.xyz"])
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
            self.assertEqual(self.snis, [])
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

        self.errors: list[str] = []
        self.session_counts: list[int] = []
        self.forwarder = UdpForwarder(
            AppConfig(listen_port=0, target_host="127.0.0.1", target_port=self.echo_port),
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
        finally:
            transport.close()


if __name__ == "__main__":
    unittest.main()
