"""
Multiplexed reverse tunnel over asyncio with 11-byte binary header framing.
"""

import asyncio
import enum
import struct
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

MAGIC = 0xFC01
HEADER_FORMAT = "!HBII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 11 bytes


class MsgType(enum.IntEnum):
    PING = 0x01
    PONG = 0x02
    DISPATCH = 0x03
    STDOUT = 0x04
    STDERR = 0x05
    EXIT = 0x06
    PORT_FWD_OPEN = 0x07
    PORT_FWD_DATA = 0x08
    PORT_FWD_CLOSE = 0x09
    AUTH = 0x0A
    AUTH_OK = 0x0B
    AUTH_FAIL = 0x0C


def pack_frame(msg_type: int, stream_id: int, payload: bytes = b"") -> bytes:
    """
    Pack binary frame: Magic (2B) + MsgType (1B) + StreamID (4B) + PayloadLen (4B) + Payload
    """
    header = struct.pack(HEADER_FORMAT, MAGIC, int(msg_type), int(stream_id), len(payload))
    return header + payload


def unpack_header(data: bytes) -> Tuple[int, int, int, int]:
    """
    Unpack 11-byte frame header: returns (magic, msg_type, stream_id, payload_len)
    """
    if len(data) != HEADER_SIZE:
        raise ValueError(f"Header must be exactly {HEADER_SIZE} bytes, got {len(data)}")
    return struct.unpack(HEADER_FORMAT, data)


async def read_frame(reader: asyncio.StreamReader) -> Optional[Tuple[int, int, bytes]]:
    """
    Read a complete framed message from asyncio StreamReader.
    Returns (msg_type, stream_id, payload) or None on EOF.
    """
    try:
        header_bytes = await reader.readexactly(HEADER_SIZE)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None

    magic, msg_type, stream_id, payload_len = unpack_header(header_bytes)
    if magic != MAGIC:
        raise ValueError(f"Invalid frame magic: 0x{magic:04X} (expected 0x{MAGIC:04X})")

    if payload_len > 0:
        try:
            payload = await reader.readexactly(payload_len)
        except asyncio.IncompleteReadError:
            return None
    else:
        payload = b""

    return msg_type, stream_id, payload


async def write_frame(writer: asyncio.StreamWriter, msg_type: int, stream_id: int, payload: bytes = b"") -> None:
    """Pack and send frame over asyncio StreamWriter."""
    frame = pack_frame(msg_type, stream_id, payload)
    writer.write(frame)
    await writer.drain()


class TunnelController:
    """
    Controller server handling multiplexed agent connections.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9050, secret: str = "") -> None:
        self.host = host
        self.port = port
        self.secret = secret
        self.server: Optional[asyncio.Server] = None
        self.agents: Dict[str, asyncio.StreamWriter] = {}
        self.agent_readers: Dict[str, asyncio.StreamReader] = {}
        self._running = False

    async def start(self) -> None:
        self._running = True
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def stop(self) -> None:
        self._running = False
        for agent_id, writer in list(self.agents.items()):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self.agents.clear()
        self.agent_readers.clear()
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        agent_id: Optional[str] = None
        try:
            # First message should be AUTH: payload contains agent_id:secret
            frame = await read_frame(reader)
            if not frame:
                writer.close()
                return

            msg_type, stream_id, payload = frame
            if msg_type != MsgType.AUTH:
                await write_frame(writer, MsgType.AUTH_FAIL, stream_id, b"Expected AUTH frame")
                writer.close()
                return

            try:
                auth_str = payload.decode("utf-8")
                client_agent_id, client_secret = auth_str.split(":", 1)
            except Exception:
                await write_frame(writer, MsgType.AUTH_FAIL, stream_id, b"Malformed AUTH payload")
                writer.close()
                return

            if self.secret and client_secret != self.secret:
                await write_frame(writer, MsgType.AUTH_FAIL, stream_id, b"Authentication failed")
                writer.close()
                return

            agent_id = client_agent_id
            self.agents[agent_id] = writer
            self.agent_readers[agent_id] = reader
            await write_frame(writer, MsgType.AUTH_OK, stream_id, b"Authenticated")

            while self._running:
                frame = await read_frame(reader)
                if not frame:
                    break
                mtype, sid, pdata = frame
                if mtype == MsgType.PING:
                    await write_frame(writer, MsgType.PONG, sid, b"")
                # other message types can be routed or handled by stream listeners
        except Exception:
            pass
        finally:
            if agent_id and agent_id in self.agents:
                del self.agents[agent_id]
            if agent_id and agent_id in self.agent_readers:
                del self.agent_readers[agent_id]
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def get_connected_agents(self) -> List[str]:
        return list(self.agents.keys())

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "connected_count": len(self.agents),
            "agents": list(self.agents.keys()),
        }


class TunnelAgent:
    """
    Agent client connecting outbound to the TunnelController.
    """

    def __init__(
        self,
        agent_id: str,
        controller_host: str = "127.0.0.1",
        controller_port: int = 9050,
        secret: str = "",
        heartbeat_interval: int = 15,
    ) -> None:
        self.agent_id = agent_id
        self.host = controller_host
        self.port = controller_port
        self.secret = secret
        self.heartbeat_interval = heartbeat_interval
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._running = False
        self._dispatch_handler: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None

    def set_dispatch_handler(self, handler: Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]) -> None:
        self._dispatch_handler = handler

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            auth_payload = f"{self.agent_id}:{self.secret}".encode("utf-8")
            await write_frame(self.writer, MsgType.AUTH, 0, auth_payload)

            resp = await read_frame(self.reader)
            if not resp or resp[0] != MsgType.AUTH_OK:
                if self.writer:
                    self.writer.close()
                    await self.writer.wait_closed()
                return False

            self._running = True
            return True
        except Exception:
            return False

    async def send_ping(self) -> bool:
        if not self.writer:
            return False
        try:
            await write_frame(self.writer, MsgType.PING, 0, b"")
            return True
        except Exception:
            return False

    async def disconnect(self) -> None:
        self._running = False
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
