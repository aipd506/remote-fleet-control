"""Tests for fleetctl.tunnel (11-byte binary framing and multiplexed reverse tunnel)."""

import asyncio
import pytest
from fleetctl.tunnel import (
    HEADER_SIZE,
    MAGIC,
    MsgType,
    TunnelAgent,
    TunnelController,
    pack_frame,
    unpack_header,
)


def test_frame_header_size_and_packing():
    payload = b"test payload 123"
    stream_id = 42
    msg_type = MsgType.DISPATCH
    
    frame = pack_frame(msg_type, stream_id, payload)
    assert len(frame) == HEADER_SIZE + len(payload)
    assert HEADER_SIZE == 11
    
    magic, parsed_type, parsed_stream, parsed_len = unpack_header(frame[:11])
    assert magic == MAGIC
    assert parsed_type == msg_type
    assert parsed_stream == stream_id
    assert parsed_len == len(payload)
    assert frame[11:] == payload


def test_unpack_header_invalid_size():
    with pytest.raises(ValueError):
        unpack_header(b"short")


def test_tunnel_controller_and_agent_handshake():
    async def _test():
        secret = "secret-tunnel-auth-key"
        controller = TunnelController(host="127.0.0.1", port=0, secret=secret)
        await controller.start()
        port = controller.server.sockets[0].getsockname()[1]

        agent = TunnelAgent(
            agent_id="test-agent-alpha",
            controller_host="127.0.0.1",
            controller_port=port,
            secret=secret,
        )

        try:
            connected = await agent.connect()
            assert connected is True
            assert "test-agent-alpha" in controller.get_connected_agents()
            status = controller.get_status()
            assert status["connected_count"] == 1

            # Test ping
            ping_ok = await agent.send_ping()
            assert ping_ok is True
        finally:
            await agent.disconnect()
            await controller.stop()

    asyncio.run(_test())


def test_tunnel_auth_rejection():
    async def _test():
        secret = "correct-secret"
        controller = TunnelController(host="127.0.0.1", port=0, secret=secret)
        await controller.start()
        port = controller.server.sockets[0].getsockname()[1]

        agent = TunnelAgent(
            agent_id="test-agent-bad",
            controller_host="127.0.0.1",
            controller_port=port,
            secret="wrong-secret",
        )

        try:
            connected = await agent.connect()
            assert connected is False
            assert "test-agent-bad" not in controller.get_connected_agents()
        finally:
            await agent.disconnect()
            await controller.stop()

    asyncio.run(_test())

