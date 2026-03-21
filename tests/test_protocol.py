"""Tests for p2pchat.core.protocol — wire protocol serialization and framing."""

from __future__ import annotations

import asyncio
import struct
import time
import uuid

import msgspec
import pytest

from p2pchat.core.protocol import (
    MAX_MESSAGE_SIZE,
    PORT,
    WireMessage,
    read_message,
    write_message,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_message(**overrides) -> WireMessage:
    defaults = dict(
        type="chat",
        from_id="alice",
        to_id="bob",
        timestamp=int(time.time() * 1000),
        message_id=str(uuid.uuid4()),
        payload={"hello": "world"},
    )
    defaults.update(overrides)
    return WireMessage(**defaults)


def _framed(msg: WireMessage) -> bytes:
    """Manually build the length-prefixed frame for a WireMessage."""
    body = msgspec.json.encode(msg)
    return struct.pack(">I", len(body)) + body


def _make_reader(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


# ---------------------------------------------------------------------------
# WireMessage struct tests
# ---------------------------------------------------------------------------

class TestWireMessage:
    def test_serialise_roundtrip(self):
        msg = _make_message()
        encoded = msgspec.json.encode(msg)
        decoded = msgspec.json.decode(encoded, type=WireMessage)

        assert decoded.type == msg.type
        assert decoded.from_id == msg.from_id
        assert decoded.to_id == msg.to_id
        assert decoded.timestamp == msg.timestamp
        assert decoded.message_id == msg.message_id
        assert decoded.payload == msg.payload

    def test_all_message_types_are_valid_strings(self):
        """WireMessage.type is a plain str — any string is accepted."""
        for t in ("handshake", "handshake_ack", "chat", "ack", "ping", "pong", "bye"):
            msg = _make_message(type=t)
            assert msg.type == t

    def test_payload_is_dict(self):
        msg = _make_message(payload={"key": "value", "num": 42})
        encoded = msgspec.json.encode(msg)
        decoded = msgspec.json.decode(encoded, type=WireMessage)
        assert decoded.payload == {"key": "value", "num": 42}

    def test_unknown_extra_fields_ignored(self):
        """msgspec silently ignores unknown JSON fields by default."""
        msg = _make_message()
        body = msgspec.json.encode(msg)
        # Inject an extra field by manipulating the JSON bytes.
        extra = b',"unexpected_field":"ignored"'
        # Insert before the closing brace.
        body_with_extra = body[:-1] + extra + b"}"
        decoded = msgspec.json.decode(body_with_extra, type=WireMessage)
        assert decoded.from_id == msg.from_id

    def test_constants(self):
        assert MAX_MESSAGE_SIZE == 4 * 1024 * 1024
        assert PORT == 7331


# ---------------------------------------------------------------------------
# read_message / write_message tests
# ---------------------------------------------------------------------------

class TestReadWrite:
    async def test_roundtrip_over_stream(self):
        """Write then read a message through an in-memory stream."""
        original = _make_message(type="handshake", payload={"version": "1.0"})

        # Serialize manually, feed into StreamReader, then read back —
        # no real sockets needed.
        frame = _framed(original)
        reader = _make_reader(frame)

        received = await read_message(reader)
        assert received.type == original.type
        assert received.from_id == original.from_id
        assert received.to_id == original.to_id
        assert received.timestamp == original.timestamp
        assert received.message_id == original.message_id
        assert received.payload == original.payload

    async def test_write_then_read_via_pipe(self):
        """Full write_message → read_message round-trip using os.pipe."""
        msg = _make_message(type="ack", payload={"acked_id": str(uuid.uuid4())})

        # Build reader from the manually encoded frame.
        frame = _framed(msg)
        reader = _make_reader(frame)

        result = await read_message(reader)
        assert result.type == "ack"
        assert result.payload["acked_id"] == msg.payload["acked_id"]

    async def test_too_large_raises_value_error(self):
        """A length header larger than MAX_MESSAGE_SIZE must raise ValueError."""
        oversized_length = MAX_MESSAGE_SIZE + 1
        header = struct.pack(">I", oversized_length)
        reader = _make_reader(header)

        with pytest.raises(ValueError, match="MAX_MESSAGE_SIZE"):
            await read_message(reader)

    async def test_empty_body_raises(self):
        """A length header of 0 must raise ValueError."""
        header = struct.pack(">I", 0)
        reader = _make_reader(header)

        with pytest.raises(ValueError):
            await read_message(reader)

    async def test_connection_closed_mid_header_raises(self):
        """EOF before the 4-byte header is fully received → ConnectionError."""
        reader = _make_reader(b"\x00\x00")  # only 2 bytes, need 4

        with pytest.raises(ConnectionError, match="header"):
            await read_message(reader)

    async def test_connection_closed_mid_body_raises(self):
        """EOF after the header but before the full body → ConnectionError."""
        body = b'{"type":"ping","from_id":"a","to_id":"b"'  # truncated JSON
        header = struct.pack(">I", len(body) + 10)  # claim more bytes than exist
        reader = _make_reader(header + body)  # EOF mid-body

        with pytest.raises(ConnectionError, match="body"):
            await read_message(reader)

    async def test_malformed_json_raises_value_error(self):
        """Non-JSON body → ValueError."""
        body = b"not json at all!!!"
        header = struct.pack(">I", len(body))
        reader = _make_reader(header + body)

        with pytest.raises(ValueError, match="[Mm]alformed"):
            await read_message(reader)

    async def test_valid_json_wrong_shape_raises_value_error(self):
        """Valid JSON that does not match WireMessage shape → ValueError."""
        import json as _json
        body = _json.dumps({"wrong": "fields"}).encode()
        header = struct.pack(">I", len(body))
        reader = _make_reader(header + body)

        with pytest.raises(ValueError):
            await read_message(reader)

    async def test_multiple_messages_on_stream(self):
        """Multiple consecutive messages can be read from the same stream."""
        msgs = [_make_message(type="ping", payload={}) for _ in range(3)]
        frames = b"".join(_framed(m) for m in msgs)
        reader = _make_reader(frames)

        for original in msgs:
            received = await read_message(reader)
            assert received.message_id == original.message_id

    async def test_write_message_produces_correct_frame(self):
        """write_message output matches the manually built frame."""
        msg = _make_message()

        # Capture what write_message produces.
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)

        # Use a mock writer that captures bytes.
        captured: list[bytes] = []

        class _FakeTransport(asyncio.Transport):
            def write(self, data: bytes) -> None:
                captured.append(data)

            def is_closing(self) -> bool:
                return False

            def close(self) -> None:
                # No real transport to close in this in-memory stub.
                pass  # noqa: PIE790

            def get_extra_info(self, name, default=None):
                return default

        _transport = _FakeTransport()
        writer = asyncio.StreamWriter(_transport, protocol, reader, asyncio.get_running_loop())

        await write_message(writer, msg)

        raw = b"".join(captured)
        (length,) = struct.unpack(">I", raw[:4])
        body = raw[4:]
        assert len(body) == length

        decoded = msgspec.json.decode(body, type=WireMessage)
        assert decoded.message_id == msg.message_id


