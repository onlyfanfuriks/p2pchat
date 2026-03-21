"""Wire protocol for p2pchat: length-prefixed JSON over TLS.

Frame format:
    [4 bytes big-endian uint32 length][JSON bytes]

The JSON body is a serialised WireMessage (msgspec.Struct).

Payload shapes by message type
--------------------------------
handshake / handshake_ack::

    {
        "ephemeral_x25519_pub": "<base64url>",   # 32-byte X25519 ephemeral public key
        "ed25519_pub":          "<base64url>",   # 32-byte Ed25519 identity public key
        "display_name":         "<str>",
        "version":              "1.0",
    }

chat::

    {
        "nonce":      "<base64url>",   # 12-byte AES-GCM nonce
        "ciphertext": "<base64url>",   # AES-GCM ciphertext (includes 16-byte auth tag)
        "signature":  "<base64url>",   # 64-byte Ed25519 sig over (nonce || ciphertext)
    }

ack::

    {
        "acked_id": "<message_id>",    # message_id being acknowledged
    }

ping / pong::

    {}   # empty payload

bye::

    {
        "reason": "<str>",   # optional human-readable reason
    }
"""

from __future__ import annotations

import asyncio
import struct

import msgspec

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------

MAX_MESSAGE_SIZE: int = 4 * 1024 * 1024  # 4 MB
PORT: int = 7331

_HEADER_FORMAT = ">I"  # big-endian unsigned 32-bit int
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)  # 4


# -------------------------------------------------------------------------
# Wire message definition
# -------------------------------------------------------------------------

class WireMessage(msgspec.Struct):
    """A single protocol frame exchanged between two peers.

    Fields
    ------
    type        : One of "handshake", "handshake_ack", "chat", "ack",
                  "ping", "pong", "bye".
    from_id     : base64url(ed25519_public) of the sender.
    to_id       : base64url(ed25519_public) of the intended recipient.
    timestamp   : Unix epoch milliseconds at time of creation.
    message_id  : UUID4 string; uniquely identifies this frame.
    payload     : Type-specific dict (see module docstring for shapes).
    """

    type: str
    from_id: str
    to_id: str
    timestamp: int
    message_id: str
    payload: dict


# msgspec encoder / decoder — reused across calls to avoid repeated
# construction.  They are module-level singletons; msgspec objects are
# thread-safe for encode/decode.
_encoder = msgspec.json.Encoder()
_decoder = msgspec.json.Decoder(WireMessage)


# -------------------------------------------------------------------------
# I/O helpers
# -------------------------------------------------------------------------

async def read_message(reader: asyncio.StreamReader) -> WireMessage:
    """Read one WireMessage from *reader*.

    Reads a 4-byte big-endian length header followed by that many bytes of
    JSON.  Deserialises and returns the WireMessage.

    Raises
    ------
    ConnectionError
        If the connection is closed before the full frame is received.
    ValueError
        If the declared frame length exceeds MAX_MESSAGE_SIZE or if the
        JSON body cannot be deserialised as a WireMessage.
    """
    # --- header ---
    try:
        header = await reader.readexactly(_HEADER_SIZE)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError(
            f"Connection closed while reading message header "
            f"(got {len(exc.partial)}/{_HEADER_SIZE} bytes)"
        ) from exc

    (length,) = struct.unpack(_HEADER_FORMAT, header)

    if length == 0:
        raise ValueError("Received message with zero-length body")

    if length > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Message length {length} exceeds MAX_MESSAGE_SIZE ({MAX_MESSAGE_SIZE})"
        )

    # --- body ---
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError(
            f"Connection closed while reading message body "
            f"(got {len(exc.partial)}/{length} bytes)"
        ) from exc

    try:
        return _decoder.decode(body)
    except (msgspec.DecodeError, msgspec.ValidationError):
        raise ValueError("Malformed WireMessage JSON") from None


async def write_message(
    writer: asyncio.StreamWriter,
    msg: WireMessage,
) -> None:
    """Serialise *msg* and write it to *writer* with a 4-byte length prefix.

    Does NOT call ``writer.drain()``; the caller is responsible for
    backpressure management (usually ``await writer.drain()`` or relying on
    the transport buffer).
    """
    body = _encoder.encode(msg)
    length = len(body)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Serialised message length {length} exceeds MAX_MESSAGE_SIZE"
        )
    header = struct.pack(_HEADER_FORMAT, length)
    writer.write(header + body)
    await writer.drain()
