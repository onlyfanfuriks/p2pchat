"""Per-peer encrypted session over an established TLS stream.

Each PeerSession wraps a (reader, writer) pair and manages:
- Application-layer handshake (ECDH key exchange + identity verification)
- Encrypted/signed message sending and receiving
- Ping/pong keepalive
- Graceful shutdown
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import AsyncGenerator, Awaitable, Callable, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from p2pchat.core.account import Account
from p2pchat.core.crypto import (
    decode_public_key,
    decrypt_message,
    display_fingerprint,
    encode_public_key,
    encrypt_message,
    generate_x25519_keypair,
    derive_session_key,
)
from p2pchat.core.protocol import WireMessage, read_message, write_message
from p2pchat.core.storage import Contact, Storage

log = logging.getLogger(__name__)

# Keepalive: send a ping if no message has been sent for this many seconds.
_PING_INTERVAL = 30.0
# Disconnect if no pong is received within this many seconds.
_PONG_TIMEOUT = 10.0
# Maximum receive iterations between successful reads (N-30: resets on success).
_MAX_RECV_ITER = 10_000
# Maximum entries in the duplicate-message-ID cache (N-11).
_MAX_SEEN_IDS = 100_000
# Disconnect after this many consecutive decryption/parse failures (N-09).
_MAX_CONSECUTIVE_FAILURES = 5

# Handshake signature context tags (N-01).
_HS_SIG_INIT = b"p2pchat-hs-init"
_HS_SIG_RESP = b"p2pchat-hs-resp"


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class ChatMessage:
    """A decrypted chat message delivered from/to a peer."""

    peer_id: str
    message_id: str
    content: str            # decrypted plaintext
    timestamp: int          # milliseconds since Unix epoch
    direction: Literal["sent", "received"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64enc(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64dec(s: str) -> bytes:
    """URL-safe base64 decode (with or without padding)."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


# ---------------------------------------------------------------------------
# PeerSession
# ---------------------------------------------------------------------------

class PeerSession:
    """Application-layer session for one connected peer.

    Parameters
    ----------
    reader, writer:
        Asyncio stream pair (already TLS-wrapped).
    account:
        The local account (identity + signing key).
    storage:
        Encrypted local DB (used to look up / persist contacts).
    is_initiator:
        True if this side initiated the TCP connection.
    verify_callback:
        Called when an unknown or untrusted peer connects.
        Signature: ``async (peer_id, display_name, fingerprint) -> bool``.
        If None or returns False, the connection is rejected.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        account: Account,
        storage: Storage,
        is_initiator: bool,
        verify_callback: Callable[[str, str, str], Awaitable[bool]] | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._account = account
        self._storage = storage
        self._is_initiator = is_initiator
        self._verify_callback = verify_callback

        self._session_key: bytes | None = None
        self._peer_id: str | None = None
        self._peer_ed25519_pub: bytes | None = None
        self._peer_x25519_pub: str = ""
        self._peer_display_name: str = ""
        self._peer_ygg_address: str = ""
        self._state: Literal["handshaking", "handshake_done", "active", "disconnected"] = "handshaking"

        # Extract peer's IPv6 address from the TCP connection.
        peername = writer.get_extra_info("peername")
        if peername:
            self._peer_ygg_address = str(peername[0])

        # Tracks last time we sent any message (for ping scheduling).
        self._last_sent: float = time.monotonic()
        # Event set when a pong is received.
        self._pong_event: asyncio.Event = asyncio.Event()
        # N-11: Bounded duplicate-message-ID cache (OrderedDict as LRU).
        self._seen_ids: OrderedDict[str, None] = OrderedDict()
        # N-15: Serialize concurrent writes to the stream.
        self._write_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def peer_id(self) -> str:
        if self._peer_id is None:
            raise RuntimeError("Handshake not yet completed")
        return self._peer_id

    @property
    def state(self) -> Literal["handshaking", "handshake_done", "active", "disconnected"]:
        return self._state

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    async def handshake(self) -> None:
        """Perform the application-layer handshake.

        Initiator flow:
        1. Sign ephemeral key with Ed25519 identity key (N-01).
        2. Send ``handshake`` with ephemeral X25519 pub, Ed25519 identity pub,
           and handshake signature.
        3. Receive ``handshake_ack`` from responder.
        4. Verify responder's handshake signature.
        5. Derive session key.

        Responder flow:
        1. Receive ``handshake`` from initiator.
        2. Verify initiator's handshake signature.
        3. Sign ephemeral key (including initiator's eph pub) with Ed25519 identity key.
        4. Send ``handshake_ack``.
        5. Derive session key.

        After key exchange both sides verify the peer identity against storage
        and call *verify_callback* if needed.

        Raises
        ------
        ConnectionRefusedError
            If the peer is rejected by the verify callback.
        ValueError
            If the handshake payload is malformed or signature verification fails.
        """
        eph_priv, eph_pub_bytes = generate_x25519_keypair()

        if self._is_initiator:
            # N-01: Sign proving we own the Ed25519 key that generated this eph key.
            init_sig = self._account.ed25519_private.sign(
                _HS_SIG_INIT + eph_pub_bytes + self._account.ed25519_public
            )
            my_payload = {
                "ephemeral_x25519_pub": _b64enc(eph_pub_bytes),
                "ed25519_pub": encode_public_key(self._account.ed25519_public),
                "x25519_pub": encode_public_key(self._account.x25519_public),
                "display_name": self._account.display_name,
                "version": "1.0",
                "handshake_sig": _b64enc(init_sig),
            }

            # Step 1: send our handshake.
            await self._send_raw(
                WireMessage(
                    type="handshake",
                    from_id=self._account.user_id,
                    to_id="",  # intentionally empty — peer unknown at this point
                    timestamp=int(time.time() * 1000),
                    message_id=str(uuid.uuid4()),
                    payload=my_payload,
                )
            )

            # Step 2: receive ack.
            ack = await read_message(self._reader)
            if ack.type != "handshake_ack":
                raise ValueError(
                    f"Expected handshake_ack, got {ack.type!r}"
                )
            peer_payload = ack.payload
            peer_from_id = ack.from_id

        else:
            # Step 1: receive initiator's handshake.
            msg = await read_message(self._reader)
            if msg.type != "handshake":
                raise ValueError(
                    f"Expected handshake, got {msg.type!r}"
                )
            peer_payload = msg.payload
            peer_from_id = msg.from_id

        # --- Parse peer payload ---
        try:
            their_eph_pub_bytes = _b64dec(peer_payload["ephemeral_x25519_pub"])
            their_ed_pub_encoded = peer_payload["ed25519_pub"]
            their_ed_pub_bytes = decode_public_key(their_ed_pub_encoded)
            their_x25519_pub_encoded = peer_payload.get("x25519_pub", "")
            peer_display_name = str(peer_payload.get("display_name", ""))
            their_sig = _b64dec(peer_payload["handshake_sig"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Malformed handshake payload: {exc}") from exc

        # --- N-01: Verify peer's handshake signature ---
        try:
            peer_pub_key = Ed25519PublicKey.from_public_bytes(their_ed_pub_bytes)
            if self._is_initiator:
                # Responder signed: RESP_TAG + their_eph + our_eph + their_ed25519
                peer_pub_key.verify(
                    their_sig,
                    _HS_SIG_RESP + their_eph_pub_bytes + eph_pub_bytes + their_ed_pub_bytes,
                )
            else:
                # Initiator signed: INIT_TAG + their_eph + their_ed25519
                peer_pub_key.verify(
                    their_sig,
                    _HS_SIG_INIT + their_eph_pub_bytes + their_ed_pub_bytes,
                )
        except InvalidSignature:
            raise ValueError(
                "Handshake identity verification failed — possible MITM attack"
            )

        # --- Responder: build and send our ack AFTER verifying initiator ---
        if not self._is_initiator:
            # N-01: Responder sig includes initiator's eph_pub for session binding.
            resp_sig = self._account.ed25519_private.sign(
                _HS_SIG_RESP + eph_pub_bytes + their_eph_pub_bytes + self._account.ed25519_public
            )
            my_payload = {
                "ephemeral_x25519_pub": _b64enc(eph_pub_bytes),
                "ed25519_pub": encode_public_key(self._account.ed25519_public),
                "x25519_pub": encode_public_key(self._account.x25519_public),
                "display_name": self._account.display_name,
                "version": "1.0",
                "handshake_sig": _b64enc(resp_sig),
            }

            await self._send_raw(
                WireMessage(
                    type="handshake_ack",
                    from_id=self._account.user_id,
                    to_id=peer_from_id,
                    timestamp=int(time.time() * 1000),
                    message_id=str(uuid.uuid4()),
                    payload=my_payload,
                )
            )

        # --- Derive shared session key ---
        self._session_key = derive_session_key(
            eph_priv,
            their_eph_pub_bytes,
            self._account.ed25519_public,
            their_ed_pub_bytes,
        )

        self._peer_id = encode_public_key(their_ed_pub_bytes)
        self._peer_ed25519_pub = their_ed_pub_bytes
        self._peer_x25519_pub = their_x25519_pub_encoded
        self._peer_display_name = peer_display_name

        # N-12: Verify wire from_id matches payload identity key.
        wire_from_id = peer_from_id
        if wire_from_id != self._peer_id:
            raise ValueError(
                f"Wire from_id {wire_from_id!r} does not match "
                f"handshake identity {self._peer_id!r}"
            )

        self._state = "handshake_done"
        log.info(
            "Crypto handshake complete with peer %s (%s)",
            self._peer_id,
            self._peer_display_name,
        )

    async def verify_and_activate(self) -> None:
        """Verify peer identity (TOFU) and activate the session.

        This is separated from handshake() because identity verification
        may require interactive user input (verify modal) which should
        not be subject to the handshake timeout.
        """
        await self._verify_peer_identity()
        self._state = "active"
        log.info(
            "Session activated with peer %s (%s)",
            self._peer_id,
            self._peer_display_name,
        )

    async def _verify_peer_identity(self) -> None:
        """Check peer against the contacts DB; call verify_callback if needed.

        Raises
        ------
        ConnectionRefusedError
            If the peer is rejected.
        """
        # N-47: explicit checks instead of assert.
        if self._peer_id is None or self._peer_ed25519_pub is None:
            raise RuntimeError("Cannot verify: handshake data not set")

        contact = await self._storage.get_contact(self._peer_id)

        if contact is not None and contact.trusted:
            # N-28: Warn on display_name change for trusted peers.
            if (
                self._peer_display_name
                and contact.display_name != self._peer_display_name
            ):
                log.warning(
                    "Trusted peer %s changed display_name from %r to %r",
                    self._peer_id,
                    contact.display_name,
                    self._peer_display_name,
                )
            # Known-trusted peer — auto-accept and refresh contact info.
            await self._storage.upsert_contact(
                Contact(
                    peer_id=self._peer_id,
                    display_name=self._peer_display_name or contact.display_name,
                    x25519_pub=self._peer_x25519_pub,
                    ygg_address=self._peer_ygg_address or contact.ygg_address,
                    trusted=True,
                    added_at=contact.added_at,
                    last_seen=int(time.time()),
                )
            )
            return

        # Unknown or untrusted — ask the callback.
        fingerprint = display_fingerprint(self._peer_ed25519_pub)
        accepted = False
        if self._verify_callback is not None:
            try:
                accepted = await self._verify_callback(
                    self._peer_id,
                    self._peer_display_name,
                    fingerprint,
                )
            except Exception as exc:
                log.warning(
                    "verify_callback raised an exception for peer %s: %s",
                    self._peer_id,
                    exc,
                )
                accepted = False

        if not accepted:
            await self._send_raw(
                WireMessage(
                    type="bye",
                    from_id=self._account.user_id,
                    to_id=self._peer_id,
                    timestamp=int(time.time() * 1000),
                    message_id=str(uuid.uuid4()),
                    payload={"reason": "peer rejected"},
                )
            )
            raise ConnectionRefusedError(
                f"Peer {self._peer_id} was rejected by verify_callback"
            )

        # Accepted — store/update contact as trusted.
        added_at = contact.added_at if contact else int(time.time())
        await self._storage.upsert_contact(
            Contact(
                peer_id=self._peer_id,
                display_name=self._peer_display_name,
                x25519_pub=self._peer_x25519_pub,
                ygg_address=self._peer_ygg_address,
                trusted=True,
                added_at=added_at,
                last_seen=int(time.time()),
            )
        )

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def send_message(
        self, plaintext: str, message_id: str | None = None,
    ) -> str:
        """Encrypt, sign, and send a chat message.

        Parameters
        ----------
        plaintext:
            Message content.
        message_id:
            Optional ID to use as the wire message_id. When provided, ACKs
            from the peer will reference this ID so delivery status can be
            tracked in the local DB. If None, a new UUID is generated.

        Returns the ``message_id`` assigned to the message.
        """
        if self._state != "active":
            raise RuntimeError(
                f"Cannot send message; session state is {self._state!r}"
            )
        # N-47: explicit checks instead of assert.
        if self._session_key is None:
            raise RuntimeError("Session key not set")
        if self._peer_id is None:
            raise RuntimeError("Peer ID not set")

        encrypted = encrypt_message(
            self._session_key,
            plaintext,
            self._account.ed25519_private,
        )
        if message_id is None:
            message_id = str(uuid.uuid4())

        await self._send_raw(
            WireMessage(
                type="chat",
                from_id=self._account.user_id,
                to_id=self._peer_id,
                timestamp=int(time.time() * 1000),
                message_id=message_id,
                payload={
                    "nonce": _b64enc(encrypted.nonce),
                    "ciphertext": _b64enc(encrypted.ciphertext),
                    "signature": _b64enc(encrypted.signature),
                },
            )
        )
        return message_id

    async def send_ack(self, message_id: str) -> None:
        """Send an ACK for a received message."""
        if self._state != "active" or self._peer_id is None:
            return

        await self._send_raw(
            WireMessage(
                type="ack",
                from_id=self._account.user_id,
                to_id=self._peer_id,
                timestamp=int(time.time() * 1000),
                message_id=str(uuid.uuid4()),
                payload={"acked_id": message_id},
            )
        )

    async def _send_ping(self) -> None:
        if self._peer_id is None:
            raise RuntimeError("Peer ID not set")
        await self._send_raw(
            WireMessage(
                type="ping",
                from_id=self._account.user_id,
                to_id=self._peer_id,
                timestamp=int(time.time() * 1000),
                message_id=str(uuid.uuid4()),
                payload={},
            )
        )

    async def _send_pong(self) -> None:
        if self._peer_id is None:
            raise RuntimeError("Peer ID not set")
        await self._send_raw(
            WireMessage(
                type="pong",
                from_id=self._account.user_id,
                to_id=self._peer_id,
                timestamp=int(time.time() * 1000),
                message_id=str(uuid.uuid4()),
                payload={},
            )
        )

    async def _send_raw(self, msg: WireMessage) -> None:
        """Write a WireMessage to the stream and record send time.

        N-15: Serializes concurrent writes via an asyncio lock to prevent
        interleaved frames from send_message / _send_ping / _send_pong.
        """
        async with self._write_lock:
            await write_message(self._writer, msg)
        self._last_sent = time.monotonic()

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------

    async def receive_loop(self) -> AsyncGenerator[ChatMessage, None]:
        """Yield decrypted ChatMessages, handling protocol internals inline.

        The loop ends when the peer sends "bye", the connection drops, or
        the session is closed.

        Also manages ping/pong keepalive:
        - Sends a ping every ``_PING_INTERVAL`` seconds of inactivity.
        - Disconnects if a pong is not received within ``_PONG_TIMEOUT`` seconds.

        Callers MUST consume this generator with ``async for`` or call
        ``aclose()`` to ensure the keepalive task is properly cleaned up.
        """
        if self._state != "active":
            raise RuntimeError(
                f"Cannot receive; session state is {self._state!r}"
            )

        # N-47: explicit checks instead of assert.
        if self._session_key is None:
            raise RuntimeError("Session key not set")
        if self._peer_id is None:
            raise RuntimeError("Peer ID not set")
        if self._peer_ed25519_pub is None:
            raise RuntimeError("Peer public key not set")

        iterations = 0
        consecutive_failures = 0
        ping_task: asyncio.Task | None = None

        async def _keepalive_loop() -> None:
            """Background task that sends pings and enforces pong timeout."""
            while self._state == "active":
                idle = time.monotonic() - self._last_sent
                sleep_for = max(0.0, _PING_INTERVAL - idle)
                await asyncio.sleep(sleep_for)

                if self._state != "active":
                    break

                idle = time.monotonic() - self._last_sent
                if idle < _PING_INTERVAL:
                    continue

                self._pong_event.clear()
                try:
                    await self._send_ping()
                except Exception as exc:
                    log.warning("Failed to send ping to %s: %s", self._peer_id, exc)
                    break

                try:
                    await asyncio.wait_for(
                        self._pong_event.wait(), timeout=_PONG_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    log.warning(
                        "No pong from %s within %.0fs; disconnecting",
                        self._peer_id,
                        _PONG_TIMEOUT,
                    )
                    break

        # N-46: create_task instead of ensure_future.
        ping_task = asyncio.create_task(_keepalive_loop())

        try:
            while self._state == "active":
                iterations += 1
                if iterations > _MAX_RECV_ITER:
                    log.warning(
                        "Reached max receive iterations (%d) for peer %s; closing",
                        _MAX_RECV_ITER,
                        self._peer_id,
                    )
                    break

                try:
                    msg = await asyncio.wait_for(
                        read_message(self._reader),
                        timeout=_PING_INTERVAL + _PONG_TIMEOUT + 5.0,
                    )
                except asyncio.TimeoutError:
                    log.warning(
                        "Read timeout for peer %s; disconnecting", self._peer_id
                    )
                    break
                except (ConnectionError, ValueError) as exc:
                    log.info(
                        "Connection error from peer %s: %s", self._peer_id, exc
                    )
                    break

                # N-30: Reset iteration counter on successful read.
                iterations = 0

                # N-12: Validate from_id matches established peer.
                if msg.from_id != self._peer_id:
                    log.warning(
                        "Message from_id %r does not match peer %r; ignoring",
                        msg.from_id,
                        self._peer_id,
                    )
                    continue

                if msg.type == "bye":
                    log.info(
                        "Peer %s sent bye: %s",
                        self._peer_id,
                        msg.payload.get("reason", ""),
                    )
                    break

                elif msg.type == "ping":
                    try:
                        await self._send_pong()
                    except Exception as exc:
                        log.warning(
                            "Failed to send pong to %s: %s", self._peer_id, exc
                        )
                        break

                elif msg.type == "pong":
                    self._pong_event.set()

                elif msg.type == "ack":
                    acked_id = msg.payload.get("acked_id")
                    log.debug(
                        "ACK from %s for %s", self._peer_id, acked_id,
                    )
                    if acked_id:
                        await self._storage.mark_delivered(acked_id)

                elif msg.type == "chat":
                    # Duplicate guard.
                    if msg.message_id in self._seen_ids:
                        log.debug(
                            "Duplicate message %s from %s; ignoring",
                            msg.message_id,
                            self._peer_id,
                        )
                        continue

                    # N-11: Bounded seen-IDs (evict oldest when full).
                    self._seen_ids[msg.message_id] = None
                    if len(self._seen_ids) > _MAX_SEEN_IDS:
                        self._seen_ids.popitem(last=False)

                    # N-08: Catch only the specific exceptions that can occur.
                    try:
                        payload = msg.payload
                        nonce = _b64dec(payload["nonce"])
                        ciphertext = _b64dec(payload["ciphertext"])
                        signature = _b64dec(payload["signature"])
                    except (KeyError, ValueError) as exc:
                        log.error(
                            "Malformed chat payload from peer %s: %s",
                            self._peer_id,
                            exc,
                        )
                        # N-09: continue instead of break; track failures.
                        consecutive_failures += 1
                        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                            log.error(
                                "Too many consecutive failures from %s; disconnecting",
                                self._peer_id,
                            )
                            break
                        continue

                    try:
                        plaintext = decrypt_message(
                            self._session_key,
                            nonce,
                            ciphertext,
                            signature,
                            self._peer_ed25519_pub,
                        )
                    except ValueError:
                        # N-09: continue instead of break; track failures.
                        log.error(
                            "Decryption/verification failed for message from peer %s",
                            self._peer_id,
                        )
                        consecutive_failures += 1
                        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                            log.error(
                                "Too many consecutive failures from %s; disconnecting",
                                self._peer_id,
                            )
                            break
                        continue

                    # Reset failure counter on successful decrypt.
                    consecutive_failures = 0

                    yield ChatMessage(
                        peer_id=self._peer_id,
                        message_id=msg.message_id,
                        content=plaintext,
                        timestamp=msg.timestamp,
                        direction="received",
                    )

                else:
                    log.debug(
                        "Unknown message type %r from peer %s; ignoring",
                        msg.type,
                        self._peer_id,
                    )

        finally:
            if ping_task is not None:
                ping_task.cancel()
                try:
                    await ping_task
                except (asyncio.CancelledError, Exception):
                    pass
            # N-36: Delegate to close() for consistent cleanup (bye + stream close).
            await self.close()

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Send "bye" and close the underlying stream."""
        if self._state == "disconnected":
            return

        self._state = "disconnected"

        # N-27: Clear session key reference (cannot truly zeroize immutable bytes
        # in Python, but removing the reference allows GC to collect it).
        self._session_key = None

        if self._peer_id is not None:
            try:
                await self._send_raw(
                    WireMessage(
                        type="bye",
                        from_id=self._account.user_id,
                        to_id=self._peer_id,
                        timestamp=int(time.time() * 1000),
                        message_id=str(uuid.uuid4()),
                        payload={"reason": "session closed"},
                    )
                )
            except Exception as exc:
                log.debug("Could not send bye to %s: %s", self._peer_id, exc)

        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception as exc:
            log.debug("Error closing writer: %s", exc)
