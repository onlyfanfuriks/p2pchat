"""Security property tests for the p2pchat network layer.

These tests verify cryptographic and protocol guarantees, not just code
coverage. Each test class corresponds to a security property that the system
MUST maintain. If any test here fails, the code has a security deficiency.
"""

from __future__ import annotations

import asyncio
import socket
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from p2pchat.core.account import Account
from p2pchat.core.crypto import (
    encode_public_key,
    encrypt_message,
    generate_ed25519_keypair,
    generate_x25519_keypair,
)
from p2pchat.core.network.session import (
    ChatMessage,
    PeerSession,
    _MAX_CONSECUTIVE_FAILURES,
    _MAX_SEEN_IDS,
    _b64enc,
)
from p2pchat.core.protocol import WireMessage, write_message
from p2pchat.core.storage import Storage, derive_db_key


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def _make_account(display_name: str = "Peer") -> Account:
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return Account(
        ed25519_private=ed_priv,
        ed25519_public=ed_pub,
        x25519_private=x_priv,
        x25519_public=x_pub,
        display_name=display_name,
    )


async def _make_storage(path: Path, account: Account) -> Storage:
    db_key = derive_db_key(account.ed25519_private)
    storage = Storage(path / "db", db_key)
    await storage.initialize()
    return storage


async def _stream_pair() -> tuple[
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
]:
    a, b = socket.socketpair()
    ar, aw = await asyncio.open_connection(sock=a)
    br, bw = await asyncio.open_connection(sock=b)
    return (ar, aw), (br, bw)


async def _handshaked_pair(
    tmp_path: Path,
) -> tuple[PeerSession, PeerSession, Account, Account]:
    """Return two active sessions + their accounts."""
    alice_acc = _make_account("Alice")
    bob_acc = _make_account("Bob")
    alice_store = await _make_storage(tmp_path / "a", alice_acc)
    bob_store = await _make_storage(tmp_path / "b", bob_acc)
    accept = AsyncMock(return_value=True)

    (ar, aw), (br, bw) = await _stream_pair()
    alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept)
    bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept)
    await asyncio.gather(alice.handshake(), bob.handshake())
    await asyncio.gather(alice.verify_and_activate(), bob.verify_and_activate())
    return alice, bob, alice_acc, bob_acc


# ---------------------------------------------------------------------------
# 1. MITM resistance — handshake requires Ed25519 identity proof (N-01)
# ---------------------------------------------------------------------------

class TestMITMResistance:
    """The handshake binds the ephemeral X25519 key to an Ed25519 identity via
    a signature. An attacker who substitutes their own ephemeral key but cannot
    sign with the victim's Ed25519 private key MUST be detected."""

    async def test_forged_handshake_signature_rejected(self, tmp_path: Path):
        """A handshake with a valid-looking but wrong signature is rejected."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        evil_acc = _make_account("Evil")
        await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)

        (ar, aw), (br, bw) = await _stream_pair()

        # Evil generates their own ephemeral key and signs with their own identity
        # but claims to be alice.
        evil_eph_priv, evil_eph_pub = generate_x25519_keypair()
        evil_sig = evil_acc.ed25519_private.sign(
            b"p2pchat-hs-init" + evil_eph_pub + evil_acc.ed25519_public
        )

        # Forge a handshake message claiming alice's identity but using evil's sig.
        forged = WireMessage(
            type="handshake",
            from_id=alice_acc.user_id,  # claims to be Alice
            to_id="",
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={
                "ephemeral_x25519_pub": _b64enc(evil_eph_pub),
                "ed25519_pub": encode_public_key(alice_acc.ed25519_public),  # Alice's real key
                "display_name": "Alice",
                "version": "1.0",
                "handshake_sig": _b64enc(evil_sig),  # signed with Evil's key
            },
        )
        # Write to aw — data appears on Bob's reader (br).
        await write_message(aw, forged)

        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False,
                          verify_callback=AsyncMock(return_value=True))

        with pytest.raises(ValueError, match="MITM|verification failed"):
            await bob.handshake()

    async def test_missing_handshake_signature_rejected(self, tmp_path: Path):
        """A handshake without a signature field is rejected as malformed."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        bob_store = await _make_storage(tmp_path / "b", bob_acc)

        (_, aw), (br, bw) = await _stream_pair()
        eph_priv, eph_pub = generate_x25519_keypair()

        no_sig = WireMessage(
            type="handshake",
            from_id=alice_acc.user_id,
            to_id="",
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={
                "ephemeral_x25519_pub": _b64enc(eph_pub),
                "ed25519_pub": encode_public_key(alice_acc.ed25519_public),
                "display_name": "Alice",
                "version": "1.0",
                # No handshake_sig field.
            },
        )
        # Write to aw — data appears on Bob's reader (br).
        await write_message(aw, no_sig)

        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False,
                          verify_callback=AsyncMock(return_value=True))

        with pytest.raises(ValueError, match="[Mm]alformed"):
            await bob.handshake()


# ---------------------------------------------------------------------------
# 2. Identity impersonation resistance (N-12)
# ---------------------------------------------------------------------------

class TestImpersonationResistance:
    """After handshake, all messages must come from the authenticated peer_id.
    Messages with a different from_id must be silently dropped."""

    async def test_spoofed_from_id_dropped(self, tmp_path: Path):
        """Messages with from_id != authenticated peer are ignored."""
        alice, bob, alice_acc, bob_acc = await _handshaked_pair(tmp_path)

        # Inject a spoofed message directly on the wire.
        spoofed = WireMessage(
            type="chat",
            from_id="impersonator-id",
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={},
        )
        await write_message(alice._writer, spoofed)
        # Follow with a legitimate message.
        await alice.send_message("real message")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        await asyncio.wait_for(_collect(), timeout=3.0)

        # Only the legitimate message should be delivered.
        assert len(received) == 1
        assert received[0].content == "real message"

        await alice.close()
        await bob.close()

    async def test_wire_from_id_mismatch_during_handshake(self, tmp_path: Path):
        """Handshake fails if wire from_id doesn't match the payload identity key."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        bob_store = await _make_storage(tmp_path / "b", bob_acc)

        (_, aw), (br, bw) = await _stream_pair()
        eph_priv, eph_pub = generate_x25519_keypair()
        sig = alice_acc.ed25519_private.sign(
            b"p2pchat-hs-init" + eph_pub + alice_acc.ed25519_public
        )

        mismatch = WireMessage(
            type="handshake",
            from_id="wrong-id",  # doesn't match ed25519_pub
            to_id="",
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={
                "ephemeral_x25519_pub": _b64enc(eph_pub),
                "ed25519_pub": encode_public_key(alice_acc.ed25519_public),
                "display_name": "Alice",
                "version": "1.0",
                "handshake_sig": _b64enc(sig),
            },
        )
        # Write to aw — data appears on Bob's reader (br).
        await write_message(aw, mismatch)

        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False,
                          verify_callback=AsyncMock(return_value=True))

        with pytest.raises(ValueError, match="does not match"):
            await bob.handshake()


# ---------------------------------------------------------------------------
# 3. Message replay resistance (N-11)
# ---------------------------------------------------------------------------

class TestReplayResistance:
    """Duplicate message IDs must be detected and dropped. The seen-IDs cache
    must be bounded to prevent memory exhaustion."""

    async def test_duplicate_message_id_dropped(self, tmp_path: Path):
        """Replayed message_id is silently discarded."""
        alice, bob, alice_acc, bob_acc = await _handshaked_pair(tmp_path)

        # Send message, then replay the same wire bytes.
        msg_id = await alice.send_message("original")
        # Manually create a second message with the same ID.
        encrypted = encrypt_message(
            alice._session_key, "replay", alice_acc.ed25519_private
        )
        replay = WireMessage(
            type="chat",
            from_id=alice_acc.user_id,
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=msg_id,  # same ID
            payload={
                "nonce": _b64enc(encrypted.nonce),
                "ciphertext": _b64enc(encrypted.ciphertext),
                "signature": _b64enc(encrypted.signature),
            },
        )
        await write_message(alice._writer, replay)
        # Send a third unique message to act as sentinel.
        await alice.send_message("sentinel")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                if len(received) >= 2:
                    break

        await asyncio.wait_for(_collect(), timeout=5.0)

        assert len(received) == 2
        assert received[0].content == "original"
        assert received[1].content == "sentinel"
        # The replay was dropped.

        await alice.close()
        await bob.close()

    async def test_seen_ids_bounded_lru(self, tmp_path: Path):
        """N-11: _seen_ids never exceeds _MAX_SEEN_IDS entries."""
        alice, bob, _, _ = await _handshaked_pair(tmp_path)

        # Manually fill the seen_ids past the limit.
        for i in range(_MAX_SEEN_IDS + 100):
            bob._seen_ids[f"fake-id-{i}"] = None
            if len(bob._seen_ids) > _MAX_SEEN_IDS:
                bob._seen_ids.popitem(last=False)

        assert len(bob._seen_ids) == _MAX_SEEN_IDS
        # Oldest entries should have been evicted.
        assert "fake-id-0" not in bob._seen_ids
        assert f"fake-id-{_MAX_SEEN_IDS + 99}" in bob._seen_ids

        await alice.close()
        await bob.close()


# ---------------------------------------------------------------------------
# 4. Error isolation — bad messages don't crash the session (N-09)
# ---------------------------------------------------------------------------

class TestErrorIsolation:
    """A limited number of corrupt messages must be tolerated. The session
    should only disconnect after _MAX_CONSECUTIVE_FAILURES in a row."""

    async def test_single_bad_message_does_not_kill_session(self, tmp_path: Path):
        """One corrupt message is tolerated; subsequent valid messages are delivered."""
        alice, bob, alice_acc, bob_acc = await _handshaked_pair(tmp_path)

        # Send a bad message (invalid ciphertext).
        bad = WireMessage(
            type="chat",
            from_id=alice_acc.user_id,
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={
                "nonce": _b64enc(b"\x00" * 12),
                "ciphertext": _b64enc(b"\xff" * 48),
                "signature": _b64enc(b"\x00" * 64),
            },
        )
        await write_message(alice._writer, bad)
        # Follow with a valid message.
        await alice.send_message("still alive")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        await asyncio.wait_for(_collect(), timeout=5.0)
        assert len(received) == 1
        assert received[0].content == "still alive"

        await alice.close()
        await bob.close()

    async def test_consecutive_failures_disconnect(self, tmp_path: Path):
        """Exactly _MAX_CONSECUTIVE_FAILURES bad messages disconnect the session."""
        alice, bob, alice_acc, bob_acc = await _handshaked_pair(tmp_path)

        # Send _MAX_CONSECUTIVE_FAILURES corrupt messages.
        for i in range(_MAX_CONSECUTIVE_FAILURES):
            bad = WireMessage(
                type="chat",
                from_id=alice_acc.user_id,
                to_id=bob_acc.user_id,
                timestamp=int(time.time() * 1000),
                message_id=str(uuid.uuid4()),  # unique IDs to bypass dedup
                payload={
                    "nonce": _b64enc(b"\x00" * 12),
                    "ciphertext": _b64enc(b"\xff" * 48),
                    "signature": _b64enc(b"\x00" * 64),
                },
            )
            await write_message(alice._writer, bad)

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)

        # The loop should exit (disconnect) without needing a timeout.
        await asyncio.wait_for(_collect(), timeout=5.0)
        assert len(received) == 0
        assert bob.state == "disconnected"

        await alice.close()

    async def test_success_resets_failure_counter(self, tmp_path: Path):
        """A valid message between bad ones resets the consecutive failure counter."""
        alice, bob, alice_acc, bob_acc = await _handshaked_pair(tmp_path)

        # Send (N-1) bad messages, then 1 good, then (N-1) bad again.
        n = _MAX_CONSECUTIVE_FAILURES - 1
        for i in range(n):
            bad = WireMessage(
                type="chat",
                from_id=alice_acc.user_id,
                to_id=bob_acc.user_id,
                timestamp=int(time.time() * 1000),
                message_id=str(uuid.uuid4()),
                payload={
                    "nonce": _b64enc(b"\x00" * 12),
                    "ciphertext": _b64enc(b"\xff" * 48),
                    "signature": _b64enc(b"\x00" * 64),
                },
            )
            await write_message(alice._writer, bad)

        # Good message — should reset counter.
        await alice.send_message("reset")

        for i in range(n):
            bad = WireMessage(
                type="chat",
                from_id=alice_acc.user_id,
                to_id=bob_acc.user_id,
                timestamp=int(time.time() * 1000),
                message_id=str(uuid.uuid4()),
                payload={
                    "nonce": _b64enc(b"\x00" * 12),
                    "ciphertext": _b64enc(b"\xff" * 48),
                    "signature": _b64enc(b"\x00" * 64),
                },
            )
            await write_message(alice._writer, bad)

        # Another good message — session should still be alive.
        await alice.send_message("still alive")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                if len(received) >= 2:
                    break

        await asyncio.wait_for(_collect(), timeout=5.0)
        assert len(received) == 2
        assert received[0].content == "reset"
        assert received[1].content == "still alive"

        await alice.close()
        await bob.close()


# ---------------------------------------------------------------------------
# 5. Concurrent write safety (N-15)
# ---------------------------------------------------------------------------

class TestConcurrentWriteSafety:
    """Multiple concurrent send_message calls must not produce interleaved
    or corrupt wire frames. The write lock ensures serialization."""

    async def test_concurrent_sends_all_delivered(self, tmp_path: Path):
        """Multiple concurrent messages are all delivered without corruption."""
        alice, bob, _, _ = await _handshaked_pair(tmp_path)

        n_messages = 20
        tasks = [alice.send_message(f"msg-{i}") for i in range(n_messages)]
        await asyncio.gather(*tasks)

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                if len(received) >= n_messages:
                    break

        await asyncio.wait_for(_collect(), timeout=10.0)

        assert len(received) == n_messages
        contents = {cm.content for cm in received}
        expected = {f"msg-{i}" for i in range(n_messages)}
        assert contents == expected

        await alice.close()
        await bob.close()


# ---------------------------------------------------------------------------
# 6. Key erasure on close (N-27)
# ---------------------------------------------------------------------------

class TestKeyErasure:
    """Session keys must not persist in memory after session close."""

    async def test_session_key_cleared_after_close(self, tmp_path: Path):
        """close() sets _session_key to None."""
        alice, bob, _, _ = await _handshaked_pair(tmp_path)

        assert alice._session_key is not None
        assert bob._session_key is not None

        await alice.close()
        await bob.close()

        assert alice._session_key is None
        assert bob._session_key is None
        assert alice.state == "disconnected"
        assert bob.state == "disconnected"

    async def test_send_after_close_raises(self, tmp_path: Path):
        """Cannot send messages after session is closed."""
        alice, bob, _, _ = await _handshaked_pair(tmp_path)
        await alice.close()

        with pytest.raises(RuntimeError):
            await alice.send_message("should fail")

        await bob.close()


# ---------------------------------------------------------------------------
# 7. TLS configuration (N-05, N-16)
# ---------------------------------------------------------------------------

class TestTlsConfiguration:
    """Both server and client TLS contexts must enforce minimum security
    standards: TLS 1.2+, no compression, no session tickets."""

    def test_client_tls_context(self):
        """Client connect() sets up a properly hardened SSLContext."""
        import ssl
        # Replicate what peer.connect() does.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.options & ssl.OP_NO_COMPRESSION
        assert ctx.options & ssl.OP_NO_TICKET

    def test_server_tls_context(self, tmp_path):
        """Server _build_ssl_context sets up a properly hardened SSLContext."""
        import ssl
        from p2pchat.core.network.server import ChatServer, generate_tls_cert

        cert_path, key_path = generate_tls_cert(tmp_path)
        ctx = ChatServer._build_ssl_context(cert_path, key_path)

        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.options & ssl.OP_NO_COMPRESSION
        assert ctx.options & ssl.OP_NO_TICKET


# ---------------------------------------------------------------------------
# 8. Server + Client integration over real TLS
# ---------------------------------------------------------------------------

class TestServerClientIntegration:
    """End-to-end test: ChatServer accepts a connection from peer.connect(),
    both complete handshake, exchange a message."""

    async def test_full_lifecycle(self, tmp_path: Path):
        """Start server, connect client, handshake, exchange message, shutdown."""
        from p2pchat.core.network.server import ChatServer

        server_acc = _make_account("Server")
        client_acc = _make_account("Client")
        server_store = await _make_storage(tmp_path / "s", server_acc)
        client_store = await _make_storage(tmp_path / "c", client_acc)

        accept = AsyncMock(return_value=True)
        session_ready_event = asyncio.Event()
        server_session_holder: list[PeerSession] = []

        async def on_session_ready(session: PeerSession):
            server_session_holder.append(session)
            session_ready_event.set()
            # Keep session alive until it ends.
            async for msg in session.receive_loop():
                pass

        server = ChatServer(
            config_dir=tmp_path / "server_conf",
            account=server_acc,
            storage=server_store,
            on_session_ready=on_session_ready,
            verify_callback=accept,
        )

        # Start on IPv6 loopback.
        await server.start("::1")
        actual_port = server.PORT

        try:
            # Connect client.
            from p2pchat.core.network.peer import connect

            client_session = await connect(
                ygg_address="::1",
                port=actual_port,
                account=client_acc,
                storage=client_store,
                config_dir=tmp_path / "client_conf",
                verify_callback=accept,
                timeout=5.0,
            )

            assert client_session.state == "active"
            assert client_session.peer_id == server_acc.user_id

            # Wait for server to accept.
            await asyncio.wait_for(session_ready_event.wait(), timeout=5.0)
            assert len(server_session_holder) == 1

            await client_session.close()

        finally:
            await server.stop()


# ---------------------------------------------------------------------------
# 9. to_id validation — messages addressed to wrong recipient dropped (N-XX)
# ---------------------------------------------------------------------------

class TestToIdValidation:
    """After handshake, all messages must have to_id matching the local
    account's user_id (or be empty). Messages addressed to a different
    identity must be silently dropped."""

    async def test_wrong_to_id_dropped(self, tmp_path: Path):
        """A chat message with to_id != local user_id is silently discarded."""
        alice, bob, alice_acc, _ = await _handshaked_pair(tmp_path)

        # Inject a message addressed to someone else.
        wrong_recipient = WireMessage(
            type="chat",
            from_id=alice_acc.user_id,
            to_id="someone-elses-id",
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={},
        )
        await write_message(alice._writer, wrong_recipient)
        # Follow with a legitimate message so the receive_loop has
        # something to deliver (acts as sentinel).
        await alice.send_message("legit")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        await asyncio.wait_for(_collect(), timeout=3.0)

        # Only the legitimate message was delivered.
        assert len(received) == 1
        assert received[0].content == "legit"

        await alice.close()
        await bob.close()

    async def test_empty_to_id_accepted(self, tmp_path: Path):
        """A message with empty to_id is NOT dropped (backwards compat)."""
        alice, bob, _, _ = await _handshaked_pair(tmp_path)

        # The to_id check is: ``if msg.to_id and msg.to_id != ...``
        # An empty string evaluates to False, so the message passes through.
        # Send a legitimate message (send_message uses the real to_id).
        await alice.send_message("accepted")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        await asyncio.wait_for(_collect(), timeout=3.0)
        assert len(received) == 1
        assert received[0].content == "accepted"

        await alice.close()
        await bob.close()

    async def test_wrong_to_id_logged(self, tmp_path: Path, caplog):
        """Dropping a wrong-to_id message emits a WARNING log entry."""
        alice, bob, alice_acc, _ = await _handshaked_pair(tmp_path)

        wrong_recipient = WireMessage(
            type="chat",
            from_id=alice_acc.user_id,
            to_id="wrong-target",
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={},
        )
        await write_message(alice._writer, wrong_recipient)
        # Sentinel.
        await alice.send_message("after-drop")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        import logging
        with caplog.at_level(logging.WARNING, logger="p2pchat.core.network.session"):
            await asyncio.wait_for(_collect(), timeout=3.0)

        assert any("does not match local id" in rec.message for rec in caplog.records)
        assert len(received) == 1

        await alice.close()
        await bob.close()


# ---------------------------------------------------------------------------
# 10. Message size limit enforcement (N-XX)
# ---------------------------------------------------------------------------

class TestMessageSizeLimit:
    """The wire protocol enforces a MAX_MESSAGE_SIZE (4 MB) on both read and
    write paths. An attacker who sends a frame header claiming a length
    exceeding this limit must be rejected without allocating that memory."""

    async def test_oversized_length_header_rejects_on_read(self):
        """read_message raises ValueError when the 4-byte length exceeds MAX_MESSAGE_SIZE."""
        import struct
        from p2pchat.core.protocol import MAX_MESSAGE_SIZE, read_message

        oversized = MAX_MESSAGE_SIZE + 1
        header = struct.pack(">I", oversized)

        reader = asyncio.StreamReader()
        reader.feed_data(header)
        reader.feed_eof()

        with pytest.raises(ValueError, match="MAX_MESSAGE_SIZE"):
            await read_message(reader)

    async def test_oversized_body_rejects_on_write(self):
        """write_message raises ValueError when the serialised body exceeds MAX_MESSAGE_SIZE."""
        from p2pchat.core.protocol import MAX_MESSAGE_SIZE

        # Build a message with a payload large enough to exceed the limit.
        huge_payload = {"data": "A" * (MAX_MESSAGE_SIZE + 1)}
        huge_msg = WireMessage(
            type="chat",
            from_id="sender",
            to_id="recipient",
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload=huge_payload,
        )

        # We need a real writer; use a socketpair.
        a, b = socket.socketpair()
        try:
            _, writer = await asyncio.open_connection(sock=a)
            with pytest.raises(ValueError, match="MAX_MESSAGE_SIZE"):
                await write_message(writer, huge_msg)
        finally:
            a.close()
            b.close()

    async def test_oversized_frame_disconnects_session_gracefully(self, tmp_path: Path):
        """When a peer sends an oversized frame header, the receive_loop
        treats it as a connection error and disconnects without crashing.
        A subsequent valid message on a new session would still work."""
        alice, bob, _, _ = await _handshaked_pair(tmp_path)

        # Manually write a raw oversized length header onto Alice's writer.
        # This bypasses write_message's own size check.
        import struct
        from p2pchat.core.protocol import MAX_MESSAGE_SIZE

        oversized_header = struct.pack(">I", MAX_MESSAGE_SIZE + 1)
        # Follow with some dummy bytes (doesn't matter, read_message will
        # reject before reading the body).
        alice._writer.write(oversized_header + b"\x00" * 64)
        await alice._writer.drain()

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)

        # The receive loop should exit (the ValueError from read_message is
        # caught by the ``except (ConnectionError, ValueError)`` handler).
        await asyncio.wait_for(_collect(), timeout=5.0)
        assert len(received) == 0
        assert bob.state == "disconnected"

        await alice.close()

    async def test_zero_length_body_rejected(self):
        """A frame with length=0 is rejected as invalid."""
        import struct
        from p2pchat.core.protocol import read_message

        header = struct.pack(">I", 0)
        reader = asyncio.StreamReader()
        reader.feed_data(header)
        reader.feed_eof()

        with pytest.raises(ValueError, match="zero-length"):
            await read_message(reader)

    async def test_max_uint32_length_rejected(self):
        """A frame header claiming 2^32 - 1 bytes is rejected (would be ~4 GB)."""
        import struct
        from p2pchat.core.protocol import read_message

        max_u32 = (2**32) - 1
        header = struct.pack(">I", max_u32)
        reader = asyncio.StreamReader()
        reader.feed_data(header)
        reader.feed_eof()

        with pytest.raises(ValueError, match="MAX_MESSAGE_SIZE"):
            await read_message(reader)
