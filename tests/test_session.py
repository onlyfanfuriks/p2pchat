"""Tests for p2pchat.core.network.session — handshake and message exchange."""

from __future__ import annotations

import asyncio
import logging
import socket
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from p2pchat.core.account import Account
from p2pchat.core.crypto import (
    encode_public_key,
    generate_ed25519_keypair,
    generate_x25519_keypair,
)
from p2pchat.core.network.session import (
    ChatMessage,
    PeerSession,
    _PING_INTERVAL,
    _PONG_TIMEOUT,
)
from p2pchat.core.protocol import WireMessage, write_message
from p2pchat.core.storage import Contact, Storage, derive_db_key


async def _full_handshake(session: PeerSession) -> None:
    """Perform crypto handshake + identity verification in one step."""
    await session.handshake()
    await session.verify_and_activate()


# ---------------------------------------------------------------------------
# Account / Storage factories
# ---------------------------------------------------------------------------

def _make_account(display_name: str = "Alice") -> Account:
    """Create a fresh in-memory Account (no disk I/O)."""
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return Account(
        ed25519_private=ed_priv,
        ed25519_public=ed_pub,
        x25519_private=x_priv,
        x25519_public=x_pub,
        display_name=display_name,
    )


async def _make_storage(tmp_path: Path, account: Account) -> Storage:
    db_path = tmp_path / "test.db"
    db_key = derive_db_key(account.ed25519_private)
    storage = Storage(db_path, db_key)
    await storage.initialize()
    return storage


# ---------------------------------------------------------------------------
# In-memory stream pair via real socketpair
# ---------------------------------------------------------------------------

async def make_stream_pair() -> tuple[
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
    tuple[asyncio.StreamReader, asyncio.StreamWriter],
]:
    """Return two (reader, writer) pairs connected to each other via socketpair.

    Data written to pair A's writer appears on pair B's reader, and vice versa.
    Uses a real OS socketpair so that asyncio's StreamWriter.drain() and
    wait_closed() work correctly.
    """
    sock_a, sock_b = socket.socketpair()

    # Wrap sock_a — reading from it gives data written to sock_b, and vice versa.
    a_reader, a_writer = await asyncio.open_connection(sock=sock_a)
    b_reader, b_writer = await asyncio.open_connection(sock=sock_b)

    return (a_reader, a_writer), (b_reader, b_writer)


# ---------------------------------------------------------------------------
# TestHandshake
# ---------------------------------------------------------------------------

class TestHandshake:
    async def test_successful_handshake_both_known(self, tmp_path: Path):
        """Two peers that already trust each other complete the handshake."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "alice", alice_acc)
        bob_store = await _make_storage(tmp_path / "bob", bob_acc)

        # Pre-trust each other.
        await alice_store.upsert_contact(Contact(
            peer_id=bob_acc.user_id,
            display_name="Bob",
            x25519_pub=encode_public_key(bob_acc.x25519_public),
            trusted=True,
            added_at=int(time.time()),
        ))
        await bob_store.upsert_contact(Contact(
            peer_id=alice_acc.user_id,
            display_name="Alice",
            x25519_pub=encode_public_key(alice_acc.x25519_public),
            trusted=True,
            added_at=int(time.time()),
        ))

        (ar, aw), (br, bw) = await make_stream_pair()

        alice_session = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True)
        bob_session = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False)

        await asyncio.gather(*[_full_handshake(alice_session), _full_handshake(bob_session)])

        assert alice_session.state == "active"
        assert bob_session.state == "active"
        assert alice_session.peer_id == bob_acc.user_id
        assert bob_session.peer_id == alice_acc.user_id

        await alice_session.close()
        await bob_session.close()

    async def test_unknown_peer_verify_callback_accept(self, tmp_path: Path):
        """An unknown peer is accepted when verify_callback returns True."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "alice", alice_acc)
        bob_store = await _make_storage(tmp_path / "bob", bob_acc)

        accept_all = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()

        alice_session = PeerSession(
            ar, aw, alice_acc, alice_store, is_initiator=True,
            verify_callback=accept_all,
        )
        bob_session = PeerSession(
            br, bw, bob_acc, bob_store, is_initiator=False,
            verify_callback=accept_all,
        )

        await asyncio.gather(*[_full_handshake(alice_session), _full_handshake(bob_session)])

        assert alice_session.state == "active"
        assert bob_session.state == "active"
        assert accept_all.call_count >= 1

        await alice_session.close()
        await bob_session.close()

    async def test_unknown_peer_verify_callback_reject_raises(self, tmp_path: Path):
        """Rejected peer raises ConnectionRefusedError on the rejecting side."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "alice", alice_acc)
        bob_store = await _make_storage(tmp_path / "bob", bob_acc)

        # Alice rejects everyone; Bob accepts.
        reject_all = AsyncMock(return_value=False)
        accept_all = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()

        alice_session = PeerSession(
            ar, aw, alice_acc, alice_store, is_initiator=True,
            verify_callback=reject_all,
        )
        bob_session = PeerSession(
            br, bw, bob_acc, bob_store, is_initiator=False,
            verify_callback=accept_all,
        )

        results = await asyncio.gather(
            *[_full_handshake(alice_session), _full_handshake(bob_session)],
            return_exceptions=True,
        )

        # At least one side should have raised ConnectionRefusedError.
        errors = [r for r in results if isinstance(r, ConnectionRefusedError)]
        assert len(errors) >= 1

    async def test_handshake_derives_same_session_key(self, tmp_path: Path):
        """Both sides derive the identical session key after handshake."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "alice", alice_acc)
        bob_store = await _make_storage(tmp_path / "bob", bob_acc)

        accept_all = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()

        alice_session = PeerSession(
            ar, aw, alice_acc, alice_store, is_initiator=True,
            verify_callback=accept_all,
        )
        bob_session = PeerSession(
            br, bw, bob_acc, bob_store, is_initiator=False,
            verify_callback=accept_all,
        )

        await asyncio.gather(*[_full_handshake(alice_session), _full_handshake(bob_session)])

        # Access private session key for verification.
        assert alice_session._session_key is not None
        assert bob_session._session_key is not None
        assert alice_session._session_key == bob_session._session_key

        await alice_session.close()
        await bob_session.close()


# ---------------------------------------------------------------------------
# TestMessageExchange
# ---------------------------------------------------------------------------

class TestMessageExchange:
    async def _setup_sessions(
        self,
        tmp_path: Path,
        verify_callback=None,
    ) -> tuple[PeerSession, PeerSession]:
        """Create two active (post-handshake) sessions."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "alice", alice_acc)
        bob_store = await _make_storage(tmp_path / "bob", bob_acc)

        cb = verify_callback or AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()

        alice_session = PeerSession(
            ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=cb
        )
        bob_session = PeerSession(
            br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=cb
        )

        await asyncio.gather(*[_full_handshake(alice_session), _full_handshake(bob_session)])
        return alice_session, bob_session

    async def test_send_receive_roundtrip(self, tmp_path: Path):
        """A message sent by Alice is received and decrypted correctly by Bob."""
        alice, bob = await self._setup_sessions(tmp_path)

        plaintext = "Hello, Bob!"
        msg_id = await alice.send_message(plaintext)

        received: list[ChatMessage] = []

        async def _collect() -> None:
            async for cm in bob.receive_loop():
                received.append(cm)
                break  # stop after first message

        await asyncio.wait_for(_collect(), timeout=5.0)

        assert len(received) == 1
        assert received[0].content == plaintext
        assert received[0].message_id == msg_id
        assert received[0].direction == "received"
        # From Bob's perspective, peer_id is Alice's id (the sender).
        # alice.peer_id is Bob's id (who Alice talks to), so compare against
        # bob.peer_id which equals Alice's user_id.
        assert received[0].peer_id == bob.peer_id

        await alice.close()
        await bob.close()

    async def test_duplicate_message_id_handled(self, tmp_path: Path):
        """Duplicate messages with the same message_id are silently dropped."""
        alice, bob = await self._setup_sessions(tmp_path)

        plaintext = "Duplicate test"
        # Send the same message twice (same message_id via patching).
        fixed_id = str(uuid.uuid4())

        class _FixedUUID:
            """Stub that returns a fixed string from str(), simulating uuid4()."""
            def __str__(self) -> str:
                return fixed_id

        with patch("p2pchat.core.network.session.uuid") as mock_uuid:
            mock_uuid.uuid4.return_value = _FixedUUID()
            await alice.send_message(plaintext)
            await alice.send_message(plaintext)

        received: list[ChatMessage] = []

        async def _collect() -> None:
            count = 0
            async for cm in bob.receive_loop():
                received.append(cm)
                count += 1
                if count >= 2:
                    break

        try:
            await asyncio.wait_for(_collect(), timeout=1.0)
        except asyncio.TimeoutError:
            pass  # Expected: only one unique message arrives, loop then times out.

        # At most one unique message should have been yielded.
        assert len(received) <= 1
        if received:
            assert received[0].content == plaintext

        await alice.close()
        await bob.close()

    async def test_tampered_ciphertext_ignored(self, tmp_path: Path):
        """A message with tampered ciphertext is dropped; no valid message yielded."""
        import base64 as _b64

        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "alice", alice_acc)
        bob_store = await _make_storage(tmp_path / "bob", bob_acc)

        accept = AsyncMock(return_value=True)
        (ar, aw), (br, bw) = await make_stream_pair()

        alice_session = PeerSession(
            ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept
        )
        bob_session = PeerSession(
            br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept
        )

        await asyncio.gather(*[_full_handshake(alice_session), _full_handshake(bob_session)])

        # Build a tampered chat message with invalid ciphertext and a bad signature.
        tampered_payload = {
            "nonce": _b64.urlsafe_b64encode(b"\x00" * 12).rstrip(b"=").decode(),
            "ciphertext": _b64.urlsafe_b64encode(b"\xff" * 48).rstrip(b"=").decode(),
            "signature": _b64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode(),
        }
        bad_msg = WireMessage(
            type="chat",
            from_id=alice_acc.user_id,
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload=tampered_payload,
        )
        await write_message(aw, bad_msg)

        received: list[ChatMessage] = []

        async def _collect() -> None:
            async for cm in bob_session.receive_loop():
                received.append(cm)

        # N-09: The loop continues past the bad message; it will time out waiting for more.
        try:
            await asyncio.wait_for(_collect(), timeout=3.0)
        except asyncio.TimeoutError:
            pass

        assert len(received) == 0
        await alice_session.close()  # tampered test cleanup

    async def test_wrong_signature_ignored(self, tmp_path: Path):
        """A message signed with the wrong key is dropped; no valid message yielded."""
        import base64 as _b64
        from p2pchat.core.crypto import encrypt_message as _enc

        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        evil_acc = _make_account("Evil")

        alice_store = await _make_storage(tmp_path / "alice", alice_acc)
        bob_store = await _make_storage(tmp_path / "bob", bob_acc)

        accept = AsyncMock(return_value=True)
        (ar, aw), (br, bw) = await make_stream_pair()

        alice_session = PeerSession(
            ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept
        )
        bob_session = PeerSession(
            br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept
        )

        await asyncio.gather(*[_full_handshake(alice_session), _full_handshake(bob_session)])

        # Use the correct session key but sign with evil_acc's identity key.
        session_key = alice_session._session_key
        encrypted = _enc(session_key, "evil message", evil_acc.ed25519_private)

        bad_msg = WireMessage(
            type="chat",
            from_id=alice_acc.user_id,
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={
                "nonce": _b64.urlsafe_b64encode(encrypted.nonce).rstrip(b"=").decode(),
                "ciphertext": _b64.urlsafe_b64encode(encrypted.ciphertext).rstrip(b"=").decode(),
                "signature": _b64.urlsafe_b64encode(encrypted.signature).rstrip(b"=").decode(),
            },
        )
        await write_message(aw, bad_msg)

        received: list[ChatMessage] = []

        async def _collect() -> None:
            async for cm in bob_session.receive_loop():
                received.append(cm)

        try:
            await asyncio.wait_for(_collect(), timeout=3.0)
        except asyncio.TimeoutError:
            pass

        assert len(received) == 0
        await alice_session.close()


# ---------------------------------------------------------------------------
# TestSessionState
# ---------------------------------------------------------------------------

class TestSessionState:
    async def test_peer_id_before_handshake_raises(self, tmp_path: Path):
        """Accessing peer_id before handshake raises RuntimeError."""
        alice_acc = _make_account("Alice")
        alice_store = await _make_storage(tmp_path, alice_acc)
        (ar, aw), (_, bw) = await make_stream_pair()
        session = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True)

        with pytest.raises(RuntimeError, match="not yet completed"):
            _ = session.peer_id

        await session.close()
        bw.close()

    async def test_send_message_before_handshake_raises(self, tmp_path: Path):
        """send_message() before handshake raises RuntimeError."""
        alice_acc = _make_account("Alice")
        alice_store = await _make_storage(tmp_path, alice_acc)
        (ar, aw), (_, bw) = await make_stream_pair()
        session = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True)

        with pytest.raises(RuntimeError, match="session state"):
            await session.send_message("test")

        await session.close()
        bw.close()

    async def test_receive_loop_before_handshake_raises(self, tmp_path: Path):
        """receive_loop() before handshake raises RuntimeError."""
        alice_acc = _make_account("Alice")
        alice_store = await _make_storage(tmp_path, alice_acc)
        (ar, aw), (_, bw) = await make_stream_pair()
        session = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True)

        with pytest.raises(RuntimeError, match="session state"):
            async for _ in session.receive_loop():  # noqa: S108
                break

        await session.close()
        bw.close()

    async def test_close_idempotent(self, tmp_path: Path):
        """close() can be called multiple times without error."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)
        accept = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept)
        await asyncio.gather(*[_full_handshake(alice), _full_handshake(bob)])

        await alice.close()
        await alice.close()  # Should not raise.
        assert alice.state == "disconnected"
        await bob.close()

    async def test_close_clears_session_key(self, tmp_path: Path):
        """N-27: close() sets session_key to None."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)
        accept = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept)
        await asyncio.gather(*[_full_handshake(alice), _full_handshake(bob)])

        assert alice._session_key is not None
        await alice.close()
        assert alice._session_key is None
        await bob.close()


# ---------------------------------------------------------------------------
# TestControlMessages
# ---------------------------------------------------------------------------

class TestControlMessages:
    async def _setup(self, tmp_path: Path) -> tuple[PeerSession, PeerSession]:
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)
        accept = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept)
        await asyncio.gather(*[_full_handshake(alice), _full_handshake(bob)])
        return alice, bob

    async def test_bye_terminates_receive_loop(self, tmp_path: Path):
        """Peer sending 'bye' cleanly terminates receive_loop."""
        alice, bob = await self._setup(tmp_path)

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)

        # Alice sends bye via close().
        await alice.close()

        # Bob's loop should exit quickly after receiving bye.
        await asyncio.wait_for(_collect(), timeout=3.0)
        assert len(received) == 0

    async def test_ping_pong_exchange(self, tmp_path: Path):
        """Ping from Alice is answered with pong by Bob's receive_loop."""
        alice, bob = await self._setup(tmp_path)

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        loop_task = asyncio.create_task(_collect())

        # Give loop a moment to start, then send a ping.
        await asyncio.sleep(0.05)
        await alice._send_ping()

        # Send a real message to verify loop is alive after handling ping.
        await asyncio.sleep(0.1)
        await alice.send_message("after ping")

        await asyncio.wait_for(loop_task, timeout=3.0)

        assert len(received) == 1
        assert received[0].content == "after ping"

        await alice.close()
        await bob.close()

    async def test_send_ack(self, tmp_path: Path):
        """send_ack() sends an ACK message without error."""
        alice, bob = await self._setup(tmp_path)

        await alice.send_message("test")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                await bob.send_ack(cm.message_id)
                break

        await asyncio.wait_for(_collect(), timeout=3.0)
        assert len(received) == 1

        await alice.close()
        await bob.close()

    async def test_from_id_mismatch_ignored(self, tmp_path: Path):
        """N-12: Messages with wrong from_id are silently ignored."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)
        accept = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept)
        await asyncio.gather(*[_full_handshake(alice), _full_handshake(bob)])

        # Send a message with a spoofed from_id.
        spoofed = WireMessage(
            type="chat",
            from_id="spoofed-peer-id",
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={},
        )
        await write_message(aw, spoofed)

        # Then send a legitimate message.
        await alice.send_message("legit")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        await asyncio.wait_for(_collect(), timeout=3.0)
        assert len(received) == 1
        assert received[0].content == "legit"

        await alice.close()
        await bob.close()

    async def test_connection_closed_ends_loop(self, tmp_path: Path):
        """Connection drop ends receive_loop cleanly."""
        alice, bob = await self._setup(tmp_path)

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)

        # Close the underlying writer directly (simulating TCP drop).
        alice._writer.close()
        try:
            await alice._writer.wait_closed()
        except Exception:
            pass

        await asyncio.wait_for(_collect(), timeout=3.0)
        assert bob.state == "disconnected"


# ---------------------------------------------------------------------------
# TestDisplayNameChange
# ---------------------------------------------------------------------------

class TestDisplayNameChange:
    async def test_trusted_peer_name_change_accepted(self, tmp_path: Path):
        """N-28: Trusted peer changing display_name still completes handshake."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)

        # Bob trusts Alice under name "OldAlice".
        await bob_store.upsert_contact(Contact(
            peer_id=alice_acc.user_id,
            display_name="OldAlice",
            x25519_pub=encode_public_key(alice_acc.x25519_public),
            trusted=True,
            added_at=int(time.time()),
        ))
        await alice_store.upsert_contact(Contact(
            peer_id=bob_acc.user_id,
            display_name="Bob",
            x25519_pub=encode_public_key(bob_acc.x25519_public),
            trusted=True,
            added_at=int(time.time()),
        ))

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False)

        await asyncio.gather(*[_full_handshake(alice), _full_handshake(bob)])

        assert alice.state == "active"
        assert bob.state == "active"

        await alice.close()
        await bob.close()


# ---------------------------------------------------------------------------
# TestVerifyCallbackEdgeCases
# ---------------------------------------------------------------------------

class TestVerifyCallbackEdgeCases:
    async def test_callback_exception_rejects_peer(self, tmp_path: Path):
        """If verify_callback raises, peer is rejected."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)

        error_cb = AsyncMock(side_effect=RuntimeError("callback error"))
        accept_cb = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=error_cb)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept_cb)

        results = await asyncio.gather(
            *[_full_handshake(alice), _full_handshake(bob)],
            return_exceptions=True,
        )

        errors = [r for r in results if isinstance(r, (ConnectionRefusedError, ConnectionError))]
        assert len(errors) >= 1

    async def test_no_callback_rejects_unknown(self, tmp_path: Path):
        """Unknown peer without verify_callback is rejected."""
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False)

        results = await asyncio.gather(
            *[_full_handshake(alice), _full_handshake(bob)],
            return_exceptions=True,
        )

        errors = [r for r in results if isinstance(r, (ConnectionRefusedError, ConnectionError))]
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# TestKeepaliveTimeout
# ---------------------------------------------------------------------------

class TestKeepaliveTimeout:
    """Tests for the ping/pong keepalive mechanism and timeout disconnection."""

    async def _setup(self, tmp_path: Path) -> tuple[PeerSession, PeerSession]:
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)
        accept = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept)
        await asyncio.gather(*[_full_handshake(alice), _full_handshake(bob)])
        return alice, bob

    async def test_pong_timeout_disconnects(self, tmp_path: Path):
        """Session disconnects when pong is not received within timeout."""
        alice, bob = await self._setup(tmp_path)

        # Patch _PING_INTERVAL and _PONG_TIMEOUT to small values for fast test.
        # The receive_loop read timeout is _PING_INTERVAL + _PONG_TIMEOUT + 5.0,
        # so we need the outer wait_for to exceed that (0.1 + 0.1 + 5.0 = 5.2s).
        with patch("p2pchat.core.network.session._PING_INTERVAL", 0.1), \
             patch("p2pchat.core.network.session._PONG_TIMEOUT", 0.1):

            received: list[ChatMessage] = []

            async def _collect():
                async for cm in alice.receive_loop():
                    received.append(cm)

            # Alice's receive_loop sends pings. Bob's side does NOT have
            # a receive_loop running, so Bob will never send a pong back.
            # Alice should disconnect after pong timeout.
            await asyncio.wait_for(_collect(), timeout=8.0)

        assert alice.state == "disconnected"
        await bob.close()

    async def test_keepalive_sent_on_schedule(self, tmp_path: Path):
        """Ping is sent after the idle interval elapses."""
        alice, bob = await self._setup(tmp_path)

        with patch("p2pchat.core.network.session._PING_INTERVAL", 0.1), \
             patch("p2pchat.core.network.session._PONG_TIMEOUT", 2.0):

            received_bob: list[ChatMessage] = []

            # Bob's receive_loop will auto-respond to pings with pongs.
            async def _collect_bob():
                async for cm in bob.receive_loop():
                    received_bob.append(cm)

            bob_task = asyncio.create_task(_collect_bob())

            # Track pings sent by Alice's keepalive loop via _send_ping.
            original_send_ping = alice._send_ping
            ping_count = 0

            async def _counting_ping():
                nonlocal ping_count
                ping_count += 1
                await original_send_ping()

            alice._send_ping = _counting_ping

            received_alice: list[ChatMessage] = []

            async def _collect_alice():
                async for cm in alice.receive_loop():
                    received_alice.append(cm)

            alice_task = asyncio.create_task(_collect_alice())

            # Wait long enough for at least 2 ping cycles (0.1s interval).
            await asyncio.sleep(0.4)

            assert ping_count >= 2, f"Expected >= 2 pings sent, got {ping_count}"
            assert alice.state == "active"

            await alice.close()
            await bob.close()
            for t in (alice_task, bob_task):
                try:
                    await asyncio.wait_for(t, timeout=3.0)
                except Exception:
                    t.cancel()

    async def test_keepalive_resets_on_message_sent(self, tmp_path: Path):
        """Sending a chat message resets the keepalive timer so no ping is needed."""
        alice, bob = await self._setup(tmp_path)

        with patch("p2pchat.core.network.session._PING_INTERVAL", 0.3), \
             patch("p2pchat.core.network.session._PONG_TIMEOUT", 2.0):

            received_bob: list[ChatMessage] = []

            async def _collect_bob():
                async for cm in bob.receive_loop():
                    received_bob.append(cm)

            bob_task = asyncio.create_task(_collect_bob())

            original_send_ping = alice._send_ping
            ping_count = 0

            async def _counting_ping():
                nonlocal ping_count
                ping_count += 1
                await original_send_ping()

            alice._send_ping = _counting_ping

            received_alice: list[ChatMessage] = []

            async def _collect_alice():
                async for cm in alice.receive_loop():
                    received_alice.append(cm)

            alice_task = asyncio.create_task(_collect_alice())

            # Send messages faster than the ping interval to suppress pings.
            for _ in range(5):
                await alice.send_message("keep alive")
                await asyncio.sleep(0.1)

            # No pings should have been needed since we kept sending messages.
            assert ping_count == 0, f"Expected 0 pings (messages reset timer), got {ping_count}"

            await alice.close()
            await bob.close()
            for t in (alice_task, bob_task):
                try:
                    await asyncio.wait_for(t, timeout=3.0)
                except Exception:
                    t.cancel()

    async def test_pong_response_keeps_session_alive(self, tmp_path: Path):
        """Receiving a pong keeps the session from disconnecting."""
        alice, bob = await self._setup(tmp_path)

        with patch("p2pchat.core.network.session._PING_INTERVAL", 0.1), \
             patch("p2pchat.core.network.session._PONG_TIMEOUT", 2.0):

            received_alice: list[ChatMessage] = []
            received_bob: list[ChatMessage] = []

            async def _collect_alice():
                async for cm in alice.receive_loop():
                    received_alice.append(cm)

            async def _collect_bob():
                async for cm in bob.receive_loop():
                    received_bob.append(cm)

            alice_task = asyncio.create_task(_collect_alice())
            bob_task = asyncio.create_task(_collect_bob())

            # Let both loops run. Bob's loop responds to pings with pongs.
            # Wait long enough for multiple ping/pong cycles.
            await asyncio.sleep(0.5)

            # Both sessions should still be active (pongs kept them alive).
            assert alice.state == "active"
            assert bob.state == "active"

            # Clean shutdown.
            await alice.close()
            await bob.close()
            try:
                await asyncio.wait_for(alice_task, timeout=3.0)
            except Exception:
                alice_task.cancel()
            try:
                await asyncio.wait_for(bob_task, timeout=3.0)
            except Exception:
                bob_task.cancel()


# ---------------------------------------------------------------------------
# TestUnknownMessageType
# ---------------------------------------------------------------------------

class TestUnknownMessageType:
    """Tests for receiving messages with unknown/unrecognized type."""

    async def _setup(self, tmp_path: Path) -> tuple[PeerSession, PeerSession, Account, Account]:
        alice_acc = _make_account("Alice")
        bob_acc = _make_account("Bob")
        alice_store = await _make_storage(tmp_path / "a", alice_acc)
        bob_store = await _make_storage(tmp_path / "b", bob_acc)
        accept = AsyncMock(return_value=True)

        (ar, aw), (br, bw) = await make_stream_pair()
        alice = PeerSession(ar, aw, alice_acc, alice_store, is_initiator=True, verify_callback=accept)
        bob = PeerSession(br, bw, bob_acc, bob_store, is_initiator=False, verify_callback=accept)
        await asyncio.gather(*[_full_handshake(alice), _full_handshake(bob)])
        return alice, bob, alice_acc, bob_acc

    async def test_unknown_type_does_not_crash(self, tmp_path: Path):
        """Receiving a message with unknown type does not crash the session."""
        alice, bob, alice_acc, bob_acc = await self._setup(tmp_path)

        # Inject a message with an unknown type directly on the wire.
        unknown = WireMessage(
            type="unknown_fancy_type",
            from_id=alice_acc.user_id,
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={"data": "something"},
        )
        await write_message(alice._writer, unknown)

        # Follow with a legitimate message to confirm the loop is still alive.
        await alice.send_message("after unknown")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        await asyncio.wait_for(_collect(), timeout=5.0)

        assert len(received) == 1
        assert received[0].content == "after unknown"

        await alice.close()
        await bob.close()

    async def test_unknown_type_logged(self, tmp_path: Path, caplog):
        """Receiving an unknown message type is logged at DEBUG level."""
        alice, bob, alice_acc, bob_acc = await self._setup(tmp_path)

        unknown = WireMessage(
            type="totally_made_up",
            from_id=alice_acc.user_id,
            to_id=bob_acc.user_id,
            timestamp=int(time.time() * 1000),
            message_id=str(uuid.uuid4()),
            payload={},
        )
        await write_message(alice._writer, unknown)
        # Sentinel message so the loop yields and we can break.
        await alice.send_message("sentinel")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        with caplog.at_level(logging.DEBUG, logger="p2pchat.core.network.session"):
            await asyncio.wait_for(_collect(), timeout=5.0)

        assert any(
            "Unknown message type" in rec.message and "totally_made_up" in rec.message
            for rec in caplog.records
        )

        await alice.close()
        await bob.close()

    async def test_session_continues_after_multiple_unknown_types(self, tmp_path: Path):
        """Multiple unknown-type messages do not accumulate failures or disconnect."""
        alice, bob, alice_acc, bob_acc = await self._setup(tmp_path)

        # Send several unknown-type messages.
        for i in range(10):
            unknown = WireMessage(
                type=f"unknown_type_{i}",
                from_id=alice_acc.user_id,
                to_id=bob_acc.user_id,
                timestamp=int(time.time() * 1000),
                message_id=str(uuid.uuid4()),
                payload={},
            )
            await write_message(alice._writer, unknown)

        # Follow with a valid chat message.
        await alice.send_message("still alive after unknowns")

        received: list[ChatMessage] = []

        async def _collect():
            async for cm in bob.receive_loop():
                received.append(cm)
                break

        await asyncio.wait_for(_collect(), timeout=5.0)

        assert len(received) == 1
        assert received[0].content == "still alive after unknowns"
        assert bob.state == "active"

        await alice.close()
        await bob.close()
