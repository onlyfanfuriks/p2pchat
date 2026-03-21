"""Tests for the Outbox offline message queue.

Tests enqueue (pre-encryption), drain (decrypt + send), retry loop
(exponential backoff), lifecycle management (start/cancel/stop), and
round-trip encryption correctness.
"""

import asyncio
import time

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from p2pchat.core.account import Account
from p2pchat.core.crypto import (
    decode_public_key,
    encode_public_key,
    generate_ed25519_keypair,
    generate_x25519_keypair,
)
from p2pchat.core.delivery.outbox import (
    Outbox,
    _BACKOFF_SCHEDULE,
    _derive_outbox_key,
)
from p2pchat.core.storage import Contact, Storage, derive_db_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_account(name="Alice"):
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return Account(
        ed25519_private=ed_priv,
        ed25519_public=ed_pub,
        x25519_private=x_priv,
        x25519_public=x_pub,
        display_name=name,
    )


def _make_peer():
    """Create a peer identity with real crypto keys.

    Returns (peer_id, x25519_pub_encoded, ed_priv, ed_pub, x_priv, x_pub).
    """
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    peer_id = encode_public_key(ed_pub)
    x25519_pub_encoded = encode_public_key(x_pub)
    return peer_id, x25519_pub_encoded, ed_priv, ed_pub, x_priv, x_pub


def _make_contact(peer_id, x25519_pub_encoded, name="Bob"):
    return Contact(
        peer_id=peer_id,
        display_name=name,
        x25519_pub=x25519_pub_encoded,
        trusted=True,
        added_at=int(time.time()),
        ygg_address="200:test::2",
    )


async def _make_storage(tmp_path, account):
    db_key = derive_db_key(account.ed25519_private)
    storage = Storage(tmp_path / "test.db", db_key)
    await storage.initialize()
    return storage


def _mock_session(peer_id, state="active"):
    session = MagicMock()
    session.peer_id = peer_id
    session.state = state
    session.send_message = AsyncMock(return_value="wire-msg-id")
    return session


# ---------------------------------------------------------------------------
# TestDeriveOutboxKey
# ---------------------------------------------------------------------------

class TestDeriveOutboxKey:
    def test_derives_deterministic_key(self):
        account = _make_account()
        _, x_pub_enc, _, ed_pub, _, x_pub = _make_peer()
        their_x = decode_public_key(x_pub_enc)
        their_ed = decode_public_key(encode_public_key(ed_pub))

        key1 = _derive_outbox_key(account, their_x, their_ed)
        key2 = _derive_outbox_key(account, their_x, their_ed)
        assert key1 == key2
        assert len(key1) == 32

    def test_different_peers_get_different_keys(self):
        account = _make_account()
        _, x1_enc, _, ed1, _, _ = _make_peer()
        _, x2_enc, _, ed2, _, _ = _make_peer()

        key1 = _derive_outbox_key(
            account, decode_public_key(x1_enc), decode_public_key(encode_public_key(ed1)),
        )
        key2 = _derive_outbox_key(
            account, decode_public_key(x2_enc), decode_public_key(encode_public_key(ed2)),
        )
        assert key1 != key2


# ---------------------------------------------------------------------------
# TestOutboxEnqueue
# ---------------------------------------------------------------------------

class TestOutboxEnqueue:
    async def test_enqueue_stores_item(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        contact = _make_contact(peer_id, x_pub_enc)
        await storage.upsert_contact(contact)

        outbox = Outbox(account, storage)
        item_id = await outbox.enqueue(peer_id, "hello world")

        items = await storage.get_pending_outbox(peer_id)
        assert len(items) == 1
        assert items[0].id == item_id
        assert items[0].peer_id == peer_id
        assert items[0].encrypted_blob != ""
        assert items[0].signature != ""
        await storage.close()

    async def test_enqueue_returns_unique_ids(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        id1 = await outbox.enqueue(peer_id, "msg1")
        id2 = await outbox.enqueue(peer_id, "msg2")
        assert id1 != id2
        await storage.close()

    async def test_enqueue_unknown_contact_raises(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)

        with pytest.raises(ValueError, match="Unknown contact"):
            await outbox.enqueue("nonexistent_peer", "hello")
        await storage.close()

    async def test_enqueue_with_message_id(self, tmp_path):
        from p2pchat.core.storage import Message

        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        # Save a message first so the FK is satisfied.
        msg = Message(
            id="msg-123", peer_id=peer_id, direction="sent",
            content="hello", timestamp=int(time.time()),
        )
        await storage.save_message(msg)

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "hello", message_id="msg-123")

        items = await storage.get_pending_outbox(peer_id)
        assert items[0].message_id == "msg-123"
        await storage.close()

    async def test_enqueue_pre_encrypts_content(self, tmp_path):
        """Encrypted blob does not contain plaintext."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "secret message")

        items = await storage.get_pending_outbox(peer_id)
        assert "secret message" not in items[0].encrypted_blob
        await storage.close()


# ---------------------------------------------------------------------------
# TestOutboxDecryptItem
# ---------------------------------------------------------------------------

class TestOutboxDecryptItem:
    async def test_round_trip_encrypt_decrypt(self, tmp_path):
        """enqueue then _decrypt_item recovers the original plaintext."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, _, ed_pub, _, x_pub = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "round trip test")

        items = await storage.get_pending_outbox(peer_id)
        their_x = decode_public_key(x_pub_enc)
        their_ed = decode_public_key(peer_id)
        static_key = _derive_outbox_key(account, their_x, their_ed)

        plaintext = outbox._decrypt_item(items[0], static_key)
        assert plaintext == "round trip test"
        await storage.close()

    async def test_decrypt_unicode_content(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        original = "Привет мир! 🌍"
        await outbox.enqueue(peer_id, original)

        items = await storage.get_pending_outbox(peer_id)
        their_x = decode_public_key(x_pub_enc)
        their_ed = decode_public_key(peer_id)
        static_key = _derive_outbox_key(account, their_x, their_ed)

        assert outbox._decrypt_item(items[0], static_key) == original
        await storage.close()


# ---------------------------------------------------------------------------
# TestOutboxDrain
# ---------------------------------------------------------------------------

class TestOutboxDrain:
    async def test_drain_sends_pending_messages(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg1")
        await outbox.enqueue(peer_id, "msg2")

        session = _mock_session(peer_id)
        sent = await outbox.drain(session)

        assert sent == 2
        assert session.send_message.await_count == 2
        # Verify plaintext was recovered and sent.
        calls = [c.args[0] for c in session.send_message.call_args_list]
        assert "msg1" in calls
        assert "msg2" in calls
        await storage.close()

    async def test_drain_marks_items_delivered(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "test")

        session = _mock_session(peer_id)
        await outbox.drain(session)

        remaining = await storage.get_pending_outbox(peer_id)
        assert len(remaining) == 0
        await storage.close()

    async def test_drain_empty_outbox_returns_zero(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        session = _mock_session(peer_id)
        sent = await outbox.drain(session)

        assert sent == 0
        session.send_message.assert_not_awaited()
        await storage.close()

    async def test_drain_skips_corrupt_item(self, tmp_path):
        """Corrupt outbox items are skipped (marked delivered) and drain continues."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg1")
        await outbox.enqueue(peer_id, "msg2")

        # First decrypt raises (corrupt), second succeeds.
        original = outbox._decrypt_item
        call_count = 0

        def _corrupt_first(item, key):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("bad base64")
            return original(item, key)

        session = _mock_session(peer_id)
        with patch.object(outbox, "_decrypt_item", side_effect=_corrupt_first):
            sent = await outbox.drain(session)

        assert sent == 1
        session.send_message.assert_awaited_once()
        remaining = await storage.get_pending_outbox(peer_id)
        assert len(remaining) == 0
        await storage.close()

    async def test_drain_stops_on_send_failure(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg1")
        await outbox.enqueue(peer_id, "msg2")

        session = _mock_session(peer_id)
        session.send_message = AsyncMock(side_effect=ConnectionError("gone"))
        sent = await outbox.drain(session)

        assert sent == 0
        # First item should have attempts incremented, second untouched.
        remaining = await storage.get_pending_outbox(peer_id)
        assert len(remaining) == 2
        assert remaining[0].attempts == 1
        assert remaining[1].attempts == 0
        await storage.close()

    async def test_drain_concurrent_prevented(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg")

        # Simulate concurrent drain by pre-adding to _draining set.
        outbox._draining.add(peer_id)
        session = _mock_session(peer_id)
        sent = await outbox.drain(session)

        assert sent == 0
        session.send_message.assert_not_awaited()
        outbox._draining.discard(peer_id)
        await storage.close()

    async def test_drain_unknown_contact_returns_zero(self, tmp_path):
        """Drain returns 0 if contact was deleted between enqueue and drain."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg")

        # Delete contact before drain.
        await storage.delete_contact(peer_id)

        session = _mock_session(peer_id)
        sent = await outbox.drain(session)
        assert sent == 0
        await storage.close()


# ---------------------------------------------------------------------------
# TestOutboxRetryLoop
# ---------------------------------------------------------------------------

class TestOutboxRetryLoop:
    async def test_retry_exits_when_empty(self, tmp_path):
        """retry_loop returns immediately when no pending items."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)
        peer_id, *_ = _make_peer()

        # Should return immediately — no items.
        await outbox.retry_loop(peer_id, AsyncMock())
        await storage.close()

    async def test_retry_connects_and_drains(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "retry msg")

        session = _mock_session(peer_id)
        connect_fn = AsyncMock(return_value=session)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await outbox.retry_loop(peer_id, connect_fn)

        connect_fn.assert_awaited_once_with(peer_id)
        session.send_message.assert_awaited_once()
        # Items should be drained.
        remaining = await storage.get_pending_outbox(peer_id)
        assert len(remaining) == 0
        await storage.close()

    async def test_retry_backoff_schedule(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg")

        call_count = 0
        session = _mock_session(peer_id)

        async def _connect_eventually(pid):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("not yet")
            return session

        sleep_delays = []

        async def _mock_sleep(delay):
            sleep_delays.append(delay)

        with patch("asyncio.sleep", side_effect=_mock_sleep):
            await outbox.retry_loop(peer_id, _connect_eventually)

        # First two attempts fail, third succeeds.
        assert call_count == 3
        assert sleep_delays[0] == _BACKOFF_SCHEDULE[0]  # 30
        assert sleep_delays[1] == _BACKOFF_SCHEDULE[1]  # 60
        await storage.close()

    async def test_retry_handles_connection_failure(self, tmp_path):
        """retry_loop increments attempt on connection failure."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg")

        attempt = 0
        session = _mock_session(peer_id)

        async def _fail_then_succeed(pid):
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                raise OSError("unreachable")
            return session

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await outbox.retry_loop(peer_id, _fail_then_succeed)

        assert attempt == 2
        await storage.close()

    async def test_retry_cancellation(self, tmp_path):
        """retry_loop propagates CancelledError."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        peer_id, x_pub_enc, *_ = _make_peer()
        await storage.upsert_contact(_make_contact(peer_id, x_pub_enc))

        outbox = Outbox(account, storage)
        await outbox.enqueue(peer_id, "msg")

        # Connect fails, then sleep raises CancelledError (simulating task cancel).
        connect_fn = AsyncMock(side_effect=ConnectionError("unreachable"))

        async def _cancel_sleep(delay):
            raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=_cancel_sleep):
            with pytest.raises(asyncio.CancelledError):
                await outbox.retry_loop(peer_id, connect_fn)
        await storage.close()


# ---------------------------------------------------------------------------
# TestOutboxLifecycle
# ---------------------------------------------------------------------------

class TestOutboxLifecycle:
    async def test_start_retry_creates_task(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)
        peer_id = "test-peer"

        connect_fn = AsyncMock()
        outbox.start_retry(peer_id, connect_fn)

        assert peer_id in outbox._retry_tasks
        task = outbox._retry_tasks[peer_id]
        assert not task.done()

        # Clean up.
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        await storage.close()

    async def test_start_retry_idempotent(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)
        peer_id = "test-peer"

        connect_fn = AsyncMock()
        outbox.start_retry(peer_id, connect_fn)
        task1 = outbox._retry_tasks[peer_id]

        outbox.start_retry(peer_id, connect_fn)
        task2 = outbox._retry_tasks[peer_id]

        assert task1 is task2  # Same task, not replaced.

        task1.cancel()
        try:
            await task1
        except (asyncio.CancelledError, Exception):
            pass
        await storage.close()

    async def test_start_retry_replaces_done_task(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)
        peer_id = "test-peer"

        # Create a completed task.
        done_task = asyncio.create_task(asyncio.sleep(0))
        await done_task
        outbox._retry_tasks[peer_id] = done_task

        connect_fn = AsyncMock()
        outbox.start_retry(peer_id, connect_fn)
        new_task = outbox._retry_tasks[peer_id]

        assert new_task is not done_task

        new_task.cancel()
        try:
            await new_task
        except (asyncio.CancelledError, Exception):
            pass
        await storage.close()

    async def test_cancel_retry(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)
        peer_id = "test-peer"

        outbox.start_retry(peer_id, AsyncMock())
        assert peer_id in outbox._retry_tasks

        outbox.cancel_retry(peer_id)
        assert peer_id not in outbox._retry_tasks
        await storage.close()

    async def test_cancel_retry_nonexistent(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)

        # Should not raise.
        outbox.cancel_retry("nonexistent")
        await storage.close()

    async def test_stop_cancels_all_tasks(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)

        outbox.start_retry("peer1", AsyncMock())
        outbox.start_retry("peer2", AsyncMock())
        assert len(outbox._retry_tasks) == 2

        await outbox.stop()
        assert len(outbox._retry_tasks) == 0
        await storage.close()

    async def test_stop_with_no_tasks(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        outbox = Outbox(account, storage)

        # Should not raise.
        await outbox.stop()
        await storage.close()


# ---------------------------------------------------------------------------
# TestOutboxConstants
# ---------------------------------------------------------------------------

class TestOutboxConstants:
    def test_backoff_schedule(self):
        assert _BACKOFF_SCHEDULE == (30, 60, 120, 300, 600)

    def test_backoff_max_is_600(self):
        assert _BACKOFF_SCHEDULE[-1] == 600
