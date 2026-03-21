"""Tests for p2pchat.core.storage — SQLCipher DB, CRUD, migrations."""

import asyncio
import os
import time

import pytest

from p2pchat.core.crypto import generate_ed25519_keypair
from p2pchat.core.storage import (
    Contact,
    Message,
    OutboxItem,
    Storage,
    _secure_delete,
    derive_db_key,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def make_db_key() -> bytes:
    priv, _ = generate_ed25519_keypair()
    return derive_db_key(priv)


@pytest.fixture
async def storage(tmp_path):
    s = Storage(tmp_path / "messages.db", make_db_key())
    await s.initialize()
    yield s
    await s.close()


@pytest.fixture
async def storage_with_contact(storage):
    """Storage pre-populated with a default contact (peer_id='peer1')."""
    await storage.upsert_contact(_contact())
    yield storage


def _contact(peer_id: str = "peer1", **kw) -> Contact:
    return Contact(
        **{
            "peer_id": peer_id,
            "display_name": "Alice",
            "x25519_pub": "AAAA",
            "trusted": False,
            "added_at": 1_000_000,
            **kw,
        }
    )


def _message(peer_id: str = "peer1", **kw) -> Message:
    return Message(
        **{
            "peer_id": peer_id,
            "direction": "sent",
            "content": "hello",
            "timestamp": 1_000_000_000,
            **kw,
        }
    )


def _outbox_item(peer_id: str = "peer1", **kw) -> OutboxItem:
    return OutboxItem(
        **{
            "peer_id": peer_id,
            "encrypted_blob": "blob==",
            "signature": "sig==",
            "created_at": 1_000_000,
            **kw,
        }
    )


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInitialization:
    async def test_creates_db_file(self, tmp_path):
        db = tmp_path / "messages.db"
        s = Storage(db, make_db_key())
        await s.initialize()
        await s.close()
        assert db.exists()

    async def test_db_permissions_0600(self, tmp_path):
        db = tmp_path / "messages.db"
        s = Storage(db, make_db_key())
        await s.initialize()
        await s.close()
        assert oct(db.stat().st_mode & 0o777) == oct(0o600)

    async def test_existing_db_permissions_enforced(self, tmp_path):
        """Opening an existing file at wrong permissions corrects them."""
        db = tmp_path / "messages.db"
        key = make_db_key()
        s = Storage(db, key)
        await s.initialize()
        await s.close()
        os.chmod(db, 0o644)  # simulate wrong perms
        s2 = Storage(db, key)
        await s2.initialize()
        await s2.close()
        assert oct(db.stat().st_mode & 0o777) == oct(0o600)

    async def test_sequential_double_initialize_is_idempotent(self, tmp_path):
        db = tmp_path / "messages.db"
        s = Storage(db, make_db_key())
        await s.initialize()
        await s.initialize()  # must not open a second connection
        await s.close()

    async def test_concurrent_initialize_is_safe(self, tmp_path):
        """Two concurrent initialize() calls must not open two connections."""
        db = tmp_path / "messages.db"
        key = make_db_key()
        s = Storage(db, key)
        await asyncio.gather(s.initialize(), s.initialize())
        # Verify the DB is usable (no leaked connection)
        await s.upsert_account("uid", "Alice", 1000)
        result = await s.get_account()
        assert result is not None
        await s.close()

    async def test_not_initialized_raises(self, tmp_path):
        s = Storage(tmp_path / "messages.db", make_db_key())
        with pytest.raises(RuntimeError, match="not initialized"):
            await s.list_contacts()

    async def test_wrong_key_raises_on_first_query(self, tmp_path):
        db = tmp_path / "messages.db"
        key = make_db_key()
        s = Storage(db, key)
        await s.initialize()
        await s.close()

        # Wrong key — first DB access should fail
        s2 = Storage(db, os.urandom(32))
        with pytest.raises(Exception):
            await s2.initialize()

    async def test_db_content_is_encrypted(self, storage_with_contact):
        """Raw DB bytes must not contain any plaintext message content."""
        st = storage_with_contact
        await st.save_message(_message(content="supersecretXYZ"))
        await st.close()
        raw = st._db_path.read_bytes()
        assert b"supersecretXYZ" not in raw


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------


class TestMigrations:
    async def test_schema_version_is_1(self, storage):
        assert await storage.get_schema_version() == 1

    async def test_expected_tables_exist(self, storage):
        def _tables():
            return {
                r[0]
                for r in storage._c().execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }

        async with storage._lock:
            tables = await asyncio.to_thread(_tables)
        assert {"contacts", "messages", "outbox", "account", "schema_migrations"}.issubset(tables)

    async def test_migrations_not_reapplied_on_reopen(self, tmp_path):
        key = make_db_key()
        db = tmp_path / "messages.db"

        s = Storage(db, key)
        await s.initialize()
        await s.close()

        s2 = Storage(db, key)
        await s2.initialize()
        assert await s2.get_schema_version() == 1
        await s2.close()

    async def test_outbox_fk_to_contacts_enforced(self, storage):
        """outbox.peer_id FK to contacts must be enforced (ON DELETE CASCADE)."""
        # Insert contact then outbox item
        await storage.upsert_contact(_contact())
        await storage.enqueue_outbox(_outbox_item())
        # Delete contact — CASCADE should wipe the outbox item
        await storage.delete_contact("peer1")
        items = await storage.get_pending_outbox("peer1")
        assert items == []

    async def test_messages_fk_cascade_on_delete_contact(self, storage):
        await storage.upsert_contact(_contact())
        await storage.save_message(_message())
        await storage.delete_contact("peer1")
        msgs = await storage.get_messages("peer1", include_deleted=True)
        assert msgs == []


# ---------------------------------------------------------------------------
# Account table
# ---------------------------------------------------------------------------


class TestAccountTable:
    async def test_upsert_and_get(self, storage):
        await storage.upsert_account("uid123", "Alice", 9999)
        assert await storage.get_account() == ("uid123", "Alice", 9999)

    async def test_upsert_updates_display_name(self, storage):
        await storage.upsert_account("uid123", "Alice", 9999)
        await storage.upsert_account("uid123", "Alice v2", 9999)
        row = await storage.get_account()
        assert row[1] == "Alice v2"

    async def test_get_returns_none_if_absent(self, storage):
        assert await storage.get_account() is None


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------


class TestContacts:
    async def test_upsert_and_get(self, storage):
        await storage.upsert_contact(_contact())
        fetched = await storage.get_contact("peer1")
        assert fetched is not None
        assert fetched.peer_id == "peer1"
        assert fetched.display_name == "Alice"

    async def test_get_unknown_returns_none(self, storage):
        assert await storage.get_contact("nobody") is None

    async def test_list_empty_initially(self, storage):
        assert await storage.list_contacts() == []

    async def test_list_sorted_by_display_name(self, storage):
        await storage.upsert_contact(_contact("p2", display_name="Zara"))
        await storage.upsert_contact(_contact("p1", display_name="Alice"))
        names = [c.display_name for c in await storage.list_contacts()]
        assert names == ["Alice", "Zara"]

    async def test_upsert_updates_existing(self, storage):
        await storage.upsert_contact(_contact())
        await storage.upsert_contact(_contact(display_name="Alice Updated"))
        assert (await storage.get_contact("peer1")).display_name == "Alice Updated"

    async def test_trust_contact(self, storage):
        await storage.upsert_contact(_contact(trusted=False))
        result = await storage.trust_contact("peer1")
        assert result is True
        assert (await storage.get_contact("peer1")).trusted is True

    async def test_trust_contact_returns_false_for_nonexistent(self, storage):
        result = await storage.trust_contact("ghost")
        assert result is False

    async def test_upsert_does_not_downgrade_trust(self, storage):
        """upsert_contact must never reduce trusted=True to False (TOFU model)."""
        await storage.upsert_contact(_contact(trusted=True))
        await storage.upsert_contact(_contact(trusted=False))  # attempt downgrade
        assert (await storage.get_contact("peer1")).trusted is True

    async def test_update_last_seen_explicit(self, storage):
        await storage.upsert_contact(_contact())
        ts = 9_999_999
        await storage.update_last_seen("peer1", ts)
        assert (await storage.get_contact("peer1")).last_seen == ts

    async def test_update_last_seen_defaults_to_now(self, storage):
        await storage.upsert_contact(_contact())
        before = int(time.time())
        await storage.update_last_seen("peer1")
        after = int(time.time())
        last_seen = (await storage.get_contact("peer1")).last_seen
        assert before <= last_seen <= after

    async def test_ygg_address_round_trip(self, storage):
        await storage.upsert_contact(_contact(ygg_address="200:cafe::1"))
        assert (await storage.get_contact("peer1")).ygg_address == "200:cafe::1"

    async def test_empty_ygg_address_returns_empty_string(self, storage):
        await storage.upsert_contact(_contact(ygg_address=""))
        assert (await storage.get_contact("peer1")).ygg_address == ""

    async def test_delete_contact_removes_from_list(self, storage):
        await storage.upsert_contact(_contact())
        await storage.delete_contact("peer1")
        assert await storage.get_contact("peer1") is None
        assert await storage.list_contacts() == []

    async def test_delete_nonexistent_contact_is_safe(self, storage):
        await storage.delete_contact("ghost")  # must not raise


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


class TestMessages:
    async def test_save_and_retrieve(self, storage_with_contact):
        msg = _message()
        await storage_with_contact.save_message(msg)
        msgs = await storage_with_contact.get_messages("peer1")
        assert len(msgs) == 1
        assert msgs[0].content == "hello"
        assert msgs[0].direction == "sent"

    async def test_messages_ordered_oldest_first(self, storage_with_contact):
        for ts in [3000, 1000, 2000]:
            await storage_with_contact.save_message(_message(timestamp=ts))
        timestamps = [m.timestamp for m in await storage_with_contact.get_messages("peer1")]
        assert timestamps == sorted(timestamps)

    async def test_get_messages_empty_for_unknown_peer(self, storage):
        assert await storage.get_messages("nobody") == []

    async def test_limit_returns_most_recent_visible(self, storage_with_contact):
        """limit=N must return the N most recent *visible* messages, not all rows."""
        # 8 messages that will be deleted, then 5 visible
        for i in range(8):
            await storage_with_contact.save_message(_message(timestamp=i + 1))  # +1 to avoid 0
        await storage_with_contact.delete_conversation("peer1")  # soft-delete those 8
        for i in range(10, 15):
            await storage_with_contact.save_message(_message(timestamp=i))

        msgs = await storage_with_contact.get_messages("peer1", limit=3)
        assert len(msgs) == 3
        # Should be the 3 newest visible (timestamps 12, 13, 14)
        assert [m.timestamp for m in msgs] == [12, 13, 14]

    async def test_duplicate_id_ignored(self, storage_with_contact):
        msg = _message()
        await storage_with_contact.save_message(msg)
        await storage_with_contact.save_message(msg)  # same id → INSERT OR IGNORE
        assert len(await storage_with_contact.get_messages("peer1")) == 1

    async def test_mark_delivered(self, storage_with_contact):
        msg = _message()
        await storage_with_contact.save_message(msg)
        result = await storage_with_contact.mark_delivered(msg.id)
        assert result is True
        assert (await storage_with_contact.get_messages("peer1"))[0].delivered is True

    async def test_mark_delivered_returns_false_for_nonexistent(self, storage_with_contact):
        result = await storage_with_contact.mark_delivered("ghost-id")
        assert result is False

    async def test_schema_enforces_invalid_direction(self, storage_with_contact):
        """Schema CHECK constraint must reject direction values outside the enum."""
        def _insert_bad():
            conn = storage_with_contact._c()
            with conn:
                conn.execute(
                    "INSERT INTO messages (id, peer_id, direction, content, timestamp) "
                    "VALUES ('bad1', 'peer1', 'outbound', 'hi', 1000)"
                )

        with pytest.raises(Exception):
            await storage_with_contact._run(_insert_bad)

    async def test_delete_conversation_soft_deletes(self, storage_with_contact):
        await storage_with_contact.save_message(_message())
        await storage_with_contact.delete_conversation("peer1")
        assert await storage_with_contact.get_messages("peer1") == []

    async def test_deleted_messages_visible_with_flag(self, storage_with_contact):
        await storage_with_contact.save_message(_message())
        await storage_with_contact.delete_conversation("peer1")
        msgs = await storage_with_contact.get_messages("peer1", include_deleted=True)
        assert len(msgs) == 1
        assert msgs[0].deleted is True

    async def test_received_direction_round_trip(self, storage_with_contact):
        msg = _message(direction="received", content="hi back")
        await storage_with_contact.save_message(msg)
        assert (await storage_with_contact.get_messages("peer1"))[0].direction == "received"

    async def test_purge_deleted_messages_by_peer(self, storage_with_contact):
        for i in range(5):
            await storage_with_contact.save_message(_message(timestamp=i + 1))
        await storage_with_contact.delete_conversation("peer1")  # soft-delete 5
        count = await storage_with_contact.purge_deleted_messages("peer1")
        assert count == 5
        assert await storage_with_contact.get_messages("peer1", include_deleted=True) == []

    async def test_purge_all_deleted_messages(self, storage):
        await storage.upsert_contact(_contact("p1", display_name="A"))
        await storage.upsert_contact(_contact("p2", display_name="B"))
        for i in range(3):
            await storage.save_message(_message("p1", timestamp=i + 1))
            await storage.save_message(_message("p2", timestamp=i + 1))
        await storage.delete_conversation("p1")
        count = await storage.purge_deleted_messages()  # all peers
        assert count == 3
        # p2 messages untouched
        assert len(await storage.get_messages("p2")) == 3

    async def test_concurrent_writes_are_safe(self, storage_with_contact):
        """Lock must serialize concurrent save_message calls correctly."""
        tasks = [
            storage_with_contact.save_message(_message(timestamp=i + 1))
            for i in range(50)
        ]
        await asyncio.gather(*tasks)
        msgs = await storage_with_contact.get_messages("peer1", limit=100)
        assert len(msgs) == 50

    async def test_get_messages_limit_zero_returns_empty(self, storage_with_contact):
        """get_messages(limit=0) should return an empty list."""
        await storage_with_contact.save_message(_message(timestamp=1_000_000_001))
        result = await storage_with_contact.get_messages("peer1", limit=0)
        assert result == []

    async def test_save_message_returns_true_on_insert(self, storage_with_contact):
        """save_message returns True when a new message is inserted."""
        result = await storage_with_contact.save_message(_message())
        assert result is True

    async def test_save_message_returns_false_on_duplicate(self, storage_with_contact):
        """save_message returns False when the message id already exists."""
        msg = _message()
        await storage_with_contact.save_message(msg)
        result = await storage_with_contact.save_message(msg)
        assert result is False


# ---------------------------------------------------------------------------
# Outbox
# ---------------------------------------------------------------------------


class TestOutbox:
    async def test_enqueue_and_retrieve(self, storage_with_contact):
        item = _outbox_item()
        await storage_with_contact.enqueue_outbox(item)
        items = await storage_with_contact.get_pending_outbox("peer1")
        assert len(items) == 1
        assert items[0].encrypted_blob == "blob=="
        assert items[0].signature == "sig=="

    async def test_empty_initially(self, storage_with_contact):
        assert await storage_with_contact.get_pending_outbox("peer1") == []

    async def test_mark_delivered_removes_item(self, storage_with_contact):
        item = _outbox_item()
        await storage_with_contact.enqueue_outbox(item)
        await storage_with_contact.mark_outbox_delivered(item.id)
        assert await storage_with_contact.get_pending_outbox("peer1") == []

    async def test_increment_attempts(self, storage_with_contact):
        item = _outbox_item()
        await storage_with_contact.enqueue_outbox(item)
        await storage_with_contact.increment_outbox_attempts(item.id)
        await storage_with_contact.increment_outbox_attempts(item.id)
        fetched = (await storage_with_contact.get_pending_outbox("peer1"))[0]
        assert fetched.attempts == 2
        assert fetched.last_attempt is not None

    async def test_delete_conversation_clears_outbox(self, storage_with_contact):
        await storage_with_contact.enqueue_outbox(_outbox_item())
        await storage_with_contact.delete_conversation("peer1")
        assert await storage_with_contact.get_pending_outbox("peer1") == []

    async def test_outbox_items_ordered_by_created_at(self, storage_with_contact):
        for ts in [300, 100, 200]:
            await storage_with_contact.enqueue_outbox(_outbox_item(created_at=ts))
        items = await storage_with_contact.get_pending_outbox("peer1")
        assert [i.created_at for i in items] == [100, 200, 300]

    async def test_duplicate_id_ignored(self, storage_with_contact):
        item = _outbox_item()
        await storage_with_contact.enqueue_outbox(item)
        await storage_with_contact.enqueue_outbox(item)
        assert len(await storage_with_contact.get_pending_outbox("peer1")) == 1

    async def test_message_id_round_trip(self, storage_with_contact):
        msg = _message()
        await storage_with_contact.save_message(msg)
        item = _outbox_item(message_id=msg.id)
        await storage_with_contact.enqueue_outbox(item)
        fetched = (await storage_with_contact.get_pending_outbox("peer1"))[0]
        assert fetched.message_id == msg.id

    async def test_get_all_pending_outbox_across_peers(self, storage):
        await storage.upsert_contact(_contact("p1", display_name="Alice"))
        await storage.upsert_contact(_contact("p2", display_name="Bob"))
        await storage.enqueue_outbox(_outbox_item("p1"))
        await storage.enqueue_outbox(_outbox_item("p2"))
        all_items = await storage.get_all_pending_outbox()
        assert len(all_items) == 2
        assert {i.peer_id for i in all_items} == {"p1", "p2"}

    async def test_get_all_pending_outbox_empty(self, storage):
        assert await storage.get_all_pending_outbox() == []

    async def test_get_all_pending_outbox_ordered_by_created_at(self, storage):
        await storage.upsert_contact(_contact("p1", display_name="A"))
        await storage.upsert_contact(_contact("p2", display_name="B"))
        await storage.enqueue_outbox(_outbox_item("p1", created_at=200))
        await storage.enqueue_outbox(_outbox_item("p2", created_at=100))
        items = await storage.get_all_pending_outbox()
        assert [i.created_at for i in items] == [100, 200]


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------


class TestMaintenance:
    async def test_vacuum_succeeds_and_preserves_data(self, storage_with_contact):
        msg = _message()
        await storage_with_contact.save_message(msg)
        await storage_with_contact.vacuum()
        msgs = await storage_with_contact.get_messages("peer1")
        assert len(msgs) == 1

    async def test_wipe_all_data_deletes_db(self, tmp_path):
        db = tmp_path / "messages.db"
        s = Storage(db, make_db_key())
        await s.initialize()
        await s.wipe_all_data()
        assert not db.exists()

    async def test_wipe_all_data_removes_wal_and_shm(self, tmp_path):
        """wipe_all_data must also remove the -wal and -shm sidecar files."""
        db = tmp_path / "messages.db"
        s = Storage(db, make_db_key())
        await s.initialize()
        wal = db.with_name(db.name + "-wal")
        shm = db.with_name(db.name + "-shm")
        wal.write_bytes(b"fake wal content" * 64)
        shm.write_bytes(b"fake shm content" * 64)
        await s.wipe_all_data()
        assert not db.exists()
        assert not wal.exists()
        assert not shm.exists()

    async def test_wipe_all_data_removes_extra_paths(self, tmp_path):
        db = tmp_path / "messages.db"
        extra = tmp_path / "account.json"
        extra.write_bytes(b"fake account data" * 100)
        s = Storage(db, make_db_key())
        await s.initialize()
        await s.wipe_all_data(extra_paths=[extra])
        assert not db.exists()
        assert not extra.exists()

    async def test_wipe_nonexistent_extra_path_is_safe(self, tmp_path):
        db = tmp_path / "messages.db"
        s = Storage(db, make_db_key())
        await s.initialize()
        await s.wipe_all_data(extra_paths=[tmp_path / "ghost.txt"])
        assert not db.exists()

    async def test_purge_then_vacuum_reclaims_space(self, storage_with_contact):
        for i in range(100):
            await storage_with_contact.save_message(_message(timestamp=i + 1, content="x" * 512))
        await storage_with_contact.delete_conversation("peer1")
        size_before = storage_with_contact._db_path.stat().st_size
        await storage_with_contact.purge_deleted_messages("peer1")
        await storage_with_contact.vacuum()
        size_after = storage_with_contact._db_path.stat().st_size
        assert size_after <= size_before

    async def test_vacuum_cancellation_safe(self, storage_with_contact):
        """Cancelling a task awaiting vacuum() must not corrupt the DB."""
        await storage_with_contact.save_message(_message())
        task = asyncio.ensure_future(storage_with_contact.vacuum())
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # DB must still be usable after the cancelled vacuum
        msgs = await storage_with_contact.get_messages("peer1")
        assert len(msgs) == 1


# ---------------------------------------------------------------------------
# DB key derivation
# ---------------------------------------------------------------------------


class TestDeriveDbKey:
    def test_returns_32_bytes(self):
        priv, _ = generate_ed25519_keypair()
        assert len(derive_db_key(priv)) == 32

    def test_deterministic_for_same_private_key(self):
        from p2pchat.core.crypto import ed25519_from_bytes, private_key_to_bytes

        priv, _ = generate_ed25519_keypair()
        raw = private_key_to_bytes(priv)
        priv2 = ed25519_from_bytes(raw)
        assert derive_db_key(priv) == derive_db_key(priv2)

    def test_different_keys_produce_different_db_keys(self):
        priv1, _ = generate_ed25519_keypair()
        priv2, _ = generate_ed25519_keypair()
        assert derive_db_key(priv1) != derive_db_key(priv2)


# ---------------------------------------------------------------------------
# Secure delete helper
# ---------------------------------------------------------------------------


class TestSecureDelete:
    def test_deletes_file(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_bytes(b"very secret data" * 100)
        _secure_delete(f)
        assert not f.exists()

    def test_noop_for_nonexistent_file(self, tmp_path):
        _secure_delete(tmp_path / "ghost.txt")  # must not raise

    def test_empty_file_does_not_raise(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        _secure_delete(f)
        assert not f.exists()

    @pytest.mark.skipif(os.getuid() == 0, reason="root bypasses file permissions")
    def test_readonly_file_does_not_raise(self, tmp_path):
        """_secure_delete on a read-only file must not raise an exception."""
        f = tmp_path / "readonly.bin"
        f.write_bytes(b"secret data" * 100)
        os.chmod(f, 0o444)
        _secure_delete(f)  # must not raise
