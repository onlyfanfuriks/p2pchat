"""Encrypted SQLite storage via SQLCipher.

DB file: ~/.config/p2pchat/messages.db (mode 0600)

Key derivation: call derive_db_key(account.ed25519_private) to get the
32-byte key, then pass it to Storage.__init__.  The DB is automatically
unlocked whenever the account is unlocked — no second password needed.

Thread-safety contract
----------------------
Storage uses a single SQLite connection opened with check_same_thread=False.
All operations go through asyncio.to_thread() under self._lock, which
guarantees that exactly one thread accesses the connection at a time.
Never bypass self._lock when accessing self._conn.

Degraded mode
-------------
If sqlcipher3 is not importable at startup, Storage raises ImportError.
There is no silent plaintext fallback — the caller must handle the error
and inform the user.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field
from importlib.resources import files as _resource_files
from pathlib import Path
from typing import Any, Callable, Literal, TypeVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import sqlcipher3 as _sql  # type: ignore[import-untyped]
except ImportError as _exc:
    raise ImportError(
        "sqlcipher3 is required for encrypted storage. "
        "Install it with: pip install sqlcipher3"
    ) from _exc

_T = TypeVar("_T")


def _iter_migration_paths():
    """Yield .sql migration file Traversable entries sorted by name.

    Uses importlib.resources so the package works correctly when installed
    as a wheel (zip archive), where Path(__file__).parent is not a real
    filesystem path and glob() would return nothing.
    """
    migs = _resource_files("p2pchat.core") / "migrations"
    yield from sorted(
        (e for e in migs.iterdir() if e.name.endswith(".sql")),
        key=lambda e: int(Path(e.name).stem.split("_")[0]) if Path(e.name).stem.split("_")[0].isdigit() else -1,
    )


# ---------------------------------------------------------------------------
# DB key derivation
# ---------------------------------------------------------------------------

def derive_db_key(ed25519_private: Ed25519PrivateKey) -> bytes:
    """Derive a 32-byte SQLCipher key from the account Ed25519 private key.

    Uses HKDF-SHA256 with a static info tag so the derived key is bound to
    this specific purpose and cannot be confused with the session key.
    """
    from .crypto import private_key_to_bytes

    raw = private_key_to_bytes(ed25519_private)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        # salt=None is explicitly permitted by RFC 5869 §3.1 when the IKM is
        # already a high-entropy secret (32-byte Ed25519 private key).  The
        # `info` tag provides domain separation — this key cannot be confused
        # with any other key derived from the same material.
        salt=None,
        info=b"p2pchat-v1-db-key",
    ).derive(raw)


# ---------------------------------------------------------------------------
# Row dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Contact:
    peer_id: str            # base64url(ed25519_pub)
    display_name: str
    x25519_pub: str         # base64url encoded
    trusted: bool
    added_at: int           # unix seconds
    ygg_address: str = ""
    last_seen: int | None = None


@dataclass
class Message:
    peer_id: str
    direction: Literal["sent", "received"]
    content: str            # plaintext
    timestamp: int          # unix seconds
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    delivered: bool = False
    deleted: bool = False


@dataclass
class OutboxItem:
    peer_id: str
    encrypted_blob: str     # base64url(nonce + ciphertext)
    signature: str          # base64url Ed25519 signature
    created_at: int
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    message_id: str | None = None   # correlates to Message.id for TUI ⏳ status
    attempts: int = 0
    last_attempt: int | None = None


# ---------------------------------------------------------------------------
# Row → dataclass helpers
# ---------------------------------------------------------------------------

def _to_contact(row: tuple) -> Contact:
    peer_id, display_name, ygg_address, x25519_pub, trusted, added_at, last_seen = row
    return Contact(
        peer_id=peer_id,
        display_name=display_name,
        ygg_address=ygg_address or "",
        x25519_pub=x25519_pub,
        trusted=bool(trusted),
        added_at=added_at,
        last_seen=last_seen,
    )


def _to_message(row: tuple) -> Message:
    id_, peer_id, direction, content, timestamp, delivered, deleted = row
    return Message(
        id=id_,
        peer_id=peer_id,
        direction=direction,
        content=content,
        timestamp=timestamp,
        delivered=bool(delivered),
        deleted=bool(deleted),
    )


def _to_outbox(row: tuple) -> OutboxItem:
    id_, peer_id, blob, sig, created_at, message_id, attempts, last_attempt = row
    return OutboxItem(
        id=id_,
        peer_id=peer_id,
        encrypted_blob=blob,
        signature=sig,
        created_at=created_at,
        message_id=message_id,
        attempts=attempts,
        last_attempt=last_attempt,
    )


# ---------------------------------------------------------------------------
# Migration runner
# ---------------------------------------------------------------------------

def _run_migrations(conn) -> None:
    """Apply any unapplied numbered .sql migration files atomically.

    The schema_migrations tracking table and all pending migrations are
    applied inside a single BEGIN EXCLUSIVE transaction, so concurrent
    processes cannot interleave migration steps or apply the same migration
    twice (UNIQUE constraint on version prevents double-apply).

    Migration files must be named NNN_description.sql where NNN is a
    zero-padded integer (e.g. 0001_initial.sql).  Statements are split on
    semicolons; comment-only lines are skipped.

    IMPORTANT: Migration SQL files must never contain semicolons inside
    string literals, trigger bodies, or comments — the splitter is naive.
    See the comment at the top of migrations/0001_initial.sql for details.
    """
    # Switch to autocommit so we control transactions explicitly.
    orig_isolation = conn.isolation_level
    conn.isolation_level = None

    try:
        # Acquire exclusive lock first, then create the tracking table inside
        # the transaction.  This eliminates the TOCTOU window where two
        # processes could both see an empty schema_migrations and both try to
        # apply migration 1.
        conn.execute("BEGIN EXCLUSIVE")
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)"
            )

            applied = {
                r[0]
                for r in conn.execute(
                    "SELECT version FROM schema_migrations"
                ).fetchall()
            }

            for entry in _iter_migration_paths():
                try:
                    version = int(Path(entry.name).stem.split("_")[0])
                except (ValueError, IndexError):
                    continue
                if version in applied:
                    continue

                sql = entry.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
                for stmt in sql.split(";"):
                    stmt = stmt.strip()
                    if stmt and not all(
                        ln.startswith("--") for ln in stmt.splitlines() if ln.strip()
                    ):
                        conn.execute(stmt)

                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, int(time.time())),
                )

            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass  # don't mask the original migration error
            raise
    finally:
        conn.isolation_level = orig_isolation


# ---------------------------------------------------------------------------
# Storage class
# ---------------------------------------------------------------------------

class Storage:
    """Async interface to the encrypted local SQLite database.

    Usage::

        storage = Storage(db_path, db_key)
        await storage.initialize()
        ...
        await storage.close()

    Thread-safety: all operations acquire self._lock before dispatching to
    a thread-pool worker via asyncio.to_thread().  Never access self._conn
    outside of _run() or methods that hold the lock.
    """

    def __init__(self, db_path: Path, db_key: bytes) -> None:
        self._db_path = db_path
        self._db_key = db_key
        self._conn = None
        self._lock = asyncio.Lock()

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def initialize(self) -> None:
        """Open DB and apply migrations.  Safe to call multiple times."""
        async with self._lock:
            if self._conn is None:
                await asyncio.to_thread(self._sync_open)

    def _sync_open(self) -> None:
        """Synchronous DB open — must be called from a thread-pool worker."""
        # SEC: create the config dir at 0700 so other users cannot list contents.
        self._db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        dirfd = os.open(str(self._db_path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(dirfd, 0o700)
        finally:
            os.close(dirfd)

        # SEC: pre-create the file at 0600 before SQLCipher touches it,
        # eliminating the window where the file exists at default umask (0644).
        try:
            fd = os.open(str(self._db_path),
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except FileExistsError:
            fd = os.open(str(self._db_path), os.O_WRONLY | os.O_NOFOLLOW)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)

        conn: Any = _sql.connect(str(self._db_path), check_same_thread=False)

        # SEC: wrap PRAGMA key so the hex key never appears in tracebacks.
        # (The key is in the SQL string; 'from None' suppresses the chain.)
        try:
            _key_pragma = f"PRAGMA key=\"x'{self._db_key.hex()}'\""
            conn.execute(_key_pragma)
            del _key_pragma
        except Exception:
            conn.close()
            raise RuntimeError(
                "Failed to set the database encryption key. "
                "Ensure sqlcipher3 is correctly installed."
            ) from None

        try:
            row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
            if row is None or row[0] != "wal":
                conn.close()
                raise RuntimeError(
                    "Failed to enable WAL journal mode. "
                    "The database may be on a network filesystem or read-only mount."
                )
            conn.execute("PRAGMA foreign_keys=ON")
            _run_migrations(conn)
        except Exception:
            # Distinguish wrong-key from other errors for a clearer message.
            conn.close()
            raise

        self._conn = conn

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                conn, self._conn = self._conn, None
                await asyncio.to_thread(conn.close)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _c(self) -> Any:
        """Return the active SQLCipher connection, or raise if not initialized."""
        if self._conn is None:
            raise RuntimeError("Storage not initialized; call initialize() first")
        return self._conn

    async def _run(self, fn: "Callable[[], _T]") -> "_T":
        """Run a synchronous DB function serialised under the asyncio lock."""
        async with self._lock:
            return await asyncio.to_thread(fn)

    async def get_schema_version(self) -> int:
        """Return the highest applied migration version, or 0 if none."""
        def _fn():
            row = self._c().execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
            return row[0] or 0

        return await self._run(_fn)

    # -----------------------------------------------------------------------
    # Account table
    # -----------------------------------------------------------------------

    async def upsert_account(self, user_id: str, display_name: str, created_at: int) -> None:
        def _fn():
            conn = self._c()
            with conn:
                conn.execute(
                    "INSERT INTO account (id, user_id, display_name, created_at) "
                    "VALUES (1, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET "
                    "user_id=excluded.user_id, display_name=excluded.display_name",
                    (user_id, display_name, created_at),
                )

        await self._run(_fn)

    async def get_account(self) -> tuple[str, str, int] | None:
        """Return (user_id, display_name, created_at) or None."""
        def _fn():
            return self._c().execute(
                "SELECT user_id, display_name, created_at FROM account WHERE id = 1"
            ).fetchone()

        return await self._run(_fn)

    # -----------------------------------------------------------------------
    # Contacts
    # -----------------------------------------------------------------------

    async def upsert_contact(self, contact: Contact) -> None:
        def _fn():
            conn = self._c()
            with conn:
                conn.execute(
                    "INSERT INTO contacts "
                    "(peer_id, display_name, ygg_address, x25519_pub, trusted, added_at, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(peer_id) DO UPDATE SET "
                    "display_name=excluded.display_name, "
                    "ygg_address=excluded.ygg_address, "
                    "x25519_pub=excluded.x25519_pub, "
                    # SEC: trust is monotonically increasing (TOFU model).
                    # upsert_contact cannot downgrade a manually-trusted contact.
                    "trusted=MAX(contacts.trusted, excluded.trusted), "
                    "last_seen=excluded.last_seen",
                    (
                        contact.peer_id,
                        contact.display_name,
                        contact.ygg_address or None,
                        contact.x25519_pub,
                        int(contact.trusted),
                        contact.added_at,
                        contact.last_seen,
                    ),
                )

        await self._run(_fn)

    async def get_contact(self, peer_id: str) -> Contact | None:
        def _fn():
            return self._c().execute(
                "SELECT peer_id, display_name, ygg_address, x25519_pub, "
                "trusted, added_at, last_seen FROM contacts WHERE peer_id = ?",
                (peer_id,),
            ).fetchone()

        row = await self._run(_fn)
        return _to_contact(row) if row else None

    async def list_contacts(self) -> list[Contact]:
        def _fn():
            return self._c().execute(
                "SELECT peer_id, display_name, ygg_address, x25519_pub, "
                "trusted, added_at, last_seen FROM contacts ORDER BY display_name"
            ).fetchall()

        return [_to_contact(r) for r in await self._run(_fn)]

    async def trust_contact(self, peer_id: str) -> bool:
        """Set trusted=1 for peer_id.  Returns True if a row was updated."""
        def _fn():
            conn = self._c()
            with conn:
                cur = conn.execute(
                    "UPDATE contacts SET trusted = 1 WHERE peer_id = ?", (peer_id,)
                )
                return cur.rowcount > 0

        return await self._run(_fn)

    async def update_last_seen(self, peer_id: str, ts: int | None = None) -> None:
        if ts is None:
            ts = int(time.time())

        def _fn():
            conn = self._c()
            with conn:
                conn.execute(
                    "UPDATE contacts SET last_seen = ? WHERE peer_id = ?", (ts, peer_id)
                )

        await self._run(_fn)

    async def delete_contact(self, peer_id: str) -> None:
        """Delete contact and all associated messages and outbox entries.

        ON DELETE CASCADE in the schema handles messages and outbox automatically.
        """
        def _fn():
            conn = self._c()
            with conn:
                conn.execute("DELETE FROM contacts WHERE peer_id = ?", (peer_id,))

        await self._run(_fn)

    # -----------------------------------------------------------------------
    # Messages
    # -----------------------------------------------------------------------

    async def save_message(self, message: Message) -> bool:
        """Save a message. Returns True if inserted, False if already existed."""
        def _fn() -> bool:
            conn = self._c()
            with conn:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO messages "
                    "(id, peer_id, direction, content, timestamp, delivered, deleted) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        message.id,
                        message.peer_id,
                        message.direction,
                        message.content,
                        message.timestamp,
                        int(message.delivered),
                        int(message.deleted),
                    ),
                )
                return cur.rowcount > 0
        return await self._run(_fn)

    async def get_messages(
        self,
        peer_id: str,
        limit: int = 100,
        include_deleted: bool = False,
    ) -> list[Message]:
        """Return up to *limit* most recent messages, oldest-first.

        The LIMIT is applied after the deleted filter so callers always get
        up to *limit* visible messages, not up to *limit* rows that may be
        mostly deleted.
        """
        def _fn():
            if include_deleted:
                sql = (
                    "SELECT id, peer_id, direction, content, timestamp, delivered, deleted "
                    "FROM messages WHERE peer_id = ? "
                    "ORDER BY timestamp DESC LIMIT ?"
                )
            else:
                sql = (
                    "SELECT id, peer_id, direction, content, timestamp, delivered, deleted "
                    "FROM messages WHERE peer_id = ? AND deleted = 0 "
                    "ORDER BY timestamp DESC LIMIT ?"
                )
            rows = self._c().execute(sql, (peer_id, limit)).fetchall()
            return list(reversed(rows))

        return [_to_message(r) for r in await self._run(_fn)]

    async def mark_delivered(self, message_id: str) -> bool:
        """Mark message as delivered.  Returns True if a row was updated."""
        def _fn():
            conn = self._c()
            with conn:
                cur = conn.execute(
                    "UPDATE messages SET delivered = 1 WHERE id = ?", (message_id,)
                )
                return cur.rowcount > 0

        return await self._run(_fn)

    async def mark_all_delivered(self, peer_id: str) -> int:
        """Mark all undelivered sent messages to a peer as delivered.

        Returns the number of rows updated.
        """
        def _fn():
            conn = self._c()
            with conn:
                cur = conn.execute(
                    "UPDATE messages SET delivered = 1 "
                    "WHERE peer_id = ? AND direction = 'sent' "
                    "AND delivered = 0 AND deleted = 0",
                    (peer_id,),
                )
                return cur.rowcount

        return await self._run(_fn)

    async def delete_conversation(self, peer_id: str) -> None:
        """Soft-delete all messages with peer and purge their outbox entries."""
        def _fn():
            conn = self._c()
            with conn:
                conn.execute(
                    "UPDATE messages SET deleted = 1 WHERE peer_id = ?", (peer_id,)
                )
                conn.execute("DELETE FROM outbox WHERE peer_id = ?", (peer_id,))

        await self._run(_fn)

    async def purge_deleted_messages(self, peer_id: str | None = None) -> int:
        """Permanently DELETE soft-deleted messages from the database.

        Pass *peer_id* to limit to one conversation; omit to purge all.
        Returns the number of rows deleted.  Call vacuum() afterwards to
        reclaim disk space.
        """
        def _fn():
            conn = self._c()
            with conn:
                if peer_id is not None:
                    cur = conn.execute(
                        "DELETE FROM messages WHERE deleted = 1 AND peer_id = ?",
                        (peer_id,),
                    )
                else:
                    cur = conn.execute("DELETE FROM messages WHERE deleted = 1")
                return cur.rowcount  # inside the with-block while cursor is valid

        return await self._run(_fn)

    # -----------------------------------------------------------------------
    # Outbox
    # -----------------------------------------------------------------------

    async def enqueue_outbox(self, item: OutboxItem) -> None:
        def _fn():
            conn = self._c()
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO outbox "
                    "(id, peer_id, encrypted_blob, signature, created_at, "
                    " message_id, attempts, last_attempt) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        item.id,
                        item.peer_id,
                        item.encrypted_blob,
                        item.signature,
                        item.created_at,
                        item.message_id,
                        item.attempts,
                        item.last_attempt,
                    ),
                )

        await self._run(_fn)

    async def get_pending_outbox(self, peer_id: str) -> list[OutboxItem]:
        def _fn():
            return self._c().execute(
                "SELECT id, peer_id, encrypted_blob, signature, created_at, "
                "message_id, attempts, last_attempt "
                "FROM outbox WHERE peer_id = ? ORDER BY created_at",
                (peer_id,),
            ).fetchall()

        return [_to_outbox(r) for r in await self._run(_fn)]

    async def get_all_pending_outbox(self) -> list[OutboxItem]:
        """Return all pending outbox items across all peers, ordered by created_at.

        Used at startup (Phase 5) to find every peer that has queued messages
        so a retry task can be scheduled for each.
        """
        def _fn():
            return self._c().execute(
                "SELECT id, peer_id, encrypted_blob, signature, created_at, "
                "message_id, attempts, last_attempt "
                "FROM outbox ORDER BY created_at"
            ).fetchall()

        return [_to_outbox(r) for r in await self._run(_fn)]

    async def mark_outbox_delivered(self, item_id: str) -> bool:
        """Remove delivered item from outbox.  Returns True if a row was deleted."""
        def _fn():
            conn = self._c()
            with conn:
                cur = conn.execute("DELETE FROM outbox WHERE id = ?", (item_id,))
                return cur.rowcount > 0

        return await self._run(_fn)

    async def increment_outbox_attempts(self, item_id: str) -> bool:
        """Increment attempt counter.  Returns True if a row was updated."""
        def _fn():
            conn = self._c()
            with conn:
                cur = conn.execute(
                    "UPDATE outbox SET attempts = attempts + 1, last_attempt = ? "
                    "WHERE id = ?",
                    (int(time.time()), item_id),
                )
                return cur.rowcount > 0

        return await self._run(_fn)

    # -----------------------------------------------------------------------
    # Maintenance
    # -----------------------------------------------------------------------

    async def vacuum(self) -> None:
        """VACUUM to reclaim space and remove deleted record fragments.

        VACUUM cannot run inside a transaction, so we switch temporarily to
        autocommit mode (isolation_level=None) for the duration.

        asyncio.shield() prevents cancellation from propagating to the thread
        while VACUUM is running.  Cancelling a VACUUM mid-flight would release
        self._lock while the thread still holds the connection, allowing a
        subsequent _run() to access self._conn concurrently.
        """
        def _fn():
            conn = self._c()
            orig = conn.isolation_level
            conn.isolation_level = None
            try:
                conn.execute("VACUUM")
            finally:
                conn.isolation_level = orig

        async with self._lock:
            task = asyncio.ensure_future(asyncio.to_thread(_fn))
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                await task  # wait for thread before releasing lock
                raise

    async def wipe_all_data(self, extra_paths: list[Path] | None = None) -> None:
        """Overwrite the DB with random bytes then delete it.

        Also wipes the WAL (-wal) and shared-memory (-shm) sidecar files that
        SQLite creates in WAL mode.  Pass *extra_paths* to also wipe additional
        files (account.json, TLS certs, etc.).

        Note: on SSDs and copy-on-write filesystems (btrfs, APFS) the
        overwrite may not reach the physical storage due to wear-leveling or
        CoW semantics.  This is a best-effort defence, not a cryptographic
        guarantee.
        """
        await self.close()
        db = self._db_path
        _extra = list(extra_paths or [])

        def _do_wipe():
            for suffix in ("", "-wal", "-shm"):
                _secure_delete(db.with_name(db.name + suffix))
            for path in _extra:
                _secure_delete(path)

        await asyncio.to_thread(_do_wipe)


def _secure_delete(path: Path) -> None:
    """Overwrite file contents with random bytes using O_NOFOLLOW, then unlink.

    O_NOFOLLOW prevents a symlink-swap attack between path.exists() and open().
    If the file cannot be opened for overwrite (read-only, symlink, missing),
    the exception is swallowed and the unlink is still attempted where possible.
    """
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    except OSError:
        # Can't overwrite (symlink ELOOP, read-only EACCES, etc.) — still remove entry.
        path.unlink(missing_ok=True)
        return
    try:
        size = os.fstat(fd).st_size
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(max(size, 1)))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)
