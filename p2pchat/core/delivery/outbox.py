"""Offline message queue with retry logic.

Pre-encrypts messages with the recipient's long-term X25519 public key
and stores them in the database. When the peer comes online, drains
pending messages through the active session.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
from typing import TYPE_CHECKING, Awaitable, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from p2pchat.core.crypto import (
    decode_public_key,
    decrypt_message,
    derive_session_key,
    encrypt_message,
    private_key_to_bytes,
)
from p2pchat.core.storage import OutboxItem, Storage

if TYPE_CHECKING:
    from p2pchat.core.account import Account
    from p2pchat.core.network.session import PeerSession

log = logging.getLogger(__name__)

# Exponential backoff schedule in seconds.
_BACKOFF_SCHEDULE = (30, 60, 120, 300, 600)

# Domain-separated HKDF info tag for outbox pre-encryption keys.
# Distinct from session keys to prevent cross-domain key reuse.
_HKDF_OUTBOX_INFO = b"p2pchat-v1-outbox-key"

# HKDF info tag for self-encryption when peer's X25519 key is unavailable.
_HKDF_SELF_INFO = b"p2pchat-v1-outbox-self-key"

# Sentinel value in the signature field marking a self-encrypted item.
_SELF_SIG = "self"


def _derive_self_key(account: Account) -> bytes:
    """Derive symmetric key for outbox self-encryption (no peer key needed).

    Uses the account's Ed25519 private key with a distinct HKDF info tag.
    """
    raw = private_key_to_bytes(account.ed25519_private)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_SELF_INFO,
    ).derive(raw)


def _derive_outbox_key(
    account: Account,
    their_x25519_pub: bytes,
    their_ed25519_pub: bytes,
) -> bytes:
    """Derive static key for outbox pre-encryption using long-term X25519 keys.

    Uses HKDF with a distinct info tag from session keys. The derived key is
    deterministic (same for every message to the same peer) so correctness
    depends on unique nonces generated per message in encrypt_message.
    """
    return derive_session_key(
        account.x25519_private,
        their_x25519_pub,
        account.ed25519_public,
        their_ed25519_pub,
        info_tag=_HKDF_OUTBOX_INFO,
    )


class Outbox:
    """Persists unsent messages. Retries delivery when peer comes online."""

    def __init__(self, account: Account, storage: Storage) -> None:
        self._account = account
        self._storage = storage
        self._retry_tasks: dict[str, asyncio.Task] = {}
        self._draining: set[str] = set()

    async def enqueue(
        self,
        to_id: str,
        plaintext: str,
        message_id: str | None = None,
    ) -> str:
        """Store message in outbox for later delivery. Returns outbox item id.

        If the peer's X25519 key is available, the message is pre-encrypted.
        Otherwise plaintext is stored directly (the DB is SQLCipher-encrypted
        at rest). Plaintext items are sent through the session on drain, which
        encrypts with the ephemeral session key.

        Parameters
        ----------
        to_id:
            Peer ID (base64url Ed25519 public key).
        plaintext:
            Message content to store.
        message_id:
            Optional link to the Message row for TUI delivery status.

        Raises
        ------
        ValueError
            If the contact is unknown (not in DB).
        """
        contact = await self._storage.get_contact(to_id)
        if contact is None:
            raise ValueError(f"Unknown contact: {to_id}")

        if contact.x25519_pub:
            their_x25519_pub = decode_public_key(contact.x25519_pub)
            their_ed25519_pub = decode_public_key(to_id)
            static_key = _derive_outbox_key(
                self._account, their_x25519_pub, their_ed25519_pub,
            )
            enc = encrypt_message(static_key, plaintext, self._account.ed25519_private)
            blob = base64.urlsafe_b64encode(enc.nonce + enc.ciphertext).decode()
            sig = base64.urlsafe_b64encode(enc.signature).decode()
        else:
            # No X25519 key yet — self-encrypt with account key.
            self_key = _derive_self_key(self._account)
            nonce = os.urandom(12)
            ct = AESGCM(self_key).encrypt(nonce, plaintext.encode(), None)
            blob = base64.urlsafe_b64encode(nonce + ct).decode()
            sig = _SELF_SIG

        item = OutboxItem(
            peer_id=to_id,
            encrypted_blob=blob,
            signature=sig,
            created_at=int(time.time()),
            message_id=message_id,
        )
        await self._storage.enqueue_outbox(item)
        return item.id

    async def drain(self, session: PeerSession) -> int:
        """Send all pending messages for session's peer. Returns count sent.

        Items with a signature are pre-encrypted and get decrypted first.
        Items with an empty signature are stored plaintext (x25519 key was
        unavailable at enqueue time) and are sent directly through the
        session, which encrypts with the ephemeral session key.

        Concurrent drains for the same peer are prevented via a guard set.
        """
        peer_id = session.peer_id
        if peer_id in self._draining:
            return 0

        self._draining.add(peer_id)
        try:
            items = await self._storage.get_pending_outbox(peer_id)
            if not items:
                return 0

            contact = await self._storage.get_contact(peer_id)
            if contact is None:
                return 0

            # Derive static key for encrypted items (if key is available).
            static_key: bytes | None = None
            if contact.x25519_pub:
                their_x25519_pub = decode_public_key(contact.x25519_pub)
                their_ed25519_pub = decode_public_key(peer_id)
                static_key = _derive_outbox_key(
                    self._account, their_x25519_pub, their_ed25519_pub,
                )

            sent = 0
            for item in items:
                try:
                    if item.signature == _SELF_SIG:
                        # Self-encrypted — decrypt with account key.
                        plaintext = self._decrypt_self_item(item)
                    elif not item.signature:
                        # Legacy plaintext item — send directly.
                        plaintext = item.encrypted_blob
                    elif static_key is not None:
                        plaintext = self._decrypt_item(item, static_key)
                    else:
                        # Encrypted but key unavailable — skip for now.
                        log.warning(
                            "Cannot decrypt outbox item %s — key not available",
                            item.id,
                        )
                        continue
                except Exception:
                    log.error(
                        "Corrupt outbox item %s — skipping", item.id,
                    )
                    await self._storage.mark_outbox_delivered(item.id)
                    continue

                try:
                    await session.send_message(plaintext)
                    await self._storage.mark_outbox_delivered(item.id)
                    if item.message_id:
                        await self._storage.mark_delivered(item.message_id)
                    sent += 1
                except Exception:
                    log.warning(
                        "Failed to send outbox item %s for %s",
                        item.id, peer_id,
                    )
                    await self._storage.increment_outbox_attempts(item.id)
                    break  # Connection likely dead — stop sending.
            return sent
        finally:
            self._draining.discard(peer_id)

    def _decrypt_self_item(self, item: OutboxItem) -> str:
        """Decrypt a self-encrypted outbox item using the account key."""
        self_key = _derive_self_key(self._account)
        blob_bytes = base64.urlsafe_b64decode(item.encrypted_blob)
        nonce = blob_bytes[:12]
        ciphertext = blob_bytes[12:]
        return AESGCM(self_key).decrypt(nonce, ciphertext, None).decode()

    def _decrypt_item(self, item: OutboxItem, static_key: bytes) -> str:
        """Decrypt a pre-encrypted outbox item to recover plaintext."""
        blob_bytes = base64.urlsafe_b64decode(item.encrypted_blob)
        nonce = blob_bytes[:12]
        ciphertext = blob_bytes[12:]
        sig_bytes = base64.urlsafe_b64decode(item.signature)

        return decrypt_message(
            static_key,
            nonce,
            ciphertext,
            sig_bytes,
            self._account.ed25519_public,
        )

    async def retry_loop(
        self,
        peer_id: str,
        connect_fn: Callable[[str], Awaitable[PeerSession]],
    ) -> None:
        """Background task: attempt to connect and drain with exponential backoff.

        Backoff schedule: 30s, 60s, 120s, 300s, 600s (max).
        Exits when no pending items remain. Connects first, then sleeps
        on failure — so the first delivery attempt is immediate.
        """
        attempt = 0
        while True:
            items = await self._storage.get_pending_outbox(peer_id)
            if not items:
                return

            try:
                session = await connect_fn(peer_id)
                sent = await self.drain(session)
                if sent > 0:
                    attempt = 0
                    continue  # Re-check immediately for more items.
                attempt += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                log.debug(
                    "Retry connect to %s failed (attempt %d)", peer_id, attempt + 1,
                )
                attempt += 1

            delay = _BACKOFF_SCHEDULE[min(attempt - 1, len(_BACKOFF_SCHEDULE) - 1)]
            await asyncio.sleep(delay)

    def start_retry(
        self,
        peer_id: str,
        connect_fn: Callable[[str], Awaitable[PeerSession]],
    ) -> None:
        """Start a retry loop for a peer if not already running."""
        existing = self._retry_tasks.get(peer_id)
        if existing and not existing.done():
            return
        task = asyncio.create_task(
            self.retry_loop(peer_id, connect_fn),
            name=f"outbox-retry-{peer_id[:8]}",
        )
        self._retry_tasks[peer_id] = task

    def cancel_retry(self, peer_id: str) -> None:
        """Cancel retry loop for a peer (e.g. when they come online)."""
        task = self._retry_tasks.pop(peer_id, None)
        if task and not task.done():
            task.cancel()

    async def stop(self) -> None:
        """Cancel all retry tasks for clean shutdown."""
        tasks = list(self._retry_tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._retry_tasks.clear()
