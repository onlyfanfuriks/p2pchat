"""Tests for p2pchat.core.network.peer — outgoing TLS client connection."""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from p2pchat.core.account import Account
from p2pchat.core.crypto import generate_ed25519_keypair, generate_x25519_keypair
from p2pchat.core.network.peer import connect
from p2pchat.core.storage import Storage, derive_db_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_account(display_name: str = "Alice") -> Account:
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
# TestConnectValidation
# ---------------------------------------------------------------------------

class TestConnectValidation:
    async def test_invalid_ipv6_raises_value_error(self, tmp_path):
        """N-18: connect() validates IPv6 address before attempting connection."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        with pytest.raises(ValueError, match="Invalid peer IPv6"):
            await connect(
                ygg_address="not-an-ipv6-address",
                port=7331,
                account=account,
                storage=storage,
                config_dir=tmp_path,
            )

    async def test_strips_brackets_from_address(self, tmp_path):
        """connect() strips brackets from IPv6 addresses."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        # Should not raise ValueError on bracket-wrapped valid IPv6.
        # Will fail at connection stage, not validation.
        with pytest.raises((OSError, asyncio.TimeoutError)):
            await connect(
                ygg_address="[200:abcd::1]",
                port=7331,
                account=account,
                storage=storage,
                config_dir=tmp_path,
                timeout=0.1,
            )

    async def test_empty_address_raises(self, tmp_path):
        """Empty address string raises ValueError."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        with pytest.raises(ValueError):
            await connect(
                ygg_address="",
                port=7331,
                account=account,
                storage=storage,
                config_dir=tmp_path,
            )

    async def test_ipv4_address_rejected(self, tmp_path):
        """IPv4 addresses are rejected (we require IPv6)."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        with pytest.raises(ValueError, match="Invalid peer IPv6"):
            await connect(
                ygg_address="192.168.1.1",
                port=7331,
                account=account,
                storage=storage,
                config_dir=tmp_path,
            )


# ---------------------------------------------------------------------------
# TestConnectTlsConfig
# ---------------------------------------------------------------------------

class TestConnectTlsConfig:
    async def test_tls_minimum_version(self, tmp_path):
        """N-05: TLS context enforces minimum TLS 1.2."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        created_contexts = []

        async def _capture_ctx(*args, **kwargs):
            if "ssl" in kwargs and isinstance(kwargs["ssl"], ssl.SSLContext):
                created_contexts.append(kwargs["ssl"])
            raise OSError("mock: not connecting")

        with patch("p2pchat.core.network.peer.asyncio.open_connection", _capture_ctx):
            with pytest.raises(OSError):
                await connect(
                    ygg_address="200:abcd::1",
                    port=7331,
                    account=account,
                    storage=storage,
                    config_dir=tmp_path,
                )

        assert len(created_contexts) == 1
        ctx = created_contexts[0]
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.options & ssl.OP_NO_COMPRESSION
        assert ctx.options & ssl.OP_NO_TICKET
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE


# ---------------------------------------------------------------------------
# TestConnectTimeout
# ---------------------------------------------------------------------------

class TestConnectTimeout:
    async def test_connection_timeout_raises(self, tmp_path):
        """Connection timeout raises asyncio.TimeoutError with clear message."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async def _slow_connect(*args, **kwargs):
            await asyncio.sleep(999)

        with patch("p2pchat.core.network.peer.asyncio.open_connection", _slow_connect):
            with pytest.raises(asyncio.TimeoutError, match="timed out"):
                await connect(
                    ygg_address="200:abcd::1",
                    port=7331,
                    account=account,
                    storage=storage,
                    config_dir=tmp_path,
                    timeout=0.1,
                )

    async def test_handshake_timeout_uses_remaining_budget(self, tmp_path):
        """N-21: Handshake timeout uses remaining time budget, not full timeout."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        writer.get_extra_info = MagicMock(return_value=("::1", 7331))

        handshake_timeouts = []
        original_wait_for = asyncio.wait_for

        async def _fast_connect(*args, **kwargs):
            # Simulate slow connection consuming some budget.
            await asyncio.sleep(0.05)
            return reader, writer

        async def _capture_wait_for(coro, timeout):
            handshake_timeouts.append(timeout)
            raise asyncio.TimeoutError("mock handshake timeout")

        with patch("p2pchat.core.network.peer.asyncio.open_connection", _fast_connect):
            with patch("p2pchat.core.network.peer.PeerSession") as MockSession:
                instance = MockSession.return_value
                instance.handshake = AsyncMock()
                instance.close = AsyncMock()
                # Patch only the second wait_for (handshake), not the first (connect).
                call_count = 0

                async def _selective_wait_for(coro, timeout):
                    nonlocal call_count
                    call_count += 1
                    if call_count == 1:
                        # Let the connection succeed.
                        return await original_wait_for(coro, timeout=timeout)
                    else:
                        # Capture the handshake timeout.
                        handshake_timeouts.append(timeout)
                        raise asyncio.TimeoutError("mock handshake timeout")

                with patch("p2pchat.core.network.peer.asyncio.wait_for", _selective_wait_for):
                    with pytest.raises(asyncio.TimeoutError):
                        await connect(
                            ygg_address="200:abcd::1",
                            port=7331,
                            account=account,
                            storage=storage,
                            config_dir=tmp_path,
                            timeout=1.0,
                        )

        # Handshake timeout should be less than the original 1.0s budget
        # because some time was consumed by the connection.
        assert len(handshake_timeouts) == 1
        assert handshake_timeouts[0] < 1.0

    async def test_handshake_failure_closes_session(self, tmp_path):
        """Session is closed if handshake fails with a non-timeout exception."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        async def _instant_connect(*args, **kwargs):
            return reader, writer

        with patch("p2pchat.core.network.peer.asyncio.open_connection", _instant_connect):
            with patch("p2pchat.core.network.peer.PeerSession") as MockSession:
                instance = MockSession.return_value
                instance.handshake = AsyncMock(side_effect=ValueError("bad handshake"))
                instance.close = AsyncMock()

                with pytest.raises(ValueError, match="bad handshake"):
                    await connect(
                        ygg_address="200:abcd::1",
                        port=7331,
                        account=account,
                        storage=storage,
                        config_dir=tmp_path,
                    )

                instance.close.assert_called_once()

    async def test_os_error_propagated(self, tmp_path):
        """OSError from connection is re-raised with context."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async def _fail_connect(*args, **kwargs):
            raise OSError("Connection refused")

        with patch("p2pchat.core.network.peer.asyncio.open_connection", _fail_connect):
            with pytest.raises(OSError, match="Cannot connect"):
                await connect(
                    ygg_address="200:abcd::1",
                    port=7331,
                    account=account,
                    storage=storage,
                    config_dir=tmp_path,
                )
