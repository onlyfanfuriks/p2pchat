"""Tests for p2pchat.core.network.server — TLS cert generation and ChatServer."""

from __future__ import annotations

import asyncio
import datetime
import os
import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from p2pchat.core.account import Account
from p2pchat.core.crypto import generate_ed25519_keypair, generate_x25519_keypair
from p2pchat.core.network.server import (
    PORT,
    ChatServer,
    _MAX_CONNECTIONS,
    generate_tls_cert,
)
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
# TestGenerateTlsCert
# ---------------------------------------------------------------------------

class TestGenerateTlsCert:
    def test_creates_cert_and_key_files(self, tmp_path):
        """generate_tls_cert creates tls.crt and tls.key files."""
        cert_path, key_path = generate_tls_cert(tmp_path)
        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path.name == "tls.crt"
        assert key_path.name == "tls.key"

    def test_files_have_0600_permissions(self, tmp_path):
        """N-19: Generated cert/key files have 0600 permissions."""
        cert_path, key_path = generate_tls_cert(tmp_path)
        for path in (cert_path, key_path):
            mode = stat.S_IMODE(os.stat(path).st_mode)
            assert mode == 0o600, f"{path.name} has mode {oct(mode)}"

    def test_cert_is_valid_x509(self, tmp_path):
        """Generated certificate is a valid X.509 cert."""
        cert_path, _ = generate_tls_cert(tmp_path)
        cert_pem = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "p2pchat"

    def test_key_is_valid_rsa(self, tmp_path):
        """Generated key is a loadable RSA private key."""
        _, key_path = generate_tls_cert(tmp_path)
        key_pem = key_path.read_bytes()
        key = serialization.load_pem_private_key(key_pem, password=None)
        assert key.key_size == 2048

    def test_cert_validity_one_year(self, tmp_path):
        """N-50: Certificate validity is approximately 1 year."""
        cert_path, _ = generate_tls_cert(tmp_path)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 364 <= delta.days <= 366

    def test_cert_and_key_match(self, tmp_path):
        """Certificate and key form a valid pair (loadable by SSLContext)."""
        import ssl
        cert_path, key_path = generate_tls_cert(tmp_path)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # This raises if cert/key don't match.
        ctx.load_cert_chain(str(cert_path), str(key_path))

    def test_creates_config_dir_if_absent(self, tmp_path):
        """generate_tls_cert creates the config directory if it doesn't exist."""
        new_dir = tmp_path / "subdir" / "certs"
        cert_path, key_path = generate_tls_cert(new_dir)
        assert new_dir.exists()
        assert cert_path.exists()

    def test_no_tmp_files_remain(self, tmp_path):
        """N-43: No .tmp files remain after successful generation."""
        generate_tls_cert(tmp_path)
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []

    def test_overwrites_existing_files(self, tmp_path):
        """Calling generate_tls_cert twice overwrites the files."""
        cert1, key1 = generate_tls_cert(tmp_path)
        content1 = cert1.read_bytes()
        cert2, key2 = generate_tls_cert(tmp_path)
        content2 = cert2.read_bytes()
        # Different serial numbers → different content.
        assert content1 != content2


# ---------------------------------------------------------------------------
# TestBuildSslContext
# ---------------------------------------------------------------------------

class TestBuildSslContext:
    def test_returns_ssl_context(self, tmp_path):
        """_build_ssl_context returns a configured SSLContext."""
        import ssl
        cert_path, key_path = generate_tls_cert(tmp_path)
        ctx = ChatServer._build_ssl_context(cert_path, key_path)
        assert isinstance(ctx, ssl.SSLContext)

    def test_minimum_tls_1_2(self, tmp_path):
        """N-05: Server context enforces TLS 1.2 minimum."""
        import ssl
        cert_path, key_path = generate_tls_cert(tmp_path)
        ctx = ChatServer._build_ssl_context(cert_path, key_path)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_compression_disabled(self, tmp_path):
        """N-16: TLS compression is disabled."""
        import ssl
        cert_path, key_path = generate_tls_cert(tmp_path)
        ctx = ChatServer._build_ssl_context(cert_path, key_path)
        assert ctx.options & ssl.OP_NO_COMPRESSION

    def test_tickets_disabled(self, tmp_path):
        """N-16: TLS session tickets are disabled."""
        import ssl
        cert_path, key_path = generate_tls_cert(tmp_path)
        ctx = ChatServer._build_ssl_context(cert_path, key_path)
        assert ctx.options & ssl.OP_NO_TICKET


# ---------------------------------------------------------------------------
# TestGetOrCreateCert
# ---------------------------------------------------------------------------

class TestGetOrCreateCert:
    async def test_generates_cert_when_none_exists(self, tmp_path):
        """Creates new cert/key when none exist."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )
        cert_path, key_path = server._get_or_create_cert()
        assert cert_path.exists()
        assert key_path.exists()

    async def test_reuses_existing_valid_cert(self, tmp_path):
        """Returns existing cert/key if still valid."""
        generate_tls_cert(tmp_path)
        original_cert = (tmp_path / "tls.crt").read_bytes()

        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )
        cert_path, _ = server._get_or_create_cert()
        assert cert_path.read_bytes() == original_cert

    async def test_regenerates_corrupt_cert(self, tmp_path):
        """N-39: Regenerates cert if existing one is corrupt."""
        # Write garbage cert/key.
        (tmp_path / "tls.crt").write_bytes(b"not a cert")
        (tmp_path / "tls.key").write_bytes(b"not a key")

        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )
        cert_path, key_path = server._get_or_create_cert()
        # Should have regenerated valid files.
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "p2pchat"


# ---------------------------------------------------------------------------
# TestChatServerInit
# ---------------------------------------------------------------------------

class TestChatServerInit:
    async def test_port_constant(self):
        """PORT is 7331."""
        assert PORT == 7331

    async def test_max_connections_constant(self):
        """_MAX_CONNECTIONS is 64."""
        assert _MAX_CONNECTIONS == 64

    async def test_init_sets_attributes(self, tmp_path):
        """ChatServer stores its configuration."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        callback = AsyncMock()
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=callback,
        )
        assert server._config_dir == tmp_path
        assert server._account is account
        assert server._server is None


# ---------------------------------------------------------------------------
# TestChatServerLifecycle
# ---------------------------------------------------------------------------

class TestChatServerLifecycle:
    async def test_double_start_raises(self, tmp_path):
        """N-40: Calling start() twice raises RuntimeError."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )
        # Simulate already running.
        server._server = MagicMock()

        with pytest.raises(RuntimeError, match="already running"):
            await server.start("200:abcd::1")

    async def test_start_validates_ipv6(self, tmp_path):
        """start() rejects invalid IPv6 addresses."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )

        with pytest.raises(ValueError, match="Invalid"):
            await server.start("not-an-ipv6")

    async def test_stop_idempotent(self, tmp_path):
        """stop() is safe to call when server is not running."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )
        # Should not raise.
        await server.stop()

    async def test_stop_cancels_active_tasks(self, tmp_path):
        """N-07: stop() cancels active session tasks."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )

        # Add a fake task.
        cancelled = False

        async def _fake_session():
            nonlocal cancelled
            try:
                await asyncio.sleep(999)
            except asyncio.CancelledError:
                cancelled = True

        task = asyncio.create_task(_fake_session())
        server._tasks.add(task)

        # Let the task enter the try block before stopping.
        await asyncio.sleep(0)

        await server.stop()
        assert cancelled

    async def test_handle_connection_rejects_at_limit(self, tmp_path):
        """N-03: _handle_connection rejects when semaphore is exhausted."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )

        # Exhaust the semaphore.
        for _ in range(_MAX_CONNECTIONS):
            await server._conn_semaphore.acquire()

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await server._handle_connection(reader, writer)
        writer.close.assert_called_once()


# ---------------------------------------------------------------------------
# TestHandleConnectionInner
# ---------------------------------------------------------------------------

class TestHandleConnectionInner:
    """Tests for _handle_connection_inner error paths (lines 263-306)."""

    async def _make_server(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        return ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )

    def _make_writer(self):
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        writer.get_extra_info = MagicMock(return_value=("::1", 7331))
        return writer

    async def test_handshake_timeout_closes_connection(self, tmp_path):
        """N-02: Server-side handshake timeout closes the connection."""
        server = await self._make_server(tmp_path)
        reader = asyncio.StreamReader()
        writer = self._make_writer()

        with patch("p2pchat.core.network.server.PeerSession") as MockSession:
            async def _slow():
                await asyncio.sleep(100)

            MockSession.return_value.handshake = _slow

            with patch("p2pchat.core.network.server._HANDSHAKE_TIMEOUT", 0.01):
                await server._handle_connection_inner(reader, writer)

        writer.close.assert_called_once()

    async def test_connection_refused_closes_connection(self, tmp_path):
        """Rejected peer handshake closes connection cleanly."""
        server = await self._make_server(tmp_path)
        reader = asyncio.StreamReader()
        writer = self._make_writer()

        with patch("p2pchat.core.network.server.PeerSession") as MockSession:
            MockSession.return_value.handshake = AsyncMock(
                side_effect=ConnectionRefusedError("identity rejected")
            )
            await server._handle_connection_inner(reader, writer)

        writer.close.assert_called_once()

    async def test_generic_exception_closes_connection(self, tmp_path):
        """Unexpected handshake exception closes the connection."""
        server = await self._make_server(tmp_path)
        reader = asyncio.StreamReader()
        writer = self._make_writer()

        with patch("p2pchat.core.network.server.PeerSession") as MockSession:
            MockSession.return_value.handshake = AsyncMock(
                side_effect=RuntimeError("protocol error")
            )
            await server._handle_connection_inner(reader, writer)

        writer.close.assert_called_once()


# ---------------------------------------------------------------------------
# TestRunSession
# ---------------------------------------------------------------------------

class TestRunSession:
    async def test_callback_exception_caught_and_session_closed(self, tmp_path):
        """on_session_ready exception is caught; session is still closed."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)

        async def _bad_callback(session):
            raise RuntimeError("callback crashed")

        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=_bad_callback,
        )

        mock_session = MagicMock()
        mock_session.peer_id = "test-peer"
        mock_session.close = AsyncMock()

        await server._run_session(mock_session)
        mock_session.close.assert_called_once()

    async def test_normal_callback_closes_session(self, tmp_path):
        """Session is closed even when callback succeeds normally."""
        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )

        mock_session = MagicMock()
        mock_session.peer_id = "test-peer"
        mock_session.close = AsyncMock()

        await server._run_session(mock_session)
        mock_session.close.assert_called_once()


# ---------------------------------------------------------------------------
# TestCertExpiry
# ---------------------------------------------------------------------------

class TestCertExpiry:
    async def test_regenerates_near_expiry(self, tmp_path):
        """N-50: Cert expiring within 30 days triggers regeneration."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, "p2pchat",
            )]))
            .issuer_name(x509.Name([x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, "p2pchat",
            )]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=355))
            .not_valid_after(now + datetime.timedelta(days=10))
            .sign(key, hashes.SHA256())
        )

        cert_path = tmp_path / "tls.crt"
        key_path = tmp_path / "tls.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

        account = _make_account()
        storage = await _make_storage(tmp_path / "db", account)
        server = ChatServer(
            config_dir=tmp_path,
            account=account,
            storage=storage,
            on_session_ready=AsyncMock(),
        )

        old_bytes = cert_path.read_bytes()
        new_cert_path, _ = server._get_or_create_cert()

        # Should have regenerated (different content).
        assert new_cert_path.read_bytes() != old_bytes
        # New cert should be valid for ~1 year.
        new_cert = x509.load_pem_x509_certificate(new_cert_path.read_bytes())
        remaining = new_cert.not_valid_after_utc - now
        assert remaining.days > 300
