"""TLS TCP server that accepts incoming peer connections.

Binds to the Yggdrasil IPv6 address on PORT 7331, wraps each accepted
connection in a PeerSession, performs the application-layer handshake, and
delivers the ready session to the caller via ``on_session_ready``.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import os
import socket
import ssl
from pathlib import Path
from typing import Awaitable, Callable, Set

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from p2pchat.core.account import Account
from p2pchat.core.storage import Storage

from .session import PeerSession

log = logging.getLogger(__name__)

PORT = 7331

# N-03: Maximum concurrent connections to prevent DoS.
_MAX_CONNECTIONS = 64
# N-02: Maximum seconds for the application-layer handshake on server side.
_HANDSHAKE_TIMEOUT = 15.0
# N-33: Maximum seconds to wait for active sessions during shutdown.
_SHUTDOWN_DRAIN_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# TLS certificate generation
# ---------------------------------------------------------------------------

def generate_tls_cert(config_dir: Path) -> tuple[Path, Path]:
    """Generate a self-signed RSA-2048 certificate valid for 1 year.

    The peer identity is verified at the application layer via Ed25519, so
    the TLS certificate is used only for channel encryption; hostname
    checking is disabled on the client side.

    Files
    -----
    ``<config_dir>/tls.key`` — private key (PEM, mode 0600)
    ``<config_dir>/tls.crt`` — certificate (PEM, mode 0600)

    Returns
    -------
    (cert_path, key_path)
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "p2pchat")]
    )

    # N-50: 1 year validity (auto-regenerated when near expiry).
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("p2pchat.local")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    key_path = config_dir / "tls.key"
    cert_path = config_dir / "tls.crt"

    # N-43: Write to temp files first, then rename for atomicity.
    # N-06/N-19: fd sentinel pattern + O_NOFOLLOW to prevent symlink attacks.
    tmp_paths: list[Path] = []
    try:
        for path, data in ((key_path, key_pem), (cert_path, cert_pem)):
            tmp_path = path.with_suffix(path.suffix + ".tmp")
            tmp_paths.append(tmp_path)
            fd = os.open(
                str(tmp_path),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    fd = -1  # fdopen took ownership
                    f.write(data)
            except BaseException:
                if fd != -1:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                raise
    except BaseException:
        for tp in tmp_paths:
            try:
                os.unlink(str(tp))
            except OSError:
                pass
        raise

    # Atomic renames (POSIX rename is atomic on the same filesystem).
    for tmp_path, final_path in zip(tmp_paths, (key_path, cert_path)):
        os.rename(str(tmp_path), str(final_path))

    log.info("Generated TLS cert: %s / %s", cert_path, key_path)
    return cert_path, key_path


# ---------------------------------------------------------------------------
# ChatServer
# ---------------------------------------------------------------------------

class ChatServer:
    """Async TLS server that accepts peer connections.

    Parameters
    ----------
    config_dir:
        Directory where TLS key/cert are stored (and generated if absent).
    account:
        Local account identity.
    storage:
        Encrypted local DB.
    on_session_ready:
        Coroutine called with the fully-handshaked PeerSession.
    verify_callback:
        Forwarded to each PeerSession for identity verification.
    """

    PORT = PORT

    def __init__(
        self,
        config_dir: Path,
        account: Account,
        storage: Storage,
        on_session_ready: Callable[[PeerSession], Awaitable[None]],
        verify_callback: Callable[[str, str, str], Awaitable[bool]] | None = None,
    ) -> None:
        self._config_dir = config_dir
        self._account = account
        self._storage = storage
        self._on_session_ready = on_session_ready
        self._verify_callback = verify_callback

        self._server: asyncio.Server | None = None
        self._tasks: Set[asyncio.Task] = set()
        # N-03: Connection-limiting semaphore.
        self._conn_semaphore = asyncio.Semaphore(_MAX_CONNECTIONS)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, ygg_address: str) -> None:
        """Bind to [ygg_address]:7331 with TLS and start accepting connections.

        Parameters
        ----------
        ygg_address:
            Yggdrasil IPv6 address string (e.g. ``"200:1234:..."``).
            Brackets are stripped automatically if present.
        """
        # N-40: Guard against double start.
        if self._server is not None:
            raise RuntimeError("ChatServer is already running; call stop() first")

        cert_path, key_path = self._get_or_create_cert()
        ctx = self._build_ssl_context(cert_path, key_path)

        # Strip brackets for asyncio (it handles IPv6 internally).
        host = ygg_address.strip("[]")

        # Validate that the address is a real IPv6 address to catch typos early.
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ValueError(
                f"Invalid Yggdrasil IPv6 address {ygg_address!r}: {exc}"
            ) from exc

        # N-20: Use socket.AF_INET6 instead of magic number 10.
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=host,
            port=self.PORT,
            ssl=ctx,
            family=socket.AF_INET6,
        )
        addrs = [s.getsockname() for s in self._server.sockets]
        log.info("ChatServer listening on %s (port %d)", addrs, self.PORT)

    async def stop(self) -> None:
        """Stop accepting new connections and drain/cancel active sessions."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        if self._tasks:
            log.info("Stopping %d active session(s)…", len(self._tasks))
            # N-07: Cancel tasks instead of waiting forever.
            for task in self._tasks:
                task.cancel()
            # N-33: Enforce a drain timeout.
            await asyncio.wait(self._tasks, timeout=_SHUTDOWN_DRAIN_TIMEOUT)

        log.info("ChatServer stopped")

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Wrap the connection in a PeerSession, handshake, then notify caller."""
        # N-03: Enforce connection limit.
        if self._conn_semaphore.locked():
            log.warning("Connection limit reached; rejecting incoming connection")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        async with self._conn_semaphore:
            await self._handle_connection_inner(reader, writer)

    async def _handle_connection_inner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer_addr = writer.get_extra_info("peername")
        log.info("Incoming connection from %s", peer_addr)

        session = PeerSession(
            reader=reader,
            writer=writer,
            account=self._account,
            storage=self._storage,
            is_initiator=False,
            verify_callback=self._verify_callback,
        )

        # N-02: Server-side crypto handshake timeout.
        try:
            await asyncio.wait_for(session.handshake(), timeout=_HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("Handshake timeout from %s", peer_addr)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        except Exception as exc:
            log.warning("Handshake failed with %s: %s", peer_addr, exc)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        log.info("Crypto handshake complete with %s, starting identity verification", peer_addr)

        # Identity verification is interactive (user approves via modal) —
        # no timeout so the user has time to verify the fingerprint.
        try:
            await session.verify_and_activate()
        except ConnectionRefusedError as exc:
            log.info("Rejected peer %s: %s", peer_addr, exc)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        except Exception as exc:
            log.warning("Verification failed with %s: %s", peer_addr, exc)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        # N-46: create_task instead of ensure_future.
        task = asyncio.create_task(self._run_session(session))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run_session(self, session: PeerSession) -> None:
        """Invoke on_session_ready and clean up afterwards."""
        try:
            await self._on_session_ready(session)
        except Exception as exc:
            log.error(
                "on_session_ready raised an exception for peer %s: %s",
                session.peer_id,
                exc,
            )
        finally:
            await session.close()

    # ------------------------------------------------------------------
    # TLS helpers
    # ------------------------------------------------------------------

    def _get_or_create_cert(self) -> tuple[Path, Path]:
        """Return existing cert/key paths or generate new ones.

        N-39: Validates that existing cert/key are loadable and not expired.
        N-50: Regenerates cert if it expires within 30 days.
        """
        cert_path = self._config_dir / "tls.crt"
        key_path = self._config_dir / "tls.key"

        if cert_path.exists() and key_path.exists():
            try:
                # Verify cert/key are loadable by building an SSL context.
                self._build_ssl_context(cert_path, key_path)
                # Check expiry.
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                remaining = (
                    cert.not_valid_after_utc
                    - datetime.datetime.now(datetime.timezone.utc)
                )
                if remaining.total_seconds() > 30 * 86400:
                    return cert_path, key_path
                log.info(
                    "TLS certificate expires in %d days; regenerating",
                    remaining.days,
                )
            except Exception as exc:
                log.warning("Existing TLS cert/key invalid (%s); regenerating", exc)

        return generate_tls_cert(self._config_dir)

    @staticmethod
    def _build_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # N-16: Disable TLS compression (CRIME) and session tickets.
        ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
        ctx.load_cert_chain(str(cert_path), str(key_path))
        return ctx
