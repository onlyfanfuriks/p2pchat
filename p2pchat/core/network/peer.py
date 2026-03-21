"""Outgoing TCP client for connecting to a remote peer.

Uses TLS with certificate verification disabled — peer identity is
established at the application layer via Ed25519 signatures, not by PKI.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
from pathlib import Path
from typing import Awaitable, Callable

from p2pchat.core.account import Account
from p2pchat.core.storage import Storage

from .session import PeerSession

log = logging.getLogger(__name__)


async def connect(
    ygg_address: str,
    port: int,
    account: Account,
    storage: Storage,
    config_dir: Path,
    verify_callback: Callable[[str, str, str], Awaitable[bool]] | None = None,
    timeout: float = 10.0,
) -> PeerSession:
    """Connect to a remote peer and complete the application-layer handshake.

    Parameters
    ----------
    ygg_address:
        Peer's Yggdrasil IPv6 address (e.g. ``"200:1234:..."``).
        Leading/trailing brackets are stripped automatically.
    port:
        Remote TCP port (typically ``7331``).
    account:
        Local account identity used during handshake.
    storage:
        Encrypted local DB (used to look up / store contacts).
    config_dir:
        Local config directory (reserved for future use; e.g. client certs).
    verify_callback:
        Called when an unknown peer is encountered.
        Signature: ``async (peer_id, display_name, fingerprint) -> bool``.
    timeout:
        Total time budget (seconds) for TCP connection + TLS + app handshake.
        The budget is shared: time spent on connection is subtracted from
        the handshake allowance.

    Returns
    -------
    PeerSession
        A fully-handshaked, active session ready for message exchange.

    Raises
    ------
    asyncio.TimeoutError
        If the connection or handshake does not complete within *timeout*.
    ConnectionRefusedError
        If the remote peer rejects the identity verification.
    OSError
        If the TCP connection itself fails (host unreachable, etc.).
    ValueError
        If *ygg_address* is not a valid IPv6 address.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # N-05: Enforce TLS 1.2 minimum on client side.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # N-16: Disable TLS compression (CRIME) and session tickets.
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    # Peer identity is verified at the application layer (Ed25519).
    # TLS provides channel encryption only; hostname / cert validation
    # is intentionally disabled.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Strip brackets — asyncio.open_connection handles bare IPv6 addresses.
    host = ygg_address.strip("[]")

    # N-18: Validate IPv6 address before connecting.
    try:
        ipaddress.IPv6Address(host)
    except ValueError as exc:
        raise ValueError(
            f"Invalid peer IPv6 address {ygg_address!r}: {exc}"
        ) from exc

    log.info("Connecting to peer %s:%d", host, port)

    # N-21: Track deadline so handshake gets remaining budget, not full timeout.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(
            f"Connection to {ygg_address}:{port} timed out after {timeout}s"
        ) from None
    except OSError as exc:
        raise OSError(
            f"Cannot connect to {ygg_address}:{port}: {exc}"
        ) from exc

    log.info("TCP/TLS connected to %s:%d; starting handshake", host, port)

    session = PeerSession(
        reader=reader,
        writer=writer,
        account=account,
        storage=storage,
        is_initiator=True,
        verify_callback=verify_callback,
    )

    # N-21: Use remaining time budget for the handshake.
    remaining = max(0.1, deadline - loop.time())

    try:
        await asyncio.wait_for(session.handshake(), timeout=remaining)
    except asyncio.TimeoutError:
        await session.close()
        raise asyncio.TimeoutError(
            f"Application-layer handshake with {ygg_address}:{port} "
            f"timed out (budget exhausted)"
        ) from None
    except Exception:
        await session.close()
        raise

    log.info("Session established with peer %s", session.peer_id)
    return session
