"""Invite link modals: show own invite link and parse a peer's invite.

Invite format:
    p2pchat://[200:a:b::c]:7331/BASE64URL_ED25519_PUBKEY#DISPLAY_NAME
"""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple

from textual import on
from textual.app import ComposeResult
from textual.containers import Grid
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from p2pchat.core.crypto import decode_public_key

_INVITE_RE = re.compile(
    r"^p2pchat://\[([0-9a-f:]+)\]:(\d+)/([A-Za-z0-9_-]+)(?:#(.*))?$"
)


class InviteInfo(NamedTuple):
    """Parsed invite link fields."""

    ygg_address: str
    port: int
    ed25519_pub: bytes
    display_name: str


def parse_invite(link: str) -> InviteInfo:
    """Parse an invite link string.

    Raises
    ------
    ValueError
        If the link format is invalid, the address is not valid IPv6,
        the port is out of range, or the public key is malformed.
    """
    link = link.strip()
    m = _INVITE_RE.match(link)
    if not m:
        raise ValueError(f"Invalid invite link format: {link!r}")

    addr_str, port_str, key_b64, name = m.groups()

    try:
        ipaddress.IPv6Address(addr_str)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv6 address in invite: {exc}") from exc

    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")

    pub_bytes = decode_public_key(key_b64)

    return InviteInfo(
        ygg_address=addr_str,
        port=port,
        ed25519_pub=pub_bytes,
        display_name=name or "",
    )


def build_invite(ygg_address: str, port: int, ed25519_pub_b64: str, display_name: str) -> str:
    """Build an invite link string."""
    safe_name = display_name.replace("#", "")
    return f"p2pchat://[{ygg_address}]:{port}/{ed25519_pub_b64}#{safe_name}"


class ShowInviteModal(ModalScreen[None]):
    """Display the local user's invite link for copying."""

    def __init__(self, invite_link: str) -> None:
        self._invite_link = invite_link
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Your Invite Link", classes="modal-title"),
            Static(self._invite_link, id="invite-text"),
            Label("Share this link with contacts via a separate channel."),
            Button("Copy", variant="primary", id="copy-btn"),
            Button("Close", id="close-btn"),
            id="invite-dialog",
        )

    @on(Button.Pressed, "#copy-btn")
    def _copy(self) -> None:
        try:
            import pyperclip
            pyperclip.copy(self._invite_link)
            self.notify("Copied to clipboard")
        except Exception:
            self.notify("Could not copy to clipboard", severity="error")

    @on(Button.Pressed, "#close-btn")
    def _close(self) -> None:
        self.dismiss(None)


class ConnectInviteModal(ModalScreen[InviteInfo | None]):
    """Prompt the user to paste a peer's invite link."""

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Connect to Peer", classes="modal-title"),
            Input(placeholder="Paste invite link\u2026", id="invite-input"),
            Label("", id="invite-error"),
            Button("Connect", variant="primary", id="connect-btn"),
            Button("Cancel", id="cancel-btn"),
            id="connect-dialog",
        )

    @on(Button.Pressed, "#connect-btn")
    def _connect(self) -> None:
        inp = self.query_one("#invite-input", Input)
        err_label = self.query_one("#invite-error", Label)
        try:
            info = parse_invite(inp.value)
        except ValueError as exc:
            err_label.update(f"[red]{exc}[/red]")
            return
        self.dismiss(info)

    @on(Button.Pressed, "#cancel-btn")
    def _cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted, "#invite-input")
    def _submit(self) -> None:
        self._connect()
