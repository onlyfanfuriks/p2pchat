"""Main chat screen with contact list, message history, and input.

Layout:
- Top: StatusBar
- Left: ContactList (collapsible with Tab)
- Right: MessageList
- Bottom: ChatInput
"""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Footer

from p2pchat.core.account import Account
from p2pchat.core.storage import Message as StorageMessage
from p2pchat.core.storage import Storage

from .contacts import ContactList
from ..widgets.chat_input import ChatInput
from ..widgets.message_list import MessageList
from ..widgets.status_bar import StatusBar

log = logging.getLogger(__name__)


class ChatScreen(Screen):
    """Primary chat interface."""

    BINDINGS = [
        ("ctrl+i", "show_invite", "My invite"),
        ("ctrl+o", "open_invite", "Connect"),
        ("ctrl+d", "delete_chat", "Delete chat"),
        ("ctrl+b", "backup", "Backup"),
        ("ctrl+w", "wipe", "Wipe data"),
        ("tab", "toggle_contacts", "Contacts"),
        ("escape", "focus_input", "Focus input"),
    ]

    def __init__(
        self,
        account: Account,
        storage: Storage,
        send_callback: Callable[[str, str, str], Awaitable[str | None]] | None = None,
    ) -> None:
        super().__init__()
        self._account = account
        self._storage = storage
        self._send_callback = send_callback
        self._selected_peer: str | None = None
        self._online_peers: set[str] = set()
        self._unread: dict[str, int] = {}

    def compose(self) -> ComposeResult:
        yield StatusBar(id="status-bar")
        with Horizontal(id="main-pane"):
            yield ContactList(id="contact-list")
            yield MessageList(id="message-list", highlight=True, markup=True)
        yield ChatInput(id="chat-input")
        yield Footer()

    async def on_mount(self) -> None:
        status = self.query_one("#status-bar", StatusBar)
        status.display_name = self._account.display_name
        status.ygg_address = self._account.ygg_address

        await self._reload_contacts()
        self.query_one("#chat-input", ChatInput).focus()

    async def _reload_contacts(self) -> None:
        contacts = await self._storage.list_contacts()
        cl = self.query_one("#contact-list", ContactList)
        cl.set_contacts(contacts, self._online_peers, self._unread)

    # ------------------------------------------------------------------
    # Contact selection
    # ------------------------------------------------------------------

    @on(ContactList.Selected)
    async def _on_contact_selected(self, event: ContactList.Selected) -> None:
        self._selected_peer = event.peer_id
        cl = self.query_one("#contact-list", ContactList)
        cl.clear_unread(event.peer_id)
        self._unread.pop(event.peer_id, None)
        await self._load_messages(event.peer_id)
        self.query_one("#chat-input", ChatInput).focus()

    async def _load_messages(self, peer_id: str) -> None:
        messages = await self._storage.get_messages(peer_id, limit=200)
        contact = await self._storage.get_contact(peer_id)
        peer_name = contact.display_name if contact else ""
        ml = self.query_one("#message-list", MessageList)
        ml.load_history(messages, peer_name)

    # ------------------------------------------------------------------
    # Message sending
    # ------------------------------------------------------------------

    @on(ChatInput.MessageReady)
    async def _on_message_submit(self, event: ChatInput.MessageReady) -> None:
        if not self._selected_peer:
            self.notify("Select a contact first", severity="warning")
            return

        import time

        msg = StorageMessage(
            peer_id=self._selected_peer,
            direction="sent",
            content=event.value,
            timestamp=int(time.time()),
        )

        await self._storage.save_message(msg)

        contact = await self._storage.get_contact(self._selected_peer)
        peer_name = contact.display_name if contact else ""
        ml = self.query_one("#message-list", MessageList)
        ml.add_chat_message(msg, peer_name)

        if self._send_callback:
            try:
                await self._send_callback(self._selected_peer, event.value, msg.id)
            except Exception as exc:
                log.warning("Send failed: %s", exc)
                self.notify(f"Send failed: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Public interface for the App to push updates
    # ------------------------------------------------------------------

    def on_message_received(
        self, peer_id: str, msg: StorageMessage, peer_name: str
    ) -> None:
        """Called by App when a message arrives from the network."""
        if peer_id == self._selected_peer:
            ml = self.query_one("#message-list", MessageList)
            ml.add_chat_message(msg, peer_name)
        else:
            self._unread[peer_id] = self._unread.get(peer_id, 0) + 1
            cl = self.query_one("#contact-list", ContactList)
            cl.increment_unread(peer_id)

    def on_peer_online(self, peer_id: str) -> None:
        self._online_peers.add(peer_id)
        cl = self.query_one("#contact-list", ContactList)
        cl.mark_online(peer_id, True)

    def on_peer_offline(self, peer_id: str) -> None:
        self._online_peers.discard(peer_id)
        cl = self.query_one("#contact-list", ContactList)
        cl.mark_online(peer_id, False)

    def set_status(self, text: str, severity: str = "default") -> None:
        self.query_one("#status-bar", StatusBar).set_status(text, severity)

    # ------------------------------------------------------------------
    # Key binding actions
    # ------------------------------------------------------------------

    def action_show_invite(self) -> None:
        if not self._account.ygg_address:
            self.notify("Waiting for Yggdrasil to start\u2026", severity="warning")
            return

        from ..widgets.invite_modal import ShowInviteModal, build_invite
        from p2pchat.core.crypto import display_fingerprint, encode_public_key
        from p2pchat.core.protocol import PORT

        link = build_invite(
            self._account.ygg_address,
            PORT,
            encode_public_key(self._account.ed25519_public),
            self._account.display_name,
        )
        fingerprint = display_fingerprint(self._account.ed25519_public)
        self.app.push_screen(ShowInviteModal(link, fingerprint))

    def action_open_invite(self) -> None:
        from ..widgets.invite_modal import ConnectInviteModal, InviteInfo

        def _on_result(info: InviteInfo | None) -> None:
            if info is not None:
                self.notify(
                    f"Connecting to {info.display_name or info.ygg_address}\u2026"
                )
                # The App layer will handle the actual connection.
                self.app.post_message(
                    ConnectRequest(info)
                )

        self.app.push_screen(ConnectInviteModal(), _on_result)

    async def action_delete_chat(self) -> None:
        if not self._selected_peer:
            self.notify("No conversation selected", severity="warning")
            return
        await self._storage.delete_conversation(self._selected_peer)
        ml = self.query_one("#message-list", MessageList)
        ml.clear()
        self.notify("Conversation deleted")

    def action_backup(self) -> None:
        self.notify("Backup: use CLI 'p2pchat backup' command", severity="information")

    def action_wipe(self) -> None:
        self.notify(
            "Wipe: use CLI 'p2pchat wipe' command for safety",
            severity="warning",
        )

    def action_toggle_contacts(self) -> None:
        cl = self.query_one("#contact-list", ContactList)
        cl.display = not cl.display

    def action_focus_input(self) -> None:
        self.query_one("#chat-input", ChatInput).focus()


class ConnectRequest(Message):
    """Message forwarded to the App for connection handling."""

    def __init__(self, info) -> None:
        self.info = info
        super().__init__()
