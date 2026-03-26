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
from textual.containers import Container
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
        ("f1", "help", "Help"),
        ("ctrl+n", "show_invite", "My invite"),
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
        with Container(id="chat-body"):
            with Container(id="chat-content"):
                yield ContactList(id="contact-list", classes="section")
                yield MessageList(id="message-list", highlight=True, markup=True, classes="section")
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

    async def on_message_received(
        self, peer_id: str, msg: StorageMessage, peer_name: str,
        refresh_delivery: bool = False,
    ) -> None:
        """Called by App when a message arrives from the network."""
        if peer_id == self._selected_peer:
            if refresh_delivery:
                # Delivery status changed — reload to update all indicators.
                await self._load_messages(peer_id)
                return
            ml = self.query_one("#message-list", MessageList)
            ml.add_chat_message(msg, peer_name)
        else:
            self._unread[peer_id] = self._unread.get(peer_id, 0) + 1
            cl = self.query_one("#contact-list", ContactList)
            cl.increment_unread(peer_id)

    async def on_peer_online(self, peer_id: str) -> None:
        self._online_peers.add(peer_id)
        await self._reload_contacts()

    async def on_peer_offline(self, peer_id: str) -> None:
        self._online_peers.discard(peer_id)
        await self._reload_contacts()

    async def refresh_messages(self, peer_id: str) -> None:
        """Reload message list if viewing this peer (updates delivery indicators)."""
        if peer_id == self._selected_peer:
            await self._load_messages(peer_id)

    def set_status(self, text: str, severity: str = "default") -> None:
        self.query_one("#status-bar", StatusBar).set_status(text, severity)

    # ------------------------------------------------------------------
    # Key binding actions
    # ------------------------------------------------------------------

    def action_help(self) -> None:
        from ..widgets.help_screen import HelpScreen
        self.app.push_screen(HelpScreen("chat"))

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

        from textual.screen import ModalScreen
        from textual.containers import Grid
        from textual.widgets import Button, Label

        peer_id = self._selected_peer

        class _ConfirmDelete(ModalScreen[bool]):
            def compose(self) -> ComposeResult:
                yield Grid(
                    Label("Delete this contact and conversation?", classes="modal-title"),
                    Label("All messages will be permanently removed."),
                    Button("Delete", variant="error", id="confirm"),
                    Button("Cancel", variant="default", id="cancel"),
                    id="invite-dialog",
                )

            def on_button_pressed(self, event: Button.Pressed) -> None:
                self.dismiss(event.button.id == "confirm")

        async def _on_confirmed(confirmed: bool | None) -> None:
            if not confirmed:
                return
            await self._storage.delete_contact(peer_id)
            self.query_one("#message-list", MessageList).clear()
            self._selected_peer = None
            self._online_peers.discard(peer_id)
            self._unread.pop(peer_id, None)
            await self._reload_contacts()
            self.notify("Contact deleted")

        self.app.push_screen(_ConfirmDelete(), _on_confirmed)

    def action_backup(self) -> None:
        self.notify("Backup: use CLI 'p2pchat backup' command", severity="information")

    def action_wipe(self) -> None:
        self.notify(
            "Wipe: use CLI 'p2pchat wipe' command for safety",
            severity="warning",
        )

    def action_toggle_contacts(self) -> None:
        cl = self.query_one("#contact-list", ContactList)
        if not cl.display:
            # Hidden → show and focus.
            cl.display = True
            cl.focus()
        elif cl.has_focus:
            # Visible and focused → move focus to input.
            self.query_one("#chat-input", ChatInput).focus()
        else:
            # Visible but not focused → focus it.
            cl.focus()

    def action_focus_input(self) -> None:
        self.query_one("#chat-input", ChatInput).focus()


class ConnectRequest(Message):
    """Message forwarded to the App for connection handling."""

    def __init__(self, info) -> None:
        self.info = info
        super().__init__()


