"""Contact list panel for the main chat screen.

Displays contacts with online/offline status and unread badges.
Posts a ``ContactList.Selected`` message when the user selects a contact.
"""

from __future__ import annotations

from rich.markup import escape
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import OptionList
from textual.widgets.option_list import Option

from p2pchat.core.storage import Contact


class ContactList(OptionList):
    """Vertical contact list with online indicators."""

    class Selected(Message):
        """Fired when the user selects a contact."""

        def __init__(self, peer_id: str) -> None:
            self.peer_id = peer_id
            super().__init__()

    selected_peer: reactive[str] = reactive("")

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._contacts: dict[str, Contact] = {}
        self._online: set[str] = set()
        self._unread: dict[str, int] = {}

    def set_contacts(
        self,
        contacts: list[Contact],
        online: set[str] | None = None,
        unread: dict[str, int] | None = None,
    ) -> None:
        """Reload the full contact list."""
        self._contacts = {c.peer_id: c for c in contacts}
        self._online = online or set()
        self._unread = unread or {}
        self._rebuild()

    def mark_online(self, peer_id: str, is_online: bool = True) -> None:
        if is_online:
            self._online.add(peer_id)
        else:
            self._online.discard(peer_id)
        self._rebuild()

    def increment_unread(self, peer_id: str) -> None:
        self._unread[peer_id] = self._unread.get(peer_id, 0) + 1
        self._rebuild()

    def clear_unread(self, peer_id: str) -> None:
        self._unread.pop(peer_id, None)
        self._rebuild()

    def _rebuild(self) -> None:
        """Reconstruct option items from current state."""
        self.clear_options()
        for pid, contact in self._contacts.items():
            dot = "\u25cf" if pid in self._online else "\u25cb"
            badge = ""
            count = self._unread.get(pid, 0)
            if count > 0:
                badge = f" [{count}]"
            label = f"{dot} {escape(contact.display_name)}{badge}"
            self.add_option(Option(label, id=pid))

    def on_option_list_option_selected(
        self, event: OptionList.OptionSelected
    ) -> None:
        event.stop()
        if event.option.id is not None:
            self.selected_peer = str(event.option.id)
            self.post_message(self.Selected(str(event.option.id)))
