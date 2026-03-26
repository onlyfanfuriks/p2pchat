"""Context-sensitive help screen showing keybindings.

Accessible via F1 from any screen. Displays all available
keybindings for the current context.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Label


_CHAT_BINDINGS = [
    ("General", [
        ("ctrl+p", "Command palette"),
        ("F1", "Show this help"),
        ("ctrl+q", "Quit"),
    ]),
    ("Chat", [
        ("Enter", "Send message"),
        ("ctrl+Enter", "New line in message"),
        ("shift+Enter", "New line in message"),
        ("Escape", "Focus message input"),
        ("Tab", "Toggle contact list"),
    ]),
    ("Contacts", [
        ("ctrl+n", "Show my invite link"),
        ("ctrl+o", "Connect to peer"),
        ("ctrl+d", "Delete contact & chat"),
    ]),
    ("Data", [
        ("ctrl+b", "Backup info"),
        ("ctrl+w", "Wipe data info"),
    ]),
]

_UNLOCK_BINDINGS = [
    ("Navigation", [
        ("Escape", "Go back"),
        ("Enter", "Submit"),
        ("ctrl+n", "New account"),
        ("F8", "Delete account"),
    ]),
]


class HelpScreen(ModalScreen[None]):
    """Modal overlay showing keybindings for the current context."""

    BINDINGS = [
        ("escape", "dismiss_help", "Close"),
        ("f1", "dismiss_help", "Close"),
    ]

    def __init__(self, context: str = "chat") -> None:
        super().__init__()
        self._help_context = context

    def compose(self) -> ComposeResult:
        bindings = _CHAT_BINDINGS if self._help_context == "chat" else _UNLOCK_BINDINGS
        title = "Chat" if self._help_context == "chat" else "Account"

        with VerticalScroll(id="help-dialog"):
            yield Label(f"p2pchat — {title} Keybindings", classes="help-header")

            for section_name, keys in bindings:
                yield Label(section_name, classes="help-section-title")
                for key, desc in keys:
                    yield HelpRow(key, desc)

            yield Label("Press Escape or F1 to close", classes="help-footer")

    def action_dismiss_help(self) -> None:
        self.dismiss(None)


class HelpRow(Horizontal):
    """Single keybinding row: key + description."""

    def __init__(self, key: str, description: str) -> None:
        super().__init__(classes="help-row")
        self._key = key
        self._description = description

    def compose(self) -> ComposeResult:
        yield Label(self._key, classes="help-key")
        yield Label(self._description, classes="help-desc")
