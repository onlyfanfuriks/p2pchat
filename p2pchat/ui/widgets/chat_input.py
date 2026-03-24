"""Bottom-anchored message input widget.

Multiline text input. Enter sends; Ctrl+Enter adds a newline.
Auto-expands up to 7 lines of text.
"""

from __future__ import annotations

from textual import events
from textual.message import Message
from textual.widgets import TextArea


class ChatInput(TextArea):
    """Multiline text input for composing chat messages."""

    class MessageReady(Message):
        """Fired when the user presses Enter with non-empty text."""

        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    MAX_LINES = 7

    def __init__(self, **kwargs) -> None:
        super().__init__(
            show_line_numbers=False,
            language=None,
            soft_wrap=True,
            **kwargs,
        )

    async def _on_key(self, event: events.Key) -> None:
        if event.key == "enter":
            event.stop()
            event.prevent_default()
            text = self.text.strip()
            if text:
                self.load_text("")
                self.post_message(self.MessageReady(text))
            return
        if event.key in ("ctrl+enter", "shift+enter"):
            event.stop()
            event.prevent_default()
            self.insert("\n")
            return
        await super()._on_key(event)

    @property
    def value(self) -> str:
        """Compatibility with Input-style API."""
        return self.text

    @value.setter
    def value(self, v: str) -> None:
        self.load_text(v)

    async def action_submit(self) -> None:
        """Programmatic submit for tests and keybindings."""
        text = self.text.strip()
        if text:
            self.load_text("")
            self.post_message(self.MessageReady(text))

    def on_text_area_changed(self) -> None:
        """Auto-resize height based on content."""
        line_count = self.document.line_count
        target = min(line_count, self.MAX_LINES) + 2
        target = max(target, 3)
        self.styles.height = target
