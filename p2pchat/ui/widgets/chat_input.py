"""Bottom-anchored message input widget.

Single-line by default. Posts a ``ChatInput.MessageReady`` message when
the user presses Enter with non-empty text.
"""

from __future__ import annotations

from textual import on
from textual.message import Message
from textual.widgets import Input


class ChatInput(Input):
    """Text input for composing chat messages."""

    class MessageReady(Message):
        """Fired when the user presses Enter with non-empty text."""

        def __init__(self, value: str) -> None:
            self.value = value
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(
            placeholder="Type a message\u2026",
            **kwargs,
        )

    @on(Input.Submitted)
    def _on_submit(self, event: Input.Submitted) -> None:
        event.stop()
        text = event.value.strip()
        if not text:
            return
        self.clear()
        self.post_message(self.MessageReady(text))
