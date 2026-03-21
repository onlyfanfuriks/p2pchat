"""Scrollable message history widget.

Renders messages with timestamps, sender names, and delivery status
using Rich markup. Auto-scrolls to the bottom on new messages.
"""

from __future__ import annotations

import datetime

from rich.markup import escape
from textual.widgets import RichLog

from p2pchat.core.storage import Message


def _format_timestamp(ts: int) -> str:
    """Format unix-seconds timestamp as HH:MM."""
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    local = dt.astimezone()
    return local.strftime("%H:%M")


def _delivery_indicator(msg: Message) -> str:
    if msg.direction != "sent":
        return ""
    if msg.delivered:
        return " [green]\u2713[/green]"
    return " [dim]\u23f3[/dim]"


class MessageList(RichLog):
    """Scrollable message history for a single conversation."""

    def add_chat_message(self, msg: Message, peer_name: str = "") -> None:
        """Append a single message to the log.

        Parameters
        ----------
        msg:
            The Message dataclass from storage.
        peer_name:
            Display name of the peer (used for received messages).
        """
        ts = _format_timestamp(msg.timestamp)
        if msg.direction == "sent":
            sender = "[bold]You[/bold]"
        else:
            name = escape(peer_name or "Peer")
            sender = f"[bold cyan]{name}[/bold cyan]"
        indicator = _delivery_indicator(msg)

        self.write(f"[dim]{ts}[/dim]  {sender}{indicator}")
        self.write(f"  {escape(msg.content)}")
        self.write("")

    def load_history(self, messages: list[Message], peer_name: str = "") -> None:
        """Clear and reload the full message history."""
        self.clear()
        for msg in messages:
            self.add_chat_message(msg, peer_name)
