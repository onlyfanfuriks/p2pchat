"""Scrollable message history widget.

Renders messages with timestamps, sender names, and delivery status
using Rich markup. Sent messages right-aligned, received left-aligned.
Auto-scrolls to the bottom on new messages.
"""

from __future__ import annotations

import datetime

from rich.align import Align
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from textual.widgets import RichLog

from p2pchat.core.storage import Message


def _format_timestamp(ts: int) -> str:
    """Format unix-seconds timestamp as HH:MM."""
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    local = dt.astimezone()
    return local.strftime("%H:%M")


def _local_date(ts: int) -> str:
    """Format unix-seconds timestamp as dd.mm.yy."""
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    local = dt.astimezone()
    return local.strftime("%d.%m.%y")


class MessageList(RichLog):
    """Scrollable message history for a single conversation."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._last_date: str = ""
        self._messages: list[Message] = []
        self._peer_name: str = ""

    def on_mount(self) -> None:
        self.app.theme_changed_signal.subscribe(self, self._on_theme_changed)

    def _on_theme_changed(self, _theme) -> None:
        self._rerender()

    def _maybe_date_separator(self, msg: Message) -> None:
        """Insert a date separator if the message is on a different day."""
        date_str = _local_date(msg.timestamp)
        if date_str != self._last_date:
            self._last_date = date_str
            c = self._theme_colors()
            self.write(Rule(date_str, style=c.get("recv_border", "dim")))

    def _theme_colors(self) -> dict[str, str]:
        """Resolve Textual theme colors for message panels.

        Mirrors the TCSS: ChatInput border uses $accent,
        ContactList border uses $surface.
        """
        try:
            v = self.app.get_css_variables()
            return {
                # Sent: accent family (matches ChatInput border)
                "sent_border": v.get("accent", ""),
                "sent_name": v.get("accent-lighten-1", v.get("accent", "")),
                # Received: surface family (matches ContactList border)
                "recv_border": v.get("secondary", ""),
                "recv_name": v.get("accent-lighten-2", v.get("secondary", "")),
                # Indicators
                "success": v.get("success", ""),
                "warning": v.get("warning", ""),
            }
        except Exception:
            return {}

    def _delivery_indicator(self, msg: Message) -> str | Text:
        if msg.direction != "sent":
            return ""
        c = self._theme_colors()
        if msg.delivered:
            color = c.get("success", "green")
            return Text(" \u2713", style=color)
        dt = datetime.datetime.fromtimestamp(msg.timestamp, tz=datetime.timezone.utc)
        local = dt.astimezone()
        queued_at = local.strftime("%d.%m.%y %H:%M:%S")
        t = Text(" \u23f3 ", style=c.get("warning", "yellow"))
        t.append(f"outbox \u2014 sent {queued_at}", style="dim")
        return t

    def _rerender(self) -> None:
        self.clear()
        self._last_date = ""
        for msg in self._messages:
            self._render_message(msg, self._peer_name)

    def add_chat_message(self, msg: Message, peer_name: str = "") -> None:
        """Append a single message to the log."""
        self._messages.append(msg)
        self._peer_name = peer_name
        self._render_message(msg, peer_name)

    def _render_message(self, msg: Message, peer_name: str) -> None:
        """Render a single message to the log."""
        self._maybe_date_separator(msg)

        ts = _format_timestamp(msg.timestamp)
        indicator = self._delivery_indicator(msg)
        c = self._theme_colors()

        if msg.direction == "sent":
            header = Text()
            header.append("You", style="bold")
            if isinstance(indicator, Text):
                header.append_text(indicator)
            header.append(f"  {ts}", style="dim")
            body = Markdown(msg.content)
            panel = Panel(
                body,
                title=header,
                title_align="right",
                border_style=c.get("sent_border", ""),
                expand=False,
            )
            self.write(Align.right(panel))
        else:
            name = escape(peer_name or "Peer")
            header = Text()
            header.append(f"{ts}  ", style="dim")
            header.append(name, style=f"bold {c.get('recv_name', '')}")
            body = Markdown(msg.content)
            panel = Panel(
                body,
                title=header,
                title_align="left",
                border_style=c.get("recv_border", ""),
                expand=False,
            )
            self.write(panel)
        self.write("")

    def load_history(self, messages: list[Message], peer_name: str = "") -> None:
        """Clear and reload the full message history."""
        self._messages = list(messages)
        self._peer_name = peer_name
        self._rerender()
