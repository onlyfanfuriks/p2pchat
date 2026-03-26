"""Scrollable message history widget.

Renders messages with timestamps, sender names, and delivery status
using Rich renderables inside Static children. Sent messages right-aligned,
received left-aligned. Auto-scrolls to the bottom on new messages.

Uses VerticalScroll + Static so each message re-renders on resize,
giving natural responsive behavior without Python resize handlers.
"""

from __future__ import annotations

import datetime

from rich.align import Align
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from textual.containers import VerticalScroll
from textual.widgets import Static

from p2pchat.core.storage import Message

_CHILDREN_SELECTOR = "_DateSep, _Bubble"


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


def _theme_colors(widget) -> dict[str, str]:
    """Resolve Textual theme colors from any mounted widget."""
    try:
        v = widget.app.get_css_variables()
        return {
            "sent_border": v.get("accent", ""),
            "sent_name": v.get("accent-lighten-1", v.get("accent", "")),
            "recv_border": v.get("secondary", ""),
            "recv_name": v.get("accent-lighten-2", v.get("secondary", "")),
            "success": v.get("success", ""),
            "warning": v.get("warning", ""),
        }
    except Exception:
        return {}


def _delivery_indicator(msg: Message, c: dict[str, str]) -> str | Text:
    if msg.direction != "sent":
        return ""
    if msg.delivered:
        color = c.get("success", "green")
        return Text(" \u2713", style=color)
    dt = datetime.datetime.fromtimestamp(msg.timestamp, tz=datetime.timezone.utc)
    local = dt.astimezone()
    queued_at = local.strftime("%d.%m.%y %H:%M:%S")
    t = Text(" \u23f3 ", style=c.get("warning", "yellow"))
    t.append(f"outbox \u2014 sent {queued_at}", style="dim")
    return t


class _DateSep(Static):
    """Date separator rule between message groups."""

    def __init__(self, date_str: str) -> None:
        super().__init__()
        self._date_str = date_str

    def render(self) -> Rule:
        c = _theme_colors(self)
        return Rule(self._date_str, style=c.get("recv_border", "dim"))


class _Bubble(Static):
    """Single chat message rendered as a Rich Panel."""

    def __init__(self, msg: Message, peer_name: str) -> None:
        super().__init__()
        self._msg = msg
        self._peer_name = peer_name
        self.styles.margin = (0, 0, 1, 0)

    def render(self) -> Align | Panel:
        msg = self._msg
        c = _theme_colors(self)
        ts = _format_timestamp(msg.timestamp)

        if msg.direction == "sent":
            header = Text()
            header.append("You", style="bold")
            indicator = _delivery_indicator(msg, c)
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
            return Align.right(panel)
        else:
            name = escape(self._peer_name or "Peer")
            header = Text()
            header.append(f"{ts}  ", style="dim")
            header.append(name, style=f"bold {c.get('recv_name', '')}")
            body = Markdown(msg.content)
            return Panel(
                body,
                title=header,
                title_align="left",
                border_style=c.get("recv_border", ""),
                expand=False,
            )


class MessageList(VerticalScroll):
    """Scrollable message history for a single conversation."""

    def __init__(self, **kwargs) -> None:
        # Strip RichLog-specific kwargs that callers may pass.
        kwargs.pop("highlight", None)
        kwargs.pop("markup", None)
        super().__init__(**kwargs)
        self._last_date: str = ""
        self._messages: list[Message] = []
        self._peer_name: str = ""

    def on_mount(self) -> None:
        self.app.theme_changed_signal.subscribe(self, self._on_theme_changed)

    def _on_theme_changed(self, _theme) -> None:
        for child in self.query(_CHILDREN_SELECTOR):
            child.refresh()

    @property
    def message_count(self) -> int:
        """Number of message bubbles currently displayed."""
        return len(self.query(_Bubble))

    def _maybe_date_separator(self, msg: Message) -> _DateSep | None:
        """Return a _DateSep widget if the message is on a new day."""
        date_str = _local_date(msg.timestamp)
        if date_str != self._last_date:
            self._last_date = date_str
            return _DateSep(date_str)
        return None

    def add_chat_message(self, msg: Message, peer_name: str = "") -> None:
        """Append a single message to the log."""
        self._messages.append(msg)
        self._peer_name = peer_name
        sep = self._maybe_date_separator(msg)
        if sep:
            self.mount(sep)
        self.mount(_Bubble(msg, peer_name))
        self.scroll_end(animate=False)

    def load_history(self, messages: list[Message], peer_name: str = "") -> None:
        """Clear and reload the full message history."""
        self._messages = list(messages)
        self._peer_name = peer_name
        self._rerender()

    def clear(self) -> None:
        """Remove all messages from the display."""
        self._messages.clear()
        self._last_date = ""
        self.query(_CHILDREN_SELECTOR).remove()

    def _rerender(self) -> None:
        self.query(_CHILDREN_SELECTOR).remove()
        self._last_date = ""
        widgets: list[_DateSep | _Bubble] = []
        for msg in self._messages:
            sep = self._maybe_date_separator(msg)
            if sep:
                widgets.append(sep)
            widgets.append(_Bubble(msg, self._peer_name))
        if widgets:
            self.mount(*widgets)
            self.scroll_end(animate=False)
