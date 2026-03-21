"""Connection state indicator bar.

Displays the current app status: ready, connecting, error, etc.
Color changes reflect state — no animations.
"""

from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static


class StatusBar(Static):
    """Single-line status indicator at the top of the chat screen."""

    display_name: reactive[str] = reactive("", layout=True)
    ygg_address: reactive[str] = reactive("", layout=True)
    status_text: reactive[str] = reactive("starting\u2026", layout=True)

    def render(self) -> str:
        parts: list[str] = ["p2pchat"]
        if self.display_name:
            parts.append(self.display_name)
        if self.ygg_address:
            parts.append(f"[{self.ygg_address}]")
        parts.append(self.status_text)
        return " \u2500 ".join(parts)

    def set_status(self, text: str, severity: str = "default") -> None:
        """Update status text and CSS class for color.

        Parameters
        ----------
        text:
            Status string (e.g. "ready", "connecting...", "error: ...").
        severity:
            One of "default", "accent", "error", "warning".
        """
        self.status_text = text
        self.remove_class("status--accent", "status--error", "status--warning")
        if severity != "default":
            self.add_class(f"status--{severity}")
