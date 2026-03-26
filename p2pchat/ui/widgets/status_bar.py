"""Connection state indicator bar.

Displays the current app status: ready, connecting, error, etc.
Color changes reflect state — no animations.
"""

from __future__ import annotations

from rich.markup import escape
from textual.reactive import reactive
from textual.widgets import Static


class StatusBar(Static):
    """Single-line status indicator at the top of the chat screen."""

    display_name: reactive[str] = reactive("", layout=True)
    ygg_address: reactive[str] = reactive("", layout=True)
    status_text: reactive[str] = reactive("starting\u2026", layout=True)
    _severity: str = "default"

    _STATUS_ICONS = {
        "default": "\u2500",
        "accent": "\u25b6",
        "error": "\u2718",
        "warning": "\u25b2",
        "success": "\u2714",
    }

    def render(self) -> str:
        icon = self._STATUS_ICONS.get(self._severity, "\u2500")
        parts: list[str] = ["[bold]p2pchat[/bold]"]
        if self.display_name:
            parts.append(escape(self.display_name))
        if self.ygg_address:
            parts.append(f"[dim]{self.ygg_address}[/dim]")
        parts.append(f"{icon} {self.status_text}")
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
        self._severity = severity
        self.remove_class(
            "status--accent", "status--error", "status--warning", "status--success",
        )
        if severity != "default":
            self.add_class(f"status--{severity}")
