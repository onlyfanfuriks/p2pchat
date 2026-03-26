"""Tests for HelpScreen modal and HelpRow widget.

Verifies composition, binding sections, keybinding display,
and dismiss actions for both chat and unlock contexts.
"""

from textual.app import App, ComposeResult
from textual.widgets import Label

from p2pchat.ui.widgets.help_screen import (
    HelpScreen,
    HelpRow,
    _CHAT_BINDINGS,
    _UNLOCK_BINDINGS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class HelpTestApp(App):
    """Minimal app that pushes HelpScreen on mount."""

    def __init__(self, context: str = "chat") -> None:
        super().__init__()
        self._help_context = context

    def on_mount(self) -> None:
        self.push_screen(HelpScreen(context=self._help_context))


# ---------------------------------------------------------------------------
# TestHelpScreenChatContext
# ---------------------------------------------------------------------------

class TestHelpScreenChatContext:
    async def test_can_compose_without_error(self):
        """HelpScreen in chat context composes successfully."""
        async with HelpTestApp("chat").run_test() as pilot:
            screen = pilot.app.screen
            assert isinstance(screen, HelpScreen)

    async def test_has_chat_title(self):
        """Header label includes 'Chat Keybindings'."""
        async with HelpTestApp("chat").run_test() as pilot:
            header = pilot.app.screen.query_one(".help-header", Label)
            assert "Chat" in header.content

    async def test_all_chat_sections_present(self):
        """Every section from _CHAT_BINDINGS appears as a section title."""
        async with HelpTestApp("chat").run_test() as pilot:
            section_labels = pilot.app.screen.query(".help-section-title")
            section_texts = [lbl.content for lbl in section_labels]
            for section_name, _ in _CHAT_BINDINGS:
                assert section_name in section_texts, (
                    f"Section '{section_name}' not found in {section_texts}"
                )

    async def test_all_chat_keybindings_displayed(self):
        """Every keybinding from _CHAT_BINDINGS is rendered as a HelpRow."""
        expected_keys = []
        for _, keys in _CHAT_BINDINGS:
            for key, _desc in keys:
                expected_keys.append(key)

        async with HelpTestApp("chat").run_test() as pilot:
            rows = pilot.app.screen.query(HelpRow)
            assert len(list(rows)) == len(expected_keys)

    async def test_keybinding_key_and_desc_labels(self):
        """Each HelpRow contains the key and description as Labels."""
        async with HelpTestApp("chat").run_test() as pilot:
            rows = list(pilot.app.screen.query(HelpRow))
            # Check the first row from General section
            first_key, first_desc = _CHAT_BINDINGS[0][1][0]
            first_row = rows[0]
            key_label = first_row.query_one(".help-key", Label)
            desc_label = first_row.query_one(".help-desc", Label)
            assert key_label.content == first_key
            assert desc_label.content == first_desc

    async def test_footer_present(self):
        """Footer with dismiss hint is shown."""
        async with HelpTestApp("chat").run_test() as pilot:
            footer = pilot.app.screen.query_one(".help-footer", Label)
            text = footer.content
            assert "Escape" in text or "F1" in text

    async def test_no_unlock_sections_in_chat_context(self):
        """Unlock-only sections do not appear in chat context."""
        async with HelpTestApp("chat").run_test() as pilot:
            section_labels = pilot.app.screen.query(".help-section-title")
            section_texts = [lbl.content for lbl in section_labels]
            for section_name, _ in _UNLOCK_BINDINGS:
                if not any(s == section_name for s, _ in _CHAT_BINDINGS):
                    assert section_name not in section_texts


# ---------------------------------------------------------------------------
# TestHelpScreenUnlockContext
# ---------------------------------------------------------------------------

class TestHelpScreenUnlockContext:
    async def test_can_compose_without_error(self):
        """HelpScreen in unlock context composes successfully."""
        async with HelpTestApp("unlock").run_test() as pilot:
            screen = pilot.app.screen
            assert isinstance(screen, HelpScreen)

    async def test_has_account_title(self):
        """Header label includes 'Account Keybindings'."""
        async with HelpTestApp("unlock").run_test() as pilot:
            header = pilot.app.screen.query_one(".help-header", Label)
            assert "Account" in header.content

    async def test_all_unlock_sections_present(self):
        """Every section from _UNLOCK_BINDINGS appears."""
        async with HelpTestApp("unlock").run_test() as pilot:
            section_labels = pilot.app.screen.query(".help-section-title")
            section_texts = [lbl.content for lbl in section_labels]
            for section_name, _ in _UNLOCK_BINDINGS:
                assert section_name in section_texts

    async def test_all_unlock_keybindings_displayed(self):
        """Every keybinding from _UNLOCK_BINDINGS is rendered."""
        expected_keys = []
        for _, keys in _UNLOCK_BINDINGS:
            for key, _desc in keys:
                expected_keys.append(key)

        async with HelpTestApp("unlock").run_test() as pilot:
            rows = pilot.app.screen.query(HelpRow)
            assert len(list(rows)) == len(expected_keys)


# ---------------------------------------------------------------------------
# TestHelpScreenDismiss
# ---------------------------------------------------------------------------

class TestHelpScreenDismiss:
    async def test_dismiss_action_pops_screen(self):
        """action_dismiss_help removes the HelpScreen."""
        async with HelpTestApp("chat").run_test() as pilot:
            assert isinstance(pilot.app.screen, HelpScreen)
            pilot.app.screen.action_dismiss_help()
            await pilot.pause()
            assert not isinstance(pilot.app.screen, HelpScreen)

    async def test_escape_key_dismisses(self):
        """Pressing Escape dismisses the help screen."""
        async with HelpTestApp("chat").run_test() as pilot:
            assert isinstance(pilot.app.screen, HelpScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(pilot.app.screen, HelpScreen)

    async def test_f1_key_dismisses(self):
        """Pressing F1 dismisses the help screen."""
        async with HelpTestApp("chat").run_test() as pilot:
            assert isinstance(pilot.app.screen, HelpScreen)
            await pilot.press("f1")
            await pilot.pause()
            assert not isinstance(pilot.app.screen, HelpScreen)


# ---------------------------------------------------------------------------
# TestHelpRow
# ---------------------------------------------------------------------------

class TestHelpRow:
    async def test_row_has_correct_classes(self):
        """HelpRow gets 'help-row' class."""
        class RowApp(App):
            def compose(self) -> ComposeResult:
                yield HelpRow("ctrl+q", "Quit")

        async with RowApp().run_test() as pilot:
            row = pilot.app.query_one(HelpRow)
            assert row.has_class("help-row")

    async def test_row_contains_key_and_desc(self):
        """HelpRow renders key and description labels."""
        class RowApp(App):
            def compose(self) -> ComposeResult:
                yield HelpRow("ctrl+q", "Quit")

        async with RowApp().run_test() as pilot:
            row = pilot.app.query_one(HelpRow)
            key_label = row.query_one(".help-key", Label)
            desc_label = row.query_one(".help-desc", Label)
            assert key_label.content == "ctrl+q"
            assert desc_label.content == "Quit"


# ---------------------------------------------------------------------------
# TestHelpScreenDefaults
# ---------------------------------------------------------------------------

class TestHelpScreenDefaults:
    async def test_default_context_is_chat(self):
        """HelpScreen defaults to chat context when no arg is given."""
        class DefaultApp(App):
            def on_mount(self) -> None:
                self.push_screen(HelpScreen())

        async with DefaultApp().run_test() as pilot:
            screen = pilot.app.screen
            assert isinstance(screen, HelpScreen)
            header = screen.query_one(".help-header", Label)
            assert "Chat" in header.content

    async def test_help_dialog_container_exists(self):
        """The help-dialog vertical scroll container is present."""
        async with HelpTestApp("chat").run_test() as pilot:
            from textual.containers import VerticalScroll
            container = pilot.app.screen.query_one("#help-dialog", VerticalScroll)
            assert container is not None

    async def test_unknown_context_falls_back_to_unlock(self):
        """A non-'chat' context falls back to unlock bindings."""
        async with HelpTestApp("unknown").run_test() as pilot:
            section_labels = pilot.app.screen.query(".help-section-title")
            section_texts = [lbl.content for lbl in section_labels]
            for section_name, _ in _UNLOCK_BINDINGS:
                assert section_name in section_texts
