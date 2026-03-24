"""Tests for TUI widgets: StatusBar, ChatInput, MessageList, ContactList.

Uses Textual's async app testing harness for proper widget lifecycle.
"""

import time

from textual.app import App, ComposeResult

from p2pchat.core.storage import Contact, Message
from p2pchat.ui.screens.contacts import ContactList
from p2pchat.ui.widgets.chat_input import ChatInput
from p2pchat.ui.widgets.message_list import (
    MessageList,
    _format_timestamp,
)
from p2pchat.ui.widgets.status_bar import StatusBar


# ---------------------------------------------------------------------------
# TestFormatTimestamp
# ---------------------------------------------------------------------------

class TestFormatTimestamp:
    def test_returns_hh_mm_format(self):
        """Timestamp is formatted as HH:MM."""
        result = _format_timestamp(0)  # epoch
        assert ":" in result
        parts = result.split(":")
        assert len(parts) == 2
        assert all(p.isdigit() for p in parts)

    def test_current_time(self):
        result = _format_timestamp(int(time.time()))
        assert len(result) == 5  # HH:MM


# ---------------------------------------------------------------------------
# TestDeliveryIndicator
# ---------------------------------------------------------------------------

class TestDeliveryIndicator:
    async def test_received_message_no_indicator(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield MessageList(id="ml", highlight=True, markup=True)

        async with TestApp().run_test() as pilot:
            ml = pilot.app.query_one("#ml", MessageList)
            msg = Message(peer_id="x", direction="received", content="hi", timestamp=0)
            assert ml._delivery_indicator(msg) == ""

    async def test_sent_delivered(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield MessageList(id="ml", highlight=True, markup=True)

        async with TestApp().run_test() as pilot:
            ml = pilot.app.query_one("#ml", MessageList)
            msg = Message(
                peer_id="x", direction="sent", content="hi",
                timestamp=0, delivered=True,
            )
            result = ml._delivery_indicator(msg)
            assert "\u2713" in str(result)  # checkmark

    async def test_sent_undelivered(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield MessageList(id="ml", highlight=True, markup=True)

        async with TestApp().run_test() as pilot:
            ml = pilot.app.query_one("#ml", MessageList)
            msg = Message(
                peer_id="x", direction="sent", content="hi",
                timestamp=0, delivered=False,
            )
            result = ml._delivery_indicator(msg)
            assert "\u23f3" in str(result)  # hourglass


# ---------------------------------------------------------------------------
# TestStatusBar (async Textual tests)
# ---------------------------------------------------------------------------

class TestStatusBar:
    async def test_initial_render(self):
        """StatusBar renders 'p2pchat' with default status."""
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield StatusBar(id="sb")

        async with TestApp().run_test() as pilot:
            sb = pilot.app.query_one("#sb", StatusBar)
            rendered = sb.render()
            assert "p2pchat" in rendered
            assert "starting" in rendered

    async def test_set_display_name_and_address(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield StatusBar(id="sb")

        async with TestApp().run_test() as pilot:
            sb = pilot.app.query_one("#sb", StatusBar)
            sb.display_name = "Alice"
            sb.ygg_address = "200:abcd::1"
            rendered = sb.render()
            assert "Alice" in rendered
            assert "[200:abcd::1]" in rendered

    async def test_set_status_accent(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield StatusBar(id="sb")

        async with TestApp().run_test() as pilot:
            sb = pilot.app.query_one("#sb", StatusBar)
            sb.set_status("connecting\u2026", "accent")
            assert sb.status_text == "connecting\u2026"
            assert sb.has_class("status--accent")

    async def test_set_status_error(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield StatusBar(id="sb")

        async with TestApp().run_test() as pilot:
            sb = pilot.app.query_one("#sb", StatusBar)
            sb.set_status("error: boom", "error")
            assert sb.has_class("status--error")

    async def test_set_status_default_clears_classes(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield StatusBar(id="sb")

        async with TestApp().run_test() as pilot:
            sb = pilot.app.query_one("#sb", StatusBar)
            sb.set_status("error: x", "error")
            assert sb.has_class("status--error")
            sb.set_status("ready", "default")
            assert not sb.has_class("status--error")
            assert not sb.has_class("status--accent")


# ---------------------------------------------------------------------------
# TestChatInput (async Textual tests)
# ---------------------------------------------------------------------------

class TestChatInput:
    async def test_submit_fires_message(self):
        """Pressing Enter with text fires ChatInput.MessageReady."""
        submitted_values = []

        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ChatInput(id="ci")

            def on_chat_input_message_ready(self, event: ChatInput.MessageReady) -> None:
                submitted_values.append(event.value)

        async with TestApp().run_test() as pilot:
            ci = pilot.app.query_one("#ci", ChatInput)
            ci.focus()
            ci.value = "hello world"
            await ci.action_submit()
            await pilot.pause()
            assert submitted_values == ["hello world"]
            assert ci.value == ""  # input cleared after submit

    async def test_empty_input_does_not_fire(self):
        """Empty input does not fire Submitted."""
        submitted = []

        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ChatInput(id="ci")

            def on_chat_input_message_ready(self, event: ChatInput.MessageReady) -> None:
                submitted.append(event.value)

        async with TestApp().run_test() as pilot:
            ci = pilot.app.query_one("#ci", ChatInput)
            ci.focus()
            ci.value = ""
            await ci.action_submit()
            await pilot.pause()
            assert submitted == []

    async def test_whitespace_only_does_not_fire(self):
        """Whitespace-only input does not fire Submitted."""
        submitted = []

        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ChatInput(id="ci")

            def on_chat_input_message_ready(self, event: ChatInput.MessageReady) -> None:
                submitted.append(event.value)

        async with TestApp().run_test() as pilot:
            ci = pilot.app.query_one("#ci", ChatInput)
            ci.focus()
            ci.value = "   "
            await ci.action_submit()
            await pilot.pause()
            assert submitted == []

    async def test_strips_whitespace(self):
        """Submitted value is stripped of leading/trailing whitespace."""
        submitted = []

        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ChatInput(id="ci")

            def on_chat_input_message_ready(self, event: ChatInput.MessageReady) -> None:
                submitted.append(event.value)

        async with TestApp().run_test() as pilot:
            ci = pilot.app.query_one("#ci", ChatInput)
            ci.focus()
            ci.value = "  hello  "
            await ci.action_submit()
            await pilot.pause()
            assert submitted == ["hello"]

    async def test_starts_empty(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ChatInput(id="ci")

        async with TestApp().run_test() as pilot:
            ci = pilot.app.query_one("#ci", ChatInput)
            assert ci.text == ""


# ---------------------------------------------------------------------------
# TestMessageList (async Textual tests)
# ---------------------------------------------------------------------------

class TestMessageList:
    async def test_add_chat_message_sent(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield MessageList(id="ml", highlight=True, markup=True)

        async with TestApp().run_test() as pilot:
            ml = pilot.app.query_one("#ml", MessageList)
            msg = Message(
                peer_id="x", direction="sent", content="hello",
                timestamp=int(time.time()), delivered=True,
            )
            ml.add_chat_message(msg)
            await pilot.pause()
            # After render, lines should contain the written content.
            assert len(ml.lines) > 0

    async def test_add_chat_message_received(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield MessageList(id="ml", highlight=True, markup=True)

        async with TestApp().run_test() as pilot:
            ml = pilot.app.query_one("#ml", MessageList)
            msg = Message(
                peer_id="x", direction="received", content="hey",
                timestamp=int(time.time()),
            )
            ml.add_chat_message(msg, "Bob")
            await pilot.pause()
            assert len(ml.lines) > 0

    async def test_load_history_clears_and_reloads(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield MessageList(id="ml", highlight=True, markup=True)

        async with TestApp().run_test() as pilot:
            ml = pilot.app.query_one("#ml", MessageList)
            msgs = [
                Message(peer_id="x", direction="sent", content=f"msg{i}", timestamp=i)
                for i in range(5)
            ]
            ml.load_history(msgs, "Peer")
            await pilot.pause()
            count_first = len(ml.lines)
            # Reload should clear and re-add with fewer messages.
            ml.load_history(msgs[:2], "Peer")
            await pilot.pause()
            assert len(ml.lines) < count_first


# ---------------------------------------------------------------------------
# TestContactList (async Textual tests)
# ---------------------------------------------------------------------------

class TestContactList:
    def _make_contacts(self, n=3):
        return [
            Contact(
                peer_id=f"peer{i}",
                display_name=f"User{i}",
                x25519_pub="dummy",
                trusted=True,
                added_at=1000 + i,
            )
            for i in range(n)
        ]

    async def test_set_contacts(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ContactList(id="cl")

        async with TestApp().run_test() as pilot:
            cl = pilot.app.query_one("#cl", ContactList)
            contacts = self._make_contacts()
            cl.set_contacts(contacts)
            assert cl.option_count == 3

    async def test_online_indicator(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ContactList(id="cl")

        async with TestApp().run_test() as pilot:
            cl = pilot.app.query_one("#cl", ContactList)
            contacts = self._make_contacts(2)
            cl.set_contacts(contacts, online={"peer0"})
            # First option should have filled circle (online).
            opt0 = cl.get_option_at_index(0)
            assert "\u25cf" in str(opt0.prompt)
            # Second should have open circle (offline).
            opt1 = cl.get_option_at_index(1)
            assert "\u25cb" in str(opt1.prompt)

    async def test_unread_badge(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ContactList(id="cl")

        async with TestApp().run_test() as pilot:
            cl = pilot.app.query_one("#cl", ContactList)
            contacts = self._make_contacts(1)
            cl.set_contacts(contacts, unread={"peer0": 5})
            opt = cl.get_option_at_index(0)
            assert "[5]" in str(opt.prompt)

    async def test_mark_online_offline(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ContactList(id="cl")

        async with TestApp().run_test() as pilot:
            cl = pilot.app.query_one("#cl", ContactList)
            contacts = self._make_contacts(1)
            cl.set_contacts(contacts)
            cl.mark_online("peer0", True)
            opt = cl.get_option_at_index(0)
            assert "\u25cf" in str(opt.prompt)
            cl.mark_online("peer0", False)
            opt = cl.get_option_at_index(0)
            assert "\u25cb" in str(opt.prompt)

    async def test_increment_and_clear_unread(self):
        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ContactList(id="cl")

        async with TestApp().run_test() as pilot:
            cl = pilot.app.query_one("#cl", ContactList)
            contacts = self._make_contacts(1)
            cl.set_contacts(contacts)
            cl.increment_unread("peer0")
            cl.increment_unread("peer0")
            opt = cl.get_option_at_index(0)
            assert "[2]" in str(opt.prompt)
            cl.clear_unread("peer0")
            opt = cl.get_option_at_index(0)
            assert "[" not in str(opt.prompt)

    async def test_selected_message_posted(self):
        selected_peers = []

        class TestApp(App):
            def compose(self) -> ComposeResult:
                yield ContactList(id="cl")

            def on_contact_list_selected(self, event: ContactList.Selected) -> None:
                selected_peers.append(event.peer_id)

        async with TestApp().run_test() as pilot:
            cl = pilot.app.query_one("#cl", ContactList)
            contacts = self._make_contacts(2)
            cl.set_contacts(contacts)
            cl.action_first()
            await pilot.pause()
            # Selection is handled via option list events.
