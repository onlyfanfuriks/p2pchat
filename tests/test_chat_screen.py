"""Tests for the ChatScreen.

Tests contact selection, message sending, peer status updates,
and key binding actions.
"""

import time

from unittest.mock import AsyncMock

from textual.app import App

from p2pchat.core.account import Account
from p2pchat.core.crypto import generate_ed25519_keypair, generate_x25519_keypair
from p2pchat.core.storage import Contact, Message, Storage

from p2pchat.ui.screens.chat import ChatScreen
from p2pchat.ui.screens.contacts import ContactList
from p2pchat.ui.widgets.message_list import MessageList
from p2pchat.ui.widgets.status_bar import StatusBar


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_account():
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return Account(
        ed25519_private=ed_priv,
        ed25519_public=ed_pub,
        x25519_private=x_priv,
        x25519_public=x_pub,
        display_name="TestUser",
        ygg_address="200:test::1",
    )


def _make_contact(peer_id="peer1", name="Bob"):
    return Contact(
        peer_id=peer_id,
        display_name=name,
        x25519_pub="dummy",
        trusted=True,
        added_at=int(time.time()),
    )


class ChatTestApp(App):
    CSS_PATH = None

    def __init__(self, account, storage, send_cb=None):
        super().__init__()
        self._account = account
        self._storage = storage
        self._send_cb = send_cb

    def on_mount(self) -> None:
        self.push_screen(
            ChatScreen(
                account=self._account,
                storage=self._storage,
                send_callback=self._send_cb,
            )
        )


async def _make_storage(tmp_path, account):
    from p2pchat.core.storage import derive_db_key
    db_key = derive_db_key(account.ed25519_private)
    storage = Storage(tmp_path / "test.db", db_key)
    await storage.initialize()
    return storage


# ---------------------------------------------------------------------------
# TestChatScreenComposition
# ---------------------------------------------------------------------------

class TestChatScreenComposition:
    async def test_screen_has_all_widgets(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            assert screen.query_one("#status-bar", StatusBar)
            assert screen.query_one("#contact-list", ContactList)
            assert screen.query_one("#message-list", MessageList)
            assert screen.query("#chat-input")
        await storage.close()

    async def test_status_bar_shows_identity(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            sb = pilot.app.screen.query_one("#status-bar", StatusBar)
            assert sb.display_name == "TestUser"
            assert sb.ygg_address == "200:test::1"
        await storage.close()


# ---------------------------------------------------------------------------
# TestChatScreenPeerStatus
# ---------------------------------------------------------------------------

class TestChatScreenPeerStatus:
    async def test_peer_online_offline(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact()
        await storage.upsert_contact(contact)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen.on_peer_online("peer1")
            assert "peer1" in screen._online_peers
            screen.on_peer_offline("peer1")
            assert "peer1" not in screen._online_peers
        await storage.close()


# ---------------------------------------------------------------------------
# TestChatScreenMessageReceived
# ---------------------------------------------------------------------------

class TestChatScreenMessageReceived:
    async def test_message_for_selected_peer_shows_in_list(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact()
        await storage.upsert_contact(contact)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen._selected_peer = "peer1"
            msg = Message(
                peer_id="peer1", direction="received",
                content="hello", timestamp=int(time.time()),
            )
            ml = screen.query_one("#message-list", MessageList)
            initial_count = len(ml.lines)
            screen.on_message_received("peer1", msg, "Bob")
            await pilot.pause()
            assert len(ml.lines) > initial_count
        await storage.close()

    async def test_message_for_other_peer_increments_unread(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact("peer2", "Charlie")
        await storage.upsert_contact(contact)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen._selected_peer = "peer1"
            msg = Message(
                peer_id="peer2", direction="received",
                content="yo", timestamp=int(time.time()),
            )
            screen.on_message_received("peer2", msg, "Charlie")
            assert screen._unread.get("peer2") == 1
        await storage.close()


# ---------------------------------------------------------------------------
# TestChatScreenSetStatus
# ---------------------------------------------------------------------------

class TestChatScreenSetStatus:
    async def test_set_status_updates_bar(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen.set_status("connecting\u2026", "accent")
            sb = screen.query_one("#status-bar", StatusBar)
            assert sb.status_text == "connecting\u2026"
            assert sb.has_class("status--accent")
        await storage.close()


# ---------------------------------------------------------------------------
# TestChatScreenActions
# ---------------------------------------------------------------------------

class TestChatScreenActions:
    async def test_toggle_contacts_hides_panel(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            cl = screen.query_one("#contact-list", ContactList)
            assert cl.display is True
            screen.action_toggle_contacts()
            assert cl.display is False
            screen.action_toggle_contacts()
            assert cl.display is True
        await storage.close()

    async def test_delete_chat_no_peer_selected(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            # No peer selected — should notify warning without error.
            await screen.action_delete_chat()
            await pilot.pause()
        await storage.close()

    async def test_delete_chat_clears_messages(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact()
        await storage.upsert_contact(contact)
        msg = Message(
            peer_id="peer1", direction="sent",
            content="test", timestamp=int(time.time()),
        )
        await storage.save_message(msg)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen._selected_peer = "peer1"
            await screen.action_delete_chat()
            await pilot.pause()
            # Messages should be soft-deleted.
            msgs = await storage.get_messages("peer1")
            assert len(msgs) == 0
        await storage.close()

    async def test_backup_action_notifies(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen.action_backup()
            await pilot.pause()
        await storage.close()

    async def test_wipe_action_notifies(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen.action_wipe()
            await pilot.pause()
        await storage.close()

    async def test_focus_input_action(self, tmp_path):
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen.action_focus_input()
            await pilot.pause()
            from p2pchat.ui.widgets.chat_input import ChatInput
            ci = screen.query_one("#chat-input", ChatInput)
            assert ci.has_focus
        await storage.close()


# ---------------------------------------------------------------------------
# TestChatScreenMessageSending
# ---------------------------------------------------------------------------

class TestChatScreenMessageSending:
    async def test_submit_no_peer_selected(self, tmp_path):
        """Sending without a selected peer notifies warning."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            from p2pchat.ui.widgets.chat_input import ChatInput
            ci = screen.query_one("#chat-input", ChatInput)
            ci.focus()
            ci.value = "hello"
            await ci.action_submit()
            await pilot.pause()
            # Should not crash — just notifies "Select a contact first"
        await storage.close()

    async def test_submit_with_peer_saves_message(self, tmp_path):
        """Sending with a selected peer saves message to storage."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact()
        await storage.upsert_contact(contact)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            screen._selected_peer = "peer1"
            from p2pchat.ui.widgets.chat_input import ChatInput
            ci = screen.query_one("#chat-input", ChatInput)
            ci.focus()
            ci.value = "hello peer"
            await ci.action_submit()
            await pilot.pause()
            msgs = await storage.get_messages("peer1")
            assert any(m.content == "hello peer" for m in msgs)
        await storage.close()

    async def test_submit_with_send_callback(self, tmp_path):
        """Send callback is invoked on message submit."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact()
        await storage.upsert_contact(contact)
        send_cb = AsyncMock(return_value=None)

        async with ChatTestApp(account, storage, send_cb=send_cb).run_test() as pilot:
            screen = pilot.app.screen
            screen._selected_peer = "peer1"
            from p2pchat.ui.widgets.chat_input import ChatInput
            ci = screen.query_one("#chat-input", ChatInput)
            ci.focus()
            ci.value = "callback test"
            await ci.action_submit()
            await pilot.pause()
            # Third arg is the auto-generated message ID.
            send_cb.assert_awaited_once()
            args = send_cb.call_args[0]
            assert args[0] == "peer1"
            assert args[1] == "callback test"
            assert len(args[2]) > 0  # message_id is a UUID string
        await storage.close()

    async def test_submit_callback_failure_notifies(self, tmp_path):
        """Failed send callback notifies error without crashing."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact()
        await storage.upsert_contact(contact)
        send_cb = AsyncMock(side_effect=ConnectionError("offline"))

        async with ChatTestApp(account, storage, send_cb=send_cb).run_test() as pilot:
            screen = pilot.app.screen
            screen._selected_peer = "peer1"
            from p2pchat.ui.widgets.chat_input import ChatInput
            ci = screen.query_one("#chat-input", ChatInput)
            ci.focus()
            ci.value = "fail test"
            await ci.action_submit()
            await pilot.pause()
            # Should not crash
        await storage.close()


# ---------------------------------------------------------------------------
# TestChatScreenContactSelection
# ---------------------------------------------------------------------------

class TestChatScreenContactSelection:
    async def test_load_messages_on_contact_select(self, tmp_path):
        """Selecting a contact loads their message history."""
        account = _make_account()
        storage = await _make_storage(tmp_path, account)
        contact = _make_contact()
        await storage.upsert_contact(contact)
        msg = Message(
            peer_id="peer1", direction="received",
            content="history msg", timestamp=int(time.time()),
        )
        await storage.save_message(msg)

        async with ChatTestApp(account, storage).run_test() as pilot:
            screen = pilot.app.screen
            await screen._on_contact_selected(ContactList.Selected("peer1"))
            await pilot.pause()
            assert screen._selected_peer == "peer1"
            ml = screen.query_one("#message-list", MessageList)
            assert len(ml.lines) > 0
        await storage.close()
