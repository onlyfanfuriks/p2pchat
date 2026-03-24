"""Tests for the ChatApp top-level application.

Tests screen transitions, shutdown, and initialization flow.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from p2pchat.app import ChatApp
from p2pchat.core.account import Account
from p2pchat.core.crypto import generate_ed25519_keypair, generate_x25519_keypair
from p2pchat.ui.screens.unlock import UnlockScreen


class _TestChatApp(ChatApp):
    """ChatApp without CSS for test isolation."""
    CSS_PATH = None


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


# ---------------------------------------------------------------------------
# TestChatAppInit
# ---------------------------------------------------------------------------

class TestChatAppInit:
    def test_initial_state(self):
        app = ChatApp()
        assert app._account is None
        assert app._storage is None
        assert app._ygg_node is None
        assert app._chat_server is None

    async def test_mounts_unlock_screen(self):
        with patch.object(Account, "exists", return_value=True):
            async with _TestChatApp().run_test(size=(80, 24)) as pilot:
                await pilot.pause()
                assert isinstance(pilot.app.screen, UnlockScreen)


# ---------------------------------------------------------------------------
# TestChatAppShutdown
# ---------------------------------------------------------------------------

class TestChatAppShutdown:
    async def test_cleanup_resources_no_resources(self):
        """Shutdown is safe when nothing was started."""
        app = ChatApp()
        await app._cleanup_resources()

    async def test_cleanup_resources_stops_all_resources(self):
        """Shutdown calls stop/close on all started resources."""
        app = ChatApp()
        app._chat_server = MagicMock()
        app._chat_server.stop = AsyncMock()
        app._ygg_node = MagicMock()
        app._ygg_node.stop = AsyncMock()
        app._storage = MagicMock()
        app._storage.close = AsyncMock()

        await app._cleanup_resources()

        app._chat_server.stop.assert_awaited_once()
        app._ygg_node.stop.assert_awaited_once()
        app._storage.close.assert_awaited_once()

    async def test_cleanup_resources_handles_exceptions(self):
        """Shutdown continues even if one resource raises."""
        app = ChatApp()
        app._chat_server = MagicMock()
        app._chat_server.stop = AsyncMock(side_effect=RuntimeError("boom"))
        app._ygg_node = MagicMock()
        app._ygg_node.stop = AsyncMock()
        app._storage = MagicMock()
        app._storage.close = AsyncMock()

        # Should not raise.
        await app._cleanup_resources()
        # Other resources still cleaned up.
        app._ygg_node.stop.assert_awaited_once()
        app._storage.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# TestChatAppSendMessage
# ---------------------------------------------------------------------------

class TestChatAppSendMessage:
    async def test_send_no_session_no_outbox(self):
        """Without outbox or session, returns None."""
        app = ChatApp()
        result = await app._send_message("peer1", "hello", "msg-1")
        assert result is None

    async def test_send_via_active_session(self):
        """Direct send through active session."""
        app = ChatApp()
        session = MagicMock()
        session.state = "active"
        session.send_message = AsyncMock(return_value="wire-id")
        app._sessions["peer1"] = session

        result = await app._send_message("peer1", "hello", "msg-1")
        assert result == "wire-id"
        session.send_message.assert_awaited_once_with("hello", "msg-1")

    async def test_send_falls_through_to_outbox_on_session_failure(self):
        """If session send fails, message is enqueued in outbox."""
        app = ChatApp()
        session = MagicMock()
        session.state = "active"
        session.send_message = AsyncMock(side_effect=ConnectionError("dead"))
        app._sessions["peer1"] = session

        mock_outbox = MagicMock()
        mock_outbox.enqueue = AsyncMock(return_value="outbox-id")
        mock_outbox.start_retry = MagicMock()
        app._outbox = mock_outbox

        result = await app._send_message("peer1", "hello", "msg-1")
        assert result == "outbox-id"
        mock_outbox.enqueue.assert_awaited_once_with("peer1", "hello", "msg-1")

    async def test_send_enqueues_when_no_session(self):
        """Without active session, message goes to outbox."""
        app = ChatApp()
        mock_outbox = MagicMock()
        mock_outbox.enqueue = AsyncMock(return_value="outbox-id")
        mock_outbox.start_retry = MagicMock()
        app._outbox = mock_outbox

        result = await app._send_message("peer1", "hello", "msg-1")
        assert result == "outbox-id"
        mock_outbox.start_retry.assert_called_once()


# ---------------------------------------------------------------------------
# TestChatAppVerifyPeerDefinition
# ---------------------------------------------------------------------------

class TestChatAppVerifyPeerDefinition:
    def test_verify_peer_is_coroutine(self):
        """_verify_peer is an async method suitable as a callback."""
        import asyncio
        app = ChatApp()
        assert asyncio.iscoroutinefunction(app._verify_peer)


# ---------------------------------------------------------------------------
# TestChatAppStartNetwork
# ---------------------------------------------------------------------------

class TestChatAppStartNetwork:
    async def test_start_network_returns_early_without_account(self):
        """_start_network returns early when no account is set."""
        app = ChatApp()
        app._account = None
        app._chat_screen = MagicMock()
        await app._start_network()
        # Should not crash

    async def test_start_network_returns_early_without_chat_screen(self):
        app = ChatApp()
        app._account = _make_account()
        app._chat_screen = None
        await app._start_network()

    async def test_start_network_ygg_failure(self):
        """If Yggdrasil fails, network start reports error."""
        app = ChatApp()
        app._account = _make_account()
        app._chat_screen = MagicMock()
        app._chat_screen.set_status = MagicMock()

        with patch.object(app, "_start_yggdrasil", new_callable=AsyncMock, side_effect=RuntimeError("ygg fail")):
            await app._start_network()

        app._chat_screen.set_status.assert_any_call("error: ygg fail", "error")

    async def test_start_network_server_failure(self):
        """If server fails, network start reports error."""
        app = ChatApp()
        app._account = _make_account()
        app._chat_screen = MagicMock()
        app._chat_screen.set_status = MagicMock()

        with patch.object(app, "_start_yggdrasil", new_callable=AsyncMock), \
             patch.object(app, "_start_chat_server", new_callable=AsyncMock, side_effect=RuntimeError("srv fail")):
            await app._start_network()

        app._chat_screen.set_status.assert_any_call("error: srv fail", "error")

    async def test_start_network_success(self):
        """Successful network start sets status to ready and starts outbox retries."""
        app = ChatApp()
        app._account = _make_account()
        app._chat_screen = MagicMock()
        app._chat_screen.set_status = MagicMock()

        with patch.object(app, "_start_yggdrasil", new_callable=AsyncMock), \
             patch.object(app, "_start_chat_server", new_callable=AsyncMock), \
             patch.object(app, "_start_outbox_retries", new_callable=AsyncMock) as mock_retries:
            await app._start_network()

        app._chat_screen.set_status.assert_any_call("ready", "success")
        mock_retries.assert_awaited_once()


# ---------------------------------------------------------------------------
# TestChatAppActionQuit
# ---------------------------------------------------------------------------

class TestChatAppActionQuit:
    async def test_action_quit_calls_cleanup_and_exit(self):
        app = ChatApp()
        app.exit = MagicMock()
        with patch.object(app, "_cleanup_resources", new_callable=AsyncMock) as mock_cleanup:
            await app.action_quit()
            mock_cleanup.assert_awaited_once()
            app.exit.assert_called_once()


# ---------------------------------------------------------------------------
# TestChatAppStartYggdrasil
# ---------------------------------------------------------------------------

class TestChatAppStartYggdrasil:
    async def test_returns_early_without_account(self):
        app = ChatApp()
        app._account = None
        await app._start_yggdrasil()
        # Should not crash

    async def test_returns_early_without_storage_in_chat_server(self):
        app = ChatApp()
        app._account = None
        app._storage = None
        await app._start_chat_server()


# ---------------------------------------------------------------------------
# TestChatAppOnSessionReady
# ---------------------------------------------------------------------------

async def _empty_receive_loop():
    """Async generator that yields nothing — used as a mock receive_loop."""
    for _ in []:
        yield


def _mock_session_with_empty_loop(peer_id="peer1"):
    """Create a mock session whose receive_loop yields nothing."""
    session = MagicMock()
    session.peer_id = peer_id
    session.receive_loop = _empty_receive_loop
    return session


def _mock_chat_screen():
    """Create a MagicMock chat screen with async on_peer_online/offline."""
    screen = MagicMock()
    screen.on_peer_online = AsyncMock()
    screen.on_peer_offline = AsyncMock()
    return screen


class TestChatAppOnSessionReady:
    async def test_on_session_ready_no_chat_screen(self):
        """Session ready with no chat screen doesn't crash."""
        app = ChatApp()
        app._chat_screen = None
        await app._on_session_ready(_mock_session_with_empty_loop())

    async def test_on_session_ready_tracks_session(self):
        """Session is registered and unregistered in _sessions."""
        app = ChatApp()
        app._chat_screen = _mock_chat_screen()
        await app._on_session_ready(_mock_session_with_empty_loop())
        assert "peer1" not in app._sessions

    async def test_on_session_ready_drains_outbox(self):
        """Session ready drains outbox and cancels retry."""
        app = ChatApp()
        app._chat_screen = _mock_chat_screen()
        mock_outbox = MagicMock()
        mock_outbox.drain = AsyncMock(return_value=0)
        mock_outbox.cancel_retry = MagicMock()
        app._outbox = mock_outbox

        mock_session = _mock_session_with_empty_loop()
        await app._on_session_ready(mock_session)

        mock_outbox.cancel_retry.assert_called_once_with("peer1")
        mock_outbox.drain.assert_awaited_once_with(mock_session)

    async def test_on_session_ready_restarts_retry_on_drain_failure(self):
        """If drain fails, retry loop is restarted."""
        app = ChatApp()
        app._chat_screen = _mock_chat_screen()
        mock_outbox = MagicMock()
        mock_outbox.drain = AsyncMock(side_effect=ConnectionError("dead"))
        mock_outbox.cancel_retry = MagicMock()
        mock_outbox.start_retry = MagicMock()
        app._outbox = mock_outbox

        await app._on_session_ready(_mock_session_with_empty_loop())
        mock_outbox.start_retry.assert_called_once()

    async def test_on_session_ready_preserves_newer_session(self):
        """Finally block doesn't remove a newer session for the same peer."""
        app = ChatApp()
        app._chat_screen = _mock_chat_screen()
        newer_session = MagicMock()

        mock_session_old = MagicMock()
        mock_session_old.peer_id = "peer1"

        async def _receive_loop():
            # Simulate newer session registering while old one is active.
            app._sessions["peer1"] = newer_session
            for _ in []:
                yield

        mock_session_old.receive_loop = _receive_loop

        await app._on_session_ready(mock_session_old)
        assert app._sessions.get("peer1") is newer_session


# ---------------------------------------------------------------------------
# TestChatAppOutboxIntegration
# ---------------------------------------------------------------------------

class TestChatAppOutboxIntegration:
    async def test_cleanup_stops_outbox(self):
        """Cleanup calls outbox.stop()."""
        app = ChatApp()
        mock_outbox = MagicMock()
        mock_outbox.stop = AsyncMock()
        app._outbox = mock_outbox

        await app._cleanup_resources()
        mock_outbox.stop.assert_awaited_once()

    async def test_start_outbox_retries_no_outbox(self):
        """_start_outbox_retries is safe when no outbox."""
        app = ChatApp()
        app._outbox = None
        await app._start_outbox_retries()

    async def test_start_outbox_retries_starts_tasks(self):
        """_start_outbox_retries starts retry for each pending peer."""
        app = ChatApp()
        mock_outbox = MagicMock()
        mock_outbox.start_retry = MagicMock()
        app._outbox = mock_outbox

        mock_storage = MagicMock()
        item1 = MagicMock()
        item1.peer_id = "peer1"
        item2 = MagicMock()
        item2.peer_id = "peer2"
        mock_storage.get_all_pending_outbox = AsyncMock(return_value=[item1, item2])
        app._storage = mock_storage

        await app._start_outbox_retries()
        assert mock_outbox.start_retry.call_count == 2

    async def test_connect_for_outbox_no_account_raises(self):
        """_connect_for_outbox raises when not initialized."""
        app = ChatApp()
        app._account = None
        with pytest.raises(RuntimeError):
            await app._connect_for_outbox("peer1")

    async def test_connect_for_outbox_no_contact_raises(self, tmp_path):
        """_connect_for_outbox raises for unknown contact."""
        app = ChatApp()
        app._account = _make_account()
        mock_storage = MagicMock()
        mock_storage.get_contact = AsyncMock(return_value=None)
        app._storage = mock_storage
        app._config_dir = tmp_path

        with pytest.raises(ValueError, match="No address"):
            await app._connect_for_outbox("peer1")


# ---------------------------------------------------------------------------
# TestChatAppConnectRequest
# ---------------------------------------------------------------------------

class TestChatAppConnectRequest:
    def _make_info(self, name="Bob", address="200:beef::1", port=7331):
        from p2pchat.ui.widgets.invite_modal import InviteInfo
        return InviteInfo(
            ygg_address=address,
            port=port,
            ed25519_pub=b"\x00" * 32,
            display_name=name,
        )

    def _make_event(self, info=None):
        from p2pchat.ui.screens.chat import ConnectRequest
        return ConnectRequest(info or self._make_info())

    async def test_connect_not_initialized(self):
        """Connect request before init notifies error."""
        app = ChatApp()
        app._account = None
        app.notify = MagicMock()

        await app.on_connect_request(self._make_event())
        app.notify.assert_called_once_with("Not initialized yet", severity="error")

    async def test_connect_success(self):
        """Successful connect creates session task."""
        app = ChatApp()
        app._account = _make_account()
        app._storage = MagicMock()
        app._config_dir = MagicMock()
        app.notify = MagicMock()

        mock_session = MagicMock()
        mock_session.peer_id = "peer-bob"

        with patch("p2pchat.core.network.peer.connect", new_callable=AsyncMock, return_value=mock_session) as mock_connect:
            with patch.object(app, "_on_session_ready", new_callable=AsyncMock):
                await app._do_connect(self._make_info())
                mock_connect.assert_awaited_once()

        calls = [c.args[0] for c in app.notify.call_args_list]
        assert any("Connecting" in c for c in calls)
        assert any("Connected" in c for c in calls)

    async def test_connect_timeout(self):
        """Timeout during connect notifies error."""
        import asyncio as _aio
        app = ChatApp()
        app._account = _make_account()
        app._storage = MagicMock()
        app._config_dir = MagicMock()
        app.notify = MagicMock()

        with patch("p2pchat.core.network.peer.connect", new_callable=AsyncMock, side_effect=_aio.TimeoutError):
            await app._do_connect(self._make_info())

        calls = [c.args[0] for c in app.notify.call_args_list]
        assert any("timed out" in c for c in calls)

    async def test_connect_os_error(self):
        """Network error during connect notifies error."""
        app = ChatApp()
        app._account = _make_account()
        app._storage = MagicMock()
        app._config_dir = MagicMock()
        app.notify = MagicMock()

        with patch("p2pchat.core.network.peer.connect", new_callable=AsyncMock, side_effect=OSError("No route")):
            await app._do_connect(self._make_info())

        calls = [c.args[0] for c in app.notify.call_args_list]
        assert any("Cannot reach" in c for c in calls)

    async def test_connect_generic_exception(self):
        """Unexpected error during connect notifies error."""
        app = ChatApp()
        app._account = _make_account()
        app._storage = MagicMock()
        app._config_dir = MagicMock()
        app.notify = MagicMock()

        with patch("p2pchat.core.network.peer.connect", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            await app._do_connect(self._make_info())

        calls = [c.args[0] for c in app.notify.call_args_list]
        assert any("failed" in c.lower() for c in calls)

    async def test_connect_uses_display_name_in_notification(self):
        """Notification uses display name when available."""
        app = ChatApp()
        app._account = _make_account()
        app._storage = MagicMock()
        app._config_dir = MagicMock()
        app.notify = MagicMock()

        with patch("p2pchat.core.network.peer.connect", new_callable=AsyncMock, side_effect=OSError("nope")):
            await app._do_connect(self._make_info(name="Alice"))

        calls = [c.args[0] for c in app.notify.call_args_list]
        assert any("Alice" in c for c in calls)

    async def test_connect_falls_back_to_address_when_no_name(self):
        """Uses address when display name is empty."""
        app = ChatApp()
        app._account = _make_account()
        app._storage = MagicMock()
        app._config_dir = MagicMock()
        app.notify = MagicMock()

        with patch("p2pchat.core.network.peer.connect", new_callable=AsyncMock, side_effect=OSError("nope")):
            await app._do_connect(self._make_info(name=""))

        calls = [c.args[0] for c in app.notify.call_args_list]
        assert any("200:beef::1" in c for c in calls)

    async def test_on_connect_request_spawns_background_task(self):
        """on_connect_request dispatches to background task, doesn't block."""
        app = ChatApp()
        app._account = _make_account()
        app._storage = MagicMock()
        app._config_dir = MagicMock()
        app.notify = MagicMock()

        with patch.object(app, "_do_connect", new_callable=AsyncMock) as mock_do:
            await app.on_connect_request(self._make_event())
            # Task was spawned (not awaited inline).
            assert len(app._background_tasks) == 1
            # Wait for it to finish.
            await asyncio.gather(*app._background_tasks)
            mock_do.assert_awaited_once()
