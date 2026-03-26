"""Textual App class — top-level application shell.

Manages screen transitions (UnlockScreen -> ChatScreen) and
coordinates between the TUI and the network layer.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Grid
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from p2pchat.core.account import ACCOUNT_DIR, Account
from p2pchat.core.delivery.outbox import Outbox
from p2pchat.core.storage import Storage, derive_db_key

_THEME_FILE = ACCOUNT_DIR / "theme.conf"

from p2pchat.ui.screens.unlock import UnlockScreen
from p2pchat.ui.screens.chat import ChatScreen, ConnectRequest
from p2pchat.ui.widgets.invite_modal import InviteInfo
from p2pchat.ui.themes import BUILTIN_THEMES

if TYPE_CHECKING:
    from p2pchat.core.network.session import PeerSession

log = logging.getLogger(__name__)


class _VerifyModal(ModalScreen[bool]):
    """Prompt user to verify an unknown peer's fingerprint (TOFU)."""

    def __init__(
        self,
        display_name: str,
        their_fingerprint: str,
        my_fingerprint: str,
    ) -> None:
        self._display_name = display_name
        self._their_fingerprint = their_fingerprint
        self._my_fingerprint = my_fingerprint
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("New Contact", classes="modal-title"),
            Label(f"Display name: [bold]{self._display_name}[/bold]"),
            Label(f"Their fingerprint:\n{self._their_fingerprint}"),
            Static(""),
            Label(f"Your fingerprint (share with them):\n{self._my_fingerprint}"),
            Static(""),
            Label("Verify out-of-band (phone, Signal, etc.)"),
            Button("Trust & Connect", variant="success", id="trust"),
            Button("Reject", variant="error", id="reject"),
            id="invite-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "trust")


class _AppCommands(Provider):
    """Command palette entries for p2pchat."""

    @property
    def _commands(self) -> list[tuple[str, object, str]]:
        return [
            ("Download Yggdrasil",
             self.app.action_download_yggdrasil,
             "Download Yggdrasil binary to ~/.config/p2pchat/bin/"),
        ]

    async def discover(self) -> Hits:
        for name, callback, help_text in self._commands:
            yield DiscoveryHit(name, callback, help=help_text)

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for name, callback, help_text in self._commands:
            score = matcher.match(name)
            if score > 0:
                yield Hit(score, matcher.highlight(name), callback, help=help_text)


class ChatApp(App):
    """p2pchat terminal application."""

    CSS_PATH = "chat.tcss"
    TITLE = "p2pchat"
    COMMANDS = App.COMMANDS | {_AppCommands}

    def __init__(self) -> None:
        super().__init__()
        # Register custom built-in themes.
        for theme in BUILTIN_THEMES.values():
            self.register_theme(theme)
        self._account: Account | None = None
        self._storage: Storage | None = None
        self._config_dir: Path | None = None
        self._ygg_node = None
        self._chat_server = None
        self._chat_screen: ChatScreen | None = None
        self._start_network_task: asyncio.Task | None = None
        self._outbox: Outbox | None = None
        self._password: str | None = None
        self._sessions: dict[str, PeerSession] = {}
        self._background_tasks: set[asyncio.Task] = set()
        self._reconnect_task: asyncio.Task | None = None
        self._connecting: set[str] = set()

    async def on_mount(self) -> None:
        try:
            if _THEME_FILE.exists():
                saved = _THEME_FILE.read_text().strip()
                if saved in self.available_themes:
                    self.theme = saved
        except Exception:
            pass
        self.push_screen(UnlockScreen())

    def watch_theme(self, theme_name: str) -> None:
        try:
            _THEME_FILE.parent.mkdir(parents=True, exist_ok=True)
            _THEME_FILE.write_text(theme_name + "\n")
        except Exception:
            pass

    async def on_unlock_screen_unlocked(self, event: UnlockScreen.Unlocked) -> None:
        """Handle successful unlock: initialise storage and start network."""
        self._account = event.account
        self._password = event.password
        self._config_dir = event.account.account_dir

        # Re-save account to update JSON format (adds display_name_plain
        # for migrated accounts so the selector shows the real name).
        await asyncio.to_thread(self._account.save, self._password)

        # Initialise encrypted storage.
        db_key = derive_db_key(self._account.ed25519_private)
        db_path = self._config_dir / "messages.db"
        self._storage = Storage(db_path, db_key)
        await self._storage.initialize()

        # Store account info in DB.
        await self._storage.upsert_account(
            self._account.user_id,
            self._account.display_name,
            self._account.created_at,
        )

        # Initialise outbox for offline message delivery.
        self._outbox = Outbox(self._account, self._storage)

        # Transition to chat screen.
        self._chat_screen = ChatScreen(
            account=self._account,
            storage=self._storage,
            send_callback=self._send_message,
        )
        self.switch_screen(self._chat_screen)

        # Start network layer (Yggdrasil + server) in background.
        self._start_network_task = asyncio.create_task(self._start_network())

    async def _start_network(self) -> None:
        """Start Yggdrasil and ChatServer in the background."""
        log.info("_start_network: begin")
        if self._account is None or self._chat_screen is None:
            log.error("_start_network: account or chat_screen is None, aborting")
            if self._chat_screen:
                self._chat_screen.set_status("error: not initialized", "error")
            return

        try:
            self._chat_screen.set_status("yggdrasil starting\u2026", "accent")
            await self._start_yggdrasil()
            log.info("_start_network: yggdrasil started, address=%s", self._account.ygg_address)
        except Exception as exc:
            log.error("Failed to start Yggdrasil: %s", exc, exc_info=True)
            self._chat_screen.set_status(f"error: {exc}", "error")
            return

        try:
            self._chat_screen.set_status("server starting\u2026", "accent")
            await self._start_chat_server()
            log.info("_start_network: server started")
        except Exception as exc:
            log.error("Failed to start server: %s", exc, exc_info=True)
            self._chat_screen.set_status(f"error: {exc}", "error")
            return

        self._chat_screen.set_status("ready", "success")
        log.info("_start_network: ready")

        # Start outbox retry loops for peers with pending items.
        await self._start_outbox_retries()

        # Periodically reconnect to offline contacts.
        self._reconnect_task = asyncio.create_task(
            self._reconnect_loop(), name="reconnect-loop",
        )

    async def _start_yggdrasil(self) -> None:
        """Start Yggdrasil subprocess or attach to a running instance.

        Strategy:
        1. Probe for an already-running Yggdrasil (admin socket / interfaces).
        2. If none found, start our own subprocess.
        3. If the subprocess fails, probe once more (it may have failed
           because a system instance owns the TUN device).
        """
        if self._account is None or self._config_dir is None:
            log.error(
                "_start_yggdrasil: precondition failed — account=%s config_dir=%s",
                self._account,
                self._config_dir,
            )
            raise RuntimeError(
                "_start_yggdrasil: account or config_dir is None"
            )

        from p2pchat.core.account import ACCOUNT_DIR
        from p2pchat.core.network.yggdrasil import YggdrasilNode

        self._config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        node = YggdrasilNode(self._config_dir)
        self._ygg_node = node

        # --- Try to attach to already-running Yggdrasil ---
        address = await node.detect_running()

        if address is None:
            # No running instance — start our own subprocess.
            if YggdrasilNode.find_binary(ACCOUNT_DIR) is None:
                raise FileNotFoundError(
                    "Yggdrasil not found \u2014 install it or Ctrl+P \u2192 Download"
                )

            conf_json = node.generate_config(
                self._account.ygg_conf or None
            )
            conf_path = self._config_dir / "ygg_run.conf"
            node.write_run_conf(conf_json, conf_path)

            # Save config on first run so Yggdrasil identity persists.
            if not self._account.ygg_conf:
                self._account.ygg_conf = conf_json
                if self._password:
                    await asyncio.to_thread(self._account.save, self._password)
                    log.info("Saved ygg config to account")

            try:
                address = await node.start(conf_path)
            except (RuntimeError, OSError) as exc:
                log.warning(
                    "Subprocess failed (%s); probing for system instance\u2026",
                    exc,
                )
                # Kill any partially-started subprocess.
                await node.stop()
                # Retry detection — maybe system Ygg owns the TUN.
                address = await node.detect_running()
                if address is None:
                    raise

        self._account.ygg_address = address

        # Update chat screen status bar with address.
        if self._chat_screen:
            from p2pchat.ui.widgets.status_bar import StatusBar

            status = self._chat_screen.query_one("#status-bar", StatusBar)
            status.ygg_address = address

    async def _start_chat_server(self) -> None:
        """Start the TLS TCP server for incoming connections."""
        if self._account is None or self._storage is None or self._config_dir is None:
            return

        from p2pchat.core.network.server import ChatServer

        server = ChatServer(
            config_dir=self._config_dir,
            account=self._account,
            storage=self._storage,
            on_session_ready=self._on_session_ready,
            verify_callback=self._verify_peer,
        )
        self._chat_server = server
        await server.start(self._account.ygg_address)

    async def on_connect_request(self, event: ConnectRequest) -> None:
        """Handle invite-link connect request from ChatScreen.

        The actual connection runs in a background task so the App's
        message pump stays unblocked — otherwise the verify modal can
        never receive button clicks and the UI freezes.
        """
        if self._account is None or self._storage is None or self._config_dir is None:
            self.notify("Not initialized yet", severity="error")
            return

        task = asyncio.create_task(self._do_connect(event.info))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _do_connect(self, info: InviteInfo) -> None:
        """Run the outgoing peer connection in a background task."""
        if self._account is None or self._storage is None or self._config_dir is None:
            return

        name = info.display_name or info.ygg_address
        log.info("Connect request: %s:%d (%s)", info.ygg_address, info.port, name)

        from p2pchat.core.network.peer import connect

        self.notify(f"Connecting to {name}...")

        try:
            session = await connect(
                info.ygg_address,
                info.port,
                self._account,
                self._storage,
                self._config_dir,
                self._verify_peer,
            )
        except asyncio.TimeoutError:
            log.warning("Connection to %s timed out", name)
            self.notify(f"Connection to {name} timed out", severity="error")
            return
        except OSError as exc:
            log.warning("Connection to %s failed: %s", name, exc)
            self.notify(f"Cannot reach {name}: {exc}", severity="error")
            return
        except Exception as exc:
            log.error("Connection to %s failed: %s", name, exc, exc_info=True)
            self.notify(f"Connection failed: {exc}", severity="error")
            return

        self.notify(f"Connected to {name}")
        log.info("Connected to %s (peer_id=%s)", name, session.peer_id)

        await self._on_session_ready(session)

    async def _on_session_ready(self, session: PeerSession) -> None:
        """Handle a fully-handshaked session (incoming or outgoing)."""
        peer_id = session.peer_id
        log.info("Session ready: peer=%s", peer_id)
        self._sessions[peer_id] = session

        if self._chat_screen:
            await self._chat_screen.on_peer_online(peer_id)

        # Drain pending outbox items for this peer.
        if self._outbox:
            self._outbox.cancel_retry(peer_id)
            try:
                sent = await self._outbox.drain(session)
                if sent > 0 and self._chat_screen:
                    # Reload messages to update delivery indicators (⏳ → ✓).
                    await self._chat_screen.refresh_messages(peer_id)
            except Exception as exc:
                log.warning("Outbox drain failed for %s: %s", peer_id, exc)
                self._outbox.start_retry(peer_id, self._connect_for_outbox)

        try:
            async for chat_msg in session.receive_loop():
                if self._storage and self._chat_screen:
                    from p2pchat.core.storage import Message

                    msg = Message(
                        id=chat_msg.message_id,
                        peer_id=chat_msg.peer_id,
                        direction="received",
                        content=chat_msg.content,
                        timestamp=int(time.time()),
                    )
                    await self._storage.save_message(msg)

                    # Receiving a message proves the peer got ours.
                    updated = await self._storage.mark_all_delivered(peer_id)

                    contact = await self._storage.get_contact(chat_msg.peer_id)
                    peer_name = contact.display_name if contact else ""
                    await self._chat_screen.on_message_received(
                        chat_msg.peer_id, msg, peer_name,
                        refresh_delivery=updated > 0,
                    )

                    await session.send_ack(chat_msg.message_id)
                    log.debug("Received message from %s: id=%s", peer_id, chat_msg.message_id)
        except Exception as exc:
            log.warning("Receive loop ended for %s: %s", peer_id, exc)
        finally:
            log.info("Session ended: peer=%s", peer_id)
            # Only remove if we're still the registered session (avoids
            # clobbering a newer session for the same peer).
            if self._sessions.get(peer_id) is session:
                self._sessions.pop(peer_id, None)
            if self._chat_screen:
                await self._chat_screen.on_peer_offline(peer_id)

    async def _verify_peer(
        self, peer_id: str, display_name: str, fingerprint: str
    ) -> bool:
        """Prompt the user to verify an unknown peer's fingerprint."""
        if self._account is None:
            return False

        from p2pchat.core.crypto import display_fingerprint

        my_fingerprint = display_fingerprint(self._account.ed25519_public)

        log.info("Verify peer: %s (%s) fingerprint=%s", peer_id, display_name, fingerprint)

        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()

        def _on_result(accepted: bool | None) -> None:
            log.info("Verify peer result: %s (%s) accepted=%s", peer_id, display_name, accepted)
            if not future.done():
                future.set_result(bool(accepted))

        modal = _VerifyModal(display_name, fingerprint, my_fingerprint)
        self.push_screen(modal, callback=_on_result)
        return await future

    async def _send_message(
        self, peer_id: str, plaintext: str, message_id: str | None = None,
    ) -> str | None:
        """Send a message to a peer via active session or outbox."""
        # Try active session first.
        session = self._sessions.get(peer_id)
        if session and session.state == "active":
            try:
                wire_msg_id = await session.send_message(plaintext, message_id)
                if message_id and self._storage:
                    await self._storage.mark_delivered(message_id)
                    if self._chat_screen:
                        await self._chat_screen.refresh_messages(peer_id)
                return wire_msg_id
            except Exception as exc:
                log.warning("Direct send to %s failed: %s", peer_id, exc)
                # Fall through to outbox.

        # Enqueue in outbox for later delivery.
        if self._outbox:
            try:
                item_id = await self._outbox.enqueue(
                    peer_id, plaintext, message_id,
                )
                self._outbox.start_retry(peer_id, self._connect_for_outbox)
                if self._chat_screen:
                    self._chat_screen.set_status("offline \u2014 queuing", "warning")
                return item_id
            except Exception as exc:
                log.error("Failed to enqueue message: %s", exc)
                raise

        log.debug("No outbox — message to %s not queued", peer_id)
        return None

    async def _connect_for_outbox(self, peer_id: str) -> PeerSession:
        """Connect to a peer for outbox delivery."""
        if self._account is None or self._storage is None or self._config_dir is None:
            raise RuntimeError("Not initialized")

        contact = await self._storage.get_contact(peer_id)
        if contact is None or not contact.ygg_address:
            raise ValueError(f"No address for peer {peer_id}")

        from p2pchat.core.network.peer import connect
        from p2pchat.core.protocol import PORT

        session = await connect(
            contact.ygg_address,
            PORT,
            self._account,
            self._storage,
            self._config_dir,
            # No verify callback — only deliver to already-trusted peers.
        )

        # Handle session lifecycle (receive loop) in background.
        task = asyncio.create_task(self._on_session_ready(session))
        # prevent GC; done callback auto-removes.
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return session

    async def _reconnect_loop(self) -> None:
        """Periodically try to connect to offline trusted contacts."""
        while True:
            await asyncio.sleep(15)
            await self._try_reconnect_all()

    async def _try_reconnect_all(self) -> None:
        """Attempt to connect to all offline trusted contacts."""
        if not self._storage or not self._account or not self._config_dir:
            return

        contacts = await self._storage.list_contacts()
        for contact in contacts:
            if contact.peer_id in self._sessions:
                continue
            if contact.peer_id in self._connecting:
                continue
            if not contact.ygg_address or not contact.trusted:
                log.debug(
                    "Skip reconnect %s: ygg=%s trusted=%s",
                    contact.display_name, bool(contact.ygg_address), contact.trusted,
                )
                continue
            log.info("Reconnecting to %s (%s)", contact.display_name, contact.ygg_address)
            task = asyncio.create_task(
                self._try_reconnect_peer(contact.peer_id, contact.ygg_address),
                name=f"reconnect-{contact.peer_id[:8]}",
            )
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def _try_reconnect_peer(self, peer_id: str, ygg_address: str) -> None:
        """Attempt to reconnect to a single peer (silent on failure)."""
        if peer_id in self._sessions or peer_id in self._connecting:
            return
        if not self._account or not self._storage or not self._config_dir:
            return

        self._connecting.add(peer_id)
        try:
            from p2pchat.core.network.peer import connect
            from p2pchat.core.protocol import PORT

            session = await connect(
                ygg_address,
                PORT,
                self._account,
                self._storage,
                self._config_dir,
                # No verify callback — silently reject unknown peers.
                timeout=8.0,
            )
            # Run session lifecycle in background.
            task = asyncio.create_task(self._on_session_ready(session))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        except Exception as exc:
            log.info("Reconnect to %s failed: %s", peer_id, exc)
        finally:
            self._connecting.discard(peer_id)

    async def _start_outbox_retries(self) -> None:
        """Start retry loops for all peers with pending outbox items."""
        if not self._outbox or not self._storage:
            return
        try:
            pending = await self._storage.get_all_pending_outbox()
            peers = {item.peer_id for item in pending}
            for peer_id in peers:
                self._outbox.start_retry(peer_id, self._connect_for_outbox)
        except Exception as exc:
            log.warning("Failed to start outbox retries: %s", exc)

    async def _cancel_background_tasks(self) -> None:
        """Cancel outbox-initiated session tasks and the network startup task."""
        # Cancel the reconnect loop.
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()

        # Cancel all background session / connection tasks.
        pending = [t for t in self._background_tasks if not t.done()]
        for task in pending:
            task.cancel()

        # Also cancel the network startup task.
        if self._start_network_task and not self._start_network_task.done():
            self._start_network_task.cancel()

        # Await everything together.
        all_tasks = pending[:]
        if self._reconnect_task:
            all_tasks.append(self._reconnect_task)
        if self._start_network_task:
            all_tasks.append(self._start_network_task)
        if all_tasks:
            await asyncio.gather(*all_tasks, return_exceptions=True)

        self._background_tasks.clear()

    async def _cleanup_resources(self) -> None:
        """Clean shutdown of network resources."""
        if self._outbox:
            try:
                await self._outbox.stop()
            except Exception:
                pass

        await self._cancel_background_tasks()

        if self._chat_server:
            try:
                await self._chat_server.stop()
            except Exception:
                pass

        if self._ygg_node:
            try:
                await self._ygg_node.stop()
            except Exception:
                pass

        if self._storage:
            try:
                await self._storage.close()
            except Exception:
                pass

    async def action_quit(self) -> None:
        await self._cleanup_resources()
        self.exit()

    async def action_download_yggdrasil(self) -> None:
        """Download Yggdrasil binary and retry network startup."""
        from p2pchat.core.account import ACCOUNT_DIR
        from p2pchat.core.network.yggdrasil import YggdrasilNode

        if YggdrasilNode.find_binary(ACCOUNT_DIR) is not None:
            self.notify("Yggdrasil is already installed")
            return

        if self._chat_screen:
            self._chat_screen.set_status("downloading yggdrasil\u2026", "accent")

        try:
            await asyncio.to_thread(YggdrasilNode.download_binary, ACCOUNT_DIR)
            self.notify("Yggdrasil downloaded")
        except Exception as exc:
            log.error("Yggdrasil download failed: %s", exc)
            self.notify(f"Download failed: {exc}", severity="error")
            if self._chat_screen:
                self._chat_screen.set_status("download failed", "error")
            return

        # Retry network startup if not connected yet.
        if self._account and not self._account.ygg_address:
            if self._start_network_task is None or self._start_network_task.done():
                self._start_network_task = asyncio.create_task(
                    self._start_network()
                )
