"""Password prompt screen, account selector, and first-run wizard.

On startup this is the first screen the user sees:
- If accounts exist: list them for selection, then prompt for password.
- If no accounts exist: run the creation wizard.
- Users can always create a new account (forgot password scenario).
- Accounts can be securely deleted with a typed confirmation phrase.
"""

from __future__ import annotations


from rich.markup import escape
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Center, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.binding import Binding
from textual.widgets import Footer, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from p2pchat.core.account import Account, AccountInfo, list_accounts

# OWASP: max 5 attempts then 30 s cooldown.
_MAX_ATTEMPTS = 5
_COOLDOWN_SECONDS = 30

# UI modes for compose/recompose.
_MODE_SELECT = "select"       # account list
_MODE_PASSWORD = "password"   # password prompt for selected account
_MODE_WIZARD = "wizard"       # new account creation
_MODE_DELETE = "delete"       # delete confirmation


class UnlockScreen(Screen):
    """Account selector, password unlock, and first-run wizard screen."""

    class Unlocked(Message):
        """Fired when the account is successfully unlocked or created."""

        def __init__(self, account: Account, password: str) -> None:
            self.account = account
            self.password = password
            super().__init__()

    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("escape", "go_back", "Back"),
        Binding("ctrl+n", "new_account", "New account"),
        Binding("f8", "delete_account", "Delete account"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._accounts: list[AccountInfo] = list_accounts()
        self._selected: AccountInfo | None = None
        self._wizard_step = 0  # 0=name, 1=password, 2=confirm
        self._wizard_name = ""
        self._wizard_password = ""
        self._attempts = 0
        self._locked_until = 0.0

        # Determine initial mode.
        if len(self._accounts) == 1:
            # Single account — skip selector, go straight to password.
            self._selected = self._accounts[0]
            self._mode = _MODE_PASSWORD
        elif self._accounts:
            self._mode = _MODE_SELECT
        else:
            self._mode = _MODE_WIZARD

    def compose(self) -> ComposeResult:
        with Center():
            with Vertical(id="unlock-box"):
                yield Static("p2pchat", id="app-title")

                if self._mode == _MODE_SELECT:
                    yield from self._compose_select()
                elif self._mode == _MODE_PASSWORD:
                    yield from self._compose_password()
                elif self._mode == _MODE_WIZARD:
                    yield from self._compose_wizard()
                elif self._mode == _MODE_DELETE:
                    yield from self._compose_delete()

                yield Label("", id="error-label")
        yield Footer(show_command_palette=False)

    def _compose_select(self) -> ComposeResult:
        yield Label("Select account:")
        opts: list[Option] = []
        for info in self._accounts:
            opts.append(Option(info.display_name, id=str(info.account_dir)))
        opts.append(Option("───────────────"))
        opts.append(Option("+ New account", id="__new__"))
        yield OptionList(*opts, id="account-list")

    def _compose_password(self) -> ComposeResult:
        name = escape(self._selected.display_name) if self._selected else ""
        yield Label(f"Unlock account [bold]{name}[/bold]:")
        yield Input(placeholder="Password", password=True, id="password-input")

    def _compose_wizard(self) -> ComposeResult:
        yield Label("Choose a display name:", id="instruction-label")
        yield Input(placeholder="Display name", id="wizard-input")

    def _compose_delete(self) -> ComposeResult:
        name = escape(self._selected.display_name) if self._selected else ""
        yield Label(
            f"[red bold]Delete account \"{name}\" and all its data?[/red bold]"
        )
        yield Label(f"Type [bold]delete account {name}[/bold] to confirm:")
        yield Input(placeholder="Type confirmation phrase", id="delete-input")

    def on_mount(self) -> None:
        self._focus_current_input()
        self._update_bindings()

    async def _recompose_and_refresh(self) -> None:
        """Recompose then update focus and footer bindings."""
        await super().recompose()
        self._update_bindings()
        # Defer focus so it wins over any pending mouse events (e.g. footer click).
        self.call_after_refresh(self._focus_current_input)

    def _focus_current_input(self) -> None:
        if self._mode == _MODE_SELECT:
            try:
                self.query_one("#account-list", OptionList).focus()
            except Exception:
                pass
        elif self._mode == _MODE_PASSWORD:
            try:
                self.query_one("#password-input", Input).focus()
            except Exception:
                pass
        elif self._mode == _MODE_WIZARD:
            try:
                self.query_one("#wizard-input", Input).focus()
            except Exception:
                pass
        elif self._mode == _MODE_DELETE:
            try:
                self.query_one("#delete-input", Input).focus()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Account selection
    # ------------------------------------------------------------------

    @on(OptionList.OptionSelected, "#account-list")
    async def _on_account_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        opt_id = event.option.id
        if opt_id == "__new__":
            self._mode = _MODE_WIZARD
            self._wizard_step = 0
            self._wizard_name = ""
            self._wizard_password = ""
            await self._recompose_and_refresh()
            return

        # Find the selected account.
        for info in self._accounts:
            if str(info.account_dir) == opt_id:
                self._selected = info
                self._mode = _MODE_PASSWORD
                self._attempts = 0
                self._locked_until = 0.0
                await self._recompose_and_refresh()
                return

    # ------------------------------------------------------------------
    # Password unlock
    # ------------------------------------------------------------------

    @on(Input.Submitted, "#password-input")
    def _on_password_submit(self, event: Input.Submitted) -> None:
        event.stop()
        password = event.value
        if not password:
            return
        self._try_unlock(password)

    @work(thread=True, exclusive=True)
    def _try_unlock(self, password: str) -> None:
        """Attempt to load the account with the given password."""
        import time

        err_label = self.query_one("#error-label", Label)

        now = time.monotonic()
        if now < self._locked_until:
            remaining = int(self._locked_until - now) + 1
            self.app.call_from_thread(
                err_label.update,
                f"[red]Too many attempts. Wait {remaining}s.[/red]",
            )
            return

        account_dir = self._selected.account_dir if self._selected else None
        try:
            account = Account.load(password, account_dir)
        except Exception as exc:
            self._attempts += 1
            if self._attempts >= _MAX_ATTEMPTS:
                self._locked_until = time.monotonic() + _COOLDOWN_SECONDS
                self._attempts = 0
                self.app.call_from_thread(
                    err_label.update,
                    f"[red]Too many attempts. Locked for {_COOLDOWN_SECONDS}s.[/red]",
                )
                self.app.call_from_thread(
                    self.set_timer, _COOLDOWN_SECONDS, self._clear_lockout,
                )
            else:
                remaining = _MAX_ATTEMPTS - self._attempts
                msg = str(exc) if "password" in str(exc).lower() else "Wrong password"
                self.app.call_from_thread(
                    err_label.update,
                    f"[red]{msg} ({remaining} attempts left)[/red]",
                )
            inp = self.query_one("#password-input", Input)
            self.app.call_from_thread(inp.clear)
            return

        self.post_message(self.Unlocked(account, password))

    def _clear_lockout(self) -> None:
        """Clear the lockout message once the cooldown has expired."""
        try:
            err_label = self.query_one("#error-label", Label)
            err_label.update("[green]You can try again.[/green]")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Wizard (new account creation)
    # ------------------------------------------------------------------

    @on(Input.Submitted, "#wizard-input")
    def _on_wizard_submit(self, event: Input.Submitted) -> None:
        event.stop()
        value = event.value.strip()
        self._advance_wizard(value)

    def _advance_wizard(self, value: str) -> None:
        """Step through the first-run wizard."""
        err_label = self.query_one("#error-label", Label)
        inp = self.query_one("#wizard-input", Input)

        if self._wizard_step == 0:
            # Display name
            if not value or len(value) > 64:
                err_label.update("[red]Name must be 1-64 characters.[/red]")
                return
            self._wizard_name = value
            self._wizard_step = 1
            err_label.update("")
            inp.clear()
            inp.placeholder = "Choose a password"
            inp.password = True
            self.query_one("#instruction-label", Label).update(
                "Choose a password (min 8 characters):"
            )

        elif self._wizard_step == 1:
            # Password
            if len(value) < 8:
                err_label.update("[red]Password must be at least 8 characters.[/red]")
                inp.clear()
                return
            self._wizard_password = value
            self._wizard_step = 2
            err_label.update("")
            inp.clear()
            inp.placeholder = "Confirm password"
            self.query_one("#instruction-label", Label).update(
                "Confirm your password:"
            )

        elif self._wizard_step == 2:
            # Confirm password
            if value != self._wizard_password:
                err_label.update("[red]Passwords do not match.[/red]")
                inp.clear()
                return
            err_label.update("[dim]Creating account\u2026[/dim]")
            inp.disabled = True
            self._create_account()

    @work(thread=True, exclusive=True)
    def _create_account(self) -> None:
        """Generate keypairs and save the new account."""
        try:
            account = Account.create(self._wizard_password, self._wizard_name)
        except Exception as exc:
            self._wizard_password = ""
            err_label = self.query_one("#error-label", Label)
            self.app.call_from_thread(
                err_label.update,
                f"[red]Account creation failed: {exc}[/red]",
            )
            inp = self.query_one("#wizard-input", Input)
            self.app.call_from_thread(setattr, inp, "disabled", False)
            return

        password = self._wizard_password
        self._wizard_password = ""
        self.post_message(self.Unlocked(account, password))

    # ------------------------------------------------------------------
    # Account deletion with confirmation
    # ------------------------------------------------------------------

    def action_help(self) -> None:
        from ..widgets.help_screen import HelpScreen
        self.app.push_screen(HelpScreen("unlock"))

    async def action_delete_account(self) -> None:
        """Enter delete-confirmation mode for the selected account."""
        if self._mode != _MODE_PASSWORD or self._selected is None:
            return
        self._mode = _MODE_DELETE
        await self._recompose_and_refresh()

    @on(Input.Submitted, "#delete-input")
    def _on_delete_submit(self, event: Input.Submitted) -> None:
        event.stop()
        value = event.value.strip()
        name = self._selected.display_name if self._selected else ""
        expected = f"delete account {name}"

        err_label = self.query_one("#error-label", Label)
        if value != expected:
            err_label.update("[red]Confirmation phrase does not match.[/red]")
            inp = self.query_one("#delete-input", Input)
            inp.clear()
            return

        self._do_secure_delete()

    @work(thread=True, exclusive=True)
    def _do_secure_delete(self) -> None:
        """Securely delete the selected account directory."""
        if self._selected is None:
            return

        from p2pchat.core.secure_delete import secure_delete_dir

        account_dir = self._selected.account_dir
        secure_delete_dir(account_dir)

        # Refresh account list and go back to selector or wizard.
        self._accounts = list_accounts()
        self._selected = None
        self._mode = _MODE_SELECT if self._accounts else _MODE_WIZARD
        self.app.call_from_thread(self._recompose_and_refresh)

    # ------------------------------------------------------------------
    # New account
    # ------------------------------------------------------------------

    async def action_new_account(self) -> None:
        """Switch to the new-account wizard."""
        if self._mode == _MODE_WIZARD:
            return
        self._mode = _MODE_WIZARD
        self._wizard_step = 0
        self._wizard_name = ""
        self._wizard_password = ""
        await self._recompose_and_refresh()

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    async def action_go_back(self) -> None:
        """Escape goes back one level, or quits from the top."""
        if self._mode == _MODE_DELETE:
            self._mode = _MODE_PASSWORD
            await self._recompose_and_refresh()
        elif self._mode == _MODE_PASSWORD:
            if len(self._accounts) > 1:
                self._mode = _MODE_SELECT
                self._selected = None
                await self._recompose_and_refresh()
            else:
                self.app.exit()
        elif self._mode == _MODE_WIZARD and len(self._accounts) > 1:
            self._mode = _MODE_SELECT
            self._wizard_step = 0
            self._wizard_name = ""
            self._wizard_password = ""
            await self._recompose_and_refresh()
        elif self._mode == _MODE_WIZARD and len(self._accounts) == 1:
            # Go back to password for the single account.
            self._selected = self._accounts[0]
            self._mode = _MODE_PASSWORD
            self._wizard_step = 0
            self._wizard_name = ""
            self._wizard_password = ""
            await self._recompose_and_refresh()
        else:
            self.app.exit()

    def _update_bindings(self) -> None:
        """Show only the bindings relevant to the current mode."""
        show_back = self._mode in (_MODE_PASSWORD, _MODE_WIZARD, _MODE_DELETE)
        show_new = self._mode in (_MODE_SELECT, _MODE_PASSWORD)
        show_delete = self._mode == _MODE_PASSWORD

        self._bindings.bind("escape", "go_back", "Back", show=show_back)
        self._bindings.bind("ctrl+n", "new_account", "New account", show=show_new)
        self._bindings.bind("f8", "delete_account", "Delete account", show=show_delete)

        try:
            self.query_one(Footer).refresh()
        except Exception:
            pass
