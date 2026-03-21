"""Tests for the UnlockScreen — account selector, wizard, and password unlock.

Tests the unlock flow, attempt limiting, wizard state machine,
account selection, and input validation.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

from textual.app import App

from p2pchat.core.account import Account, AccountInfo
from p2pchat.ui.screens.unlock import UnlockScreen, _MAX_ATTEMPTS, _COOLDOWN_SECONDS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_unlock_app(accounts: list[AccountInfo] | None = None):
    """Create a test app with list_accounts patched.

    *accounts*=None or empty list → wizard mode (no accounts).
    *accounts*=[...] → account selector mode.
    """
    if accounts is None:
        accounts = []

    class UnlockTestApp(App):
        def __init__(self):
            super().__init__()
            self.unlocked_account = None

        def on_mount(self) -> None:
            with patch("p2pchat.ui.screens.unlock.list_accounts", return_value=accounts):
                self.push_screen(UnlockScreen())

        def on_unlock_screen_unlocked(self, event: UnlockScreen.Unlocked) -> None:
            self.unlocked_account = event.account

    return UnlockTestApp()


def _fake_accounts(names: list[str], base: Path | None = None) -> list[AccountInfo]:
    """Create fake AccountInfo entries for testing."""
    base = base or Path("/tmp/test-accounts")
    return [
        AccountInfo(display_name=n, account_dir=base / n, created_at=1000 + i)
        for i, n in enumerate(names)
    ]


# ---------------------------------------------------------------------------
# TestUnlockScreenExistence
# ---------------------------------------------------------------------------

class TestUnlockScreenExistence:
    async def test_shows_account_list_when_multiple_accounts_exist(self):
        accounts = _fake_accounts(["Alice", "Bob"])
        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            assert pilot.app.screen.query("#account-list")

    async def test_single_account_skips_to_password(self):
        accounts = _fake_accounts(["Alice"])
        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            assert pilot.app.screen.query("#password-input")

    async def test_shows_wizard_when_no_account(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            assert pilot.app.screen.query("#wizard-input")


# ---------------------------------------------------------------------------
# TestUnlockScreenConstants
# ---------------------------------------------------------------------------

class TestUnlockScreenConstants:
    def test_max_attempts_matches_owasp(self):
        """OWASP recommends max 5 attempts before lockout."""
        assert _MAX_ATTEMPTS == 5

    def test_cooldown_period(self):
        """Cooldown must be >= 30 seconds per OWASP."""
        assert _COOLDOWN_SECONDS >= 30


# ---------------------------------------------------------------------------
# TestWizardValidation
# ---------------------------------------------------------------------------

class TestWizardValidation:
    async def test_empty_display_name_rejected(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            screen._advance_wizard("")
            await pilot.pause()
            err = screen.query_one("#error-label")
            rendered = str(err._Static__content).lower()
            assert "1-64" in rendered or "character" in rendered

    async def test_long_display_name_rejected(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            screen._advance_wizard("A" * 65)
            await pilot.pause()
            err = screen.query_one("#error-label")
            rendered = str(err._Static__content).lower()
            assert "1-64" in rendered or "character" in rendered

    async def test_short_password_rejected(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            screen._advance_wizard("Alice")
            await pilot.pause()
            screen._advance_wizard("short")
            await pilot.pause()
            err = screen.query_one("#error-label")
            assert "8" in str(err._Static__content)

    async def test_password_mismatch_rejected(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            screen._advance_wizard("Alice")
            await pilot.pause()
            screen._advance_wizard("password123")
            await pilot.pause()
            screen._advance_wizard("different")
            await pilot.pause()
            err = screen.query_one("#error-label")
            assert "match" in str(err._Static__content).lower()

    async def test_wizard_steps_advance(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            assert screen._wizard_step == 0
            screen._advance_wizard("Alice")
            assert screen._wizard_step == 1
            assert screen._wizard_name == "Alice"
            screen._advance_wizard("password123")
            assert screen._wizard_step == 2
            assert screen._wizard_password == "password123"

    async def test_valid_name_advances_to_password(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            screen._advance_wizard("Bob")
            inp = screen.query_one("#wizard-input")
            assert inp.password is True

    async def test_max_name_length_64_accepted(self):
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            screen._advance_wizard("A" * 64)
            assert screen._wizard_step == 1


# ---------------------------------------------------------------------------
# TestUnlockScreenMessage
# ---------------------------------------------------------------------------

class TestUnlockScreenMessage:
    def test_unlocked_message_carries_account(self):
        """UnlockScreen.Unlocked message holds the Account object."""
        mock_account = MagicMock(spec=Account)
        msg = UnlockScreen.Unlocked(mock_account, "test-password")
        assert msg.account is mock_account
        assert msg.password == "test-password"


# ---------------------------------------------------------------------------
# TestWizardSubmitAndCreation
# ---------------------------------------------------------------------------

class TestWizardSubmitAndCreation:
    async def test_wizard_submit_strips_and_advances(self):
        """Input.Submitted on wizard triggers _advance_wizard with stripped value."""
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            from textual.widgets import Input
            inp = screen.query_one("#wizard-input", Input)
            inp.focus()
            inp.value = "  Alice  "
            await inp.action_submit()
            await pilot.pause()
            assert screen._wizard_step == 1
            assert screen._wizard_name == "Alice"

    async def test_wizard_full_flow_creates_account(self, tmp_path):
        """Complete wizard flow triggers account creation."""
        mock_account = MagicMock(spec=Account)

        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            # Step 0: display name
            screen._advance_wizard("TestUser")
            await pilot.pause()
            # Step 1: password
            screen._advance_wizard("password123")
            await pilot.pause()
            # Step 2: confirm — patch Account.create
            with patch.object(Account, "create", return_value=mock_account):
                screen._advance_wizard("password123")
                await pilot.pause()
                # Wait for @work(thread=True)
                await screen.workers.wait_for_complete()
                await pilot.pause()

            assert pilot.app.unlocked_account is mock_account

    async def test_wizard_create_account_failure(self):
        """Account creation failure shows error and re-enables input."""
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            screen._advance_wizard("TestUser")
            screen._advance_wizard("password123")
            with patch.object(Account, "create", side_effect=RuntimeError("disk full")):
                screen._advance_wizard("password123")
                await pilot.pause()
                await screen.workers.wait_for_complete()
                await pilot.pause()

            err = screen.query_one("#error-label")
            assert "disk full" in str(err._Static__content).lower()
            inp = screen.query_one("#wizard-input")
            assert inp.disabled is False


# ---------------------------------------------------------------------------
# TestAccountSelection
# ---------------------------------------------------------------------------

class TestAccountSelection:
    async def test_selecting_account_shows_password(self):
        """Selecting an account transitions to password prompt."""
        accounts = _fake_accounts(["Alice"])
        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            # Simulate account selection by setting state directly.
            screen._selected = accounts[0]
            screen._mode = "password"
            screen._attempts = 0
            screen._locked_until = 0.0
            await screen.recompose()
            await pilot.pause()
            assert screen.query("#password-input")


# ---------------------------------------------------------------------------
# TestPasswordUnlock
# ---------------------------------------------------------------------------

class TestPasswordUnlock:
    async def _enter_password_mode(self, pilot, accounts):
        """Select first account to get to password screen."""
        screen = pilot.app.screen
        screen._selected = accounts[0]
        screen._mode = "password"
        screen._attempts = 0
        screen._locked_until = 0.0
        await screen.recompose()
        await pilot.pause()
        return screen

    async def test_password_submit_empty_ignored(self):
        """Empty password submission is ignored."""
        accounts = _fake_accounts(["Alice"])
        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            screen = await self._enter_password_mode(pilot, accounts)
            from textual.widgets import Input
            inp = screen.query_one("#password-input", Input)
            inp.focus()
            inp.value = ""
            await inp.action_submit()
            await pilot.pause()
            err = screen.query_one("#error-label")
            assert str(err._Static__content) == ""

    async def test_wrong_password_shows_error(self):
        """Wrong password shows error with attempts remaining."""
        accounts = _fake_accounts(["Alice"])
        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            screen = await self._enter_password_mode(pilot, accounts)
            with patch.object(Account, "load", side_effect=ValueError("Wrong password")):
                from textual.widgets import Input
                inp = screen.query_one("#password-input", Input)
                inp.focus()
                inp.value = "wrongpass"
                await inp.action_submit()
                await pilot.pause()
                await screen.workers.wait_for_complete()
                await pilot.pause()

            err = screen.query_one("#error-label")
            content = str(err._Static__content).lower()
            assert "wrong password" in content or "attempts" in content

    async def test_correct_password_unlocks(self):
        """Correct password posts Unlocked message."""
        mock_account = MagicMock(spec=Account)
        accounts = _fake_accounts(["Alice"])

        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            screen = await self._enter_password_mode(pilot, accounts)
            with patch.object(Account, "load", return_value=mock_account):
                from textual.widgets import Input
                inp = screen.query_one("#password-input", Input)
                inp.focus()
                inp.value = "correctpassword"
                await inp.action_submit()
                await pilot.pause()
                await screen.workers.wait_for_complete()
                await pilot.pause()

            assert pilot.app.unlocked_account is mock_account

    async def test_lockout_after_max_attempts(self):
        """Account locks after MAX_ATTEMPTS wrong passwords."""
        accounts = _fake_accounts(["Alice"])
        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            screen = await self._enter_password_mode(pilot, accounts)
            with patch.object(Account, "load", side_effect=ValueError("bad")):
                from textual.widgets import Input
                for _ in range(_MAX_ATTEMPTS):
                    inp = screen.query_one("#password-input", Input)
                    inp.focus()
                    inp.value = "wrong"
                    await inp.action_submit()
                    await pilot.pause()
                    await screen.workers.wait_for_complete()
                    await pilot.pause()

            err = screen.query_one("#error-label")
            content = str(err._Static__content).lower()
            assert "locked" in content or "too many" in content

    async def test_escape_from_password_goes_to_selector(self):
        """Escape from password mode goes back to account selector (multi-account)."""
        accounts = _fake_accounts(["Alice", "Bob"])
        async with _make_unlock_app(accounts).run_test() as pilot:
            await pilot.pause()
            screen = await self._enter_password_mode(pilot, accounts)
            await screen.action_go_back()
            await pilot.pause()
            assert screen.query("#account-list")

    async def test_escape_from_wizard_quits_if_no_accounts(self):
        """Escape from wizard with no accounts exits the app."""
        async with _make_unlock_app([]).run_test() as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            await screen.action_go_back()
            await pilot.pause()
