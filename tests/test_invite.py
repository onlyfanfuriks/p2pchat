"""Tests for invite link parsing and generation.

Covers: parse_invite, build_invite, InviteInfo
Security focus: malformed inputs, injection attempts, boundary validation.
"""

import pytest

from textual.app import App

from p2pchat.core.crypto import encode_public_key, generate_ed25519_keypair
from p2pchat.ui.widgets.invite_modal import (
    ConnectInviteModal,
    InviteInfo,
    ShowInviteModal,
    build_invite,
    parse_invite,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_keypair():
    _, pub = generate_ed25519_keypair()
    return pub, encode_public_key(pub)


@pytest.fixture
def valid_link(valid_keypair):
    _, pub_b64 = valid_keypair
    return f"p2pchat://[200:abcd::1]:7331/{pub_b64}#Alice"


# ---------------------------------------------------------------------------
# TestParseInvite
# ---------------------------------------------------------------------------

class TestParseInvite:
    def test_valid_link(self, valid_link, valid_keypair):
        pub_bytes, pub_b64 = valid_keypair
        info = parse_invite(valid_link)
        assert info.ygg_address == "200:abcd::1"
        assert info.port == 7331
        assert info.ed25519_pub == pub_bytes
        assert info.display_name == "Alice"

    def test_valid_link_no_display_name(self, valid_keypair):
        _, pub_b64 = valid_keypair
        link = f"p2pchat://[200:abcd::1]:7331/{pub_b64}"
        info = parse_invite(link)
        assert info.display_name == ""

    def test_strips_whitespace(self, valid_link, valid_keypair):
        info = parse_invite(f"  {valid_link}  \n")
        assert info.ygg_address == "200:abcd::1"

    def test_invalid_format_no_scheme(self, valid_keypair):
        _, pub_b64 = valid_keypair
        with pytest.raises(ValueError, match="Invalid invite link format"):
            parse_invite(f"http://[200:abcd::1]:7331/{pub_b64}#Alice")

    def test_invalid_format_garbage(self):
        with pytest.raises(ValueError, match="Invalid invite link format"):
            parse_invite("not-a-link")

    def test_invalid_format_empty(self):
        with pytest.raises(ValueError, match="Invalid invite link format"):
            parse_invite("")

    def test_invalid_ipv6_address_rejected_by_regex(self, valid_keypair):
        """IPv4 address is rejected by the hex-only regex."""
        _, pub_b64 = valid_keypair
        with pytest.raises(ValueError, match="Invalid invite link format"):
            parse_invite(f"p2pchat://[999.999.999.999]:7331/{pub_b64}#Alice")

    def test_invalid_ipv6_too_many_groups(self, valid_keypair):
        """Address with too many groups caught by ipaddress validation."""
        _, pub_b64 = valid_keypair
        with pytest.raises(ValueError, match="Invalid IPv6"):
            parse_invite(f"p2pchat://[1:2:3:4:5:6:7:8:9]:7331/{pub_b64}#Alice")

    def test_port_out_of_range_zero(self, valid_keypair):
        _, pub_b64 = valid_keypair
        with pytest.raises(ValueError, match="Port out of range"):
            parse_invite(f"p2pchat://[200:abcd::1]:0/{pub_b64}#Alice")

    def test_port_out_of_range_high(self, valid_keypair):
        _, pub_b64 = valid_keypair
        with pytest.raises(ValueError, match="Port out of range"):
            parse_invite(f"p2pchat://[200:abcd::1]:70000/{pub_b64}#Alice")

    def test_invalid_public_key(self):
        with pytest.raises(ValueError):
            parse_invite("p2pchat://[200:abcd::1]:7331/AAAA#Alice")

    def test_malformed_base64_key(self):
        with pytest.raises(ValueError):
            parse_invite("p2pchat://[200:abcd::1]:7331/!!!invalid!!!#Alice")

    def test_namedtuple_fields(self, valid_link, valid_keypair):
        """InviteInfo is a proper NamedTuple with all fields."""
        info = parse_invite(valid_link)
        assert isinstance(info, InviteInfo)
        assert hasattr(info, "ygg_address")
        assert hasattr(info, "port")
        assert hasattr(info, "ed25519_pub")
        assert hasattr(info, "display_name")


# ---------------------------------------------------------------------------
# TestBuildInvite
# ---------------------------------------------------------------------------

class TestBuildInvite:
    def test_roundtrip(self, valid_keypair):
        """build_invite -> parse_invite returns identical data."""
        pub_bytes, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Bob")
        info = parse_invite(link)
        assert info.ygg_address == "200:abcd::1"
        assert info.port == 7331
        assert info.ed25519_pub == pub_bytes
        assert info.display_name == "Bob"

    def test_url_encodes_special_chars_in_name(self, valid_keypair):
        """Special characters in display name are percent-encoded."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Al#ice")
        assert "#Al%23ice" in link
        # Round-trip preserves original name
        info = parse_invite(link)
        assert info is not None
        assert info.display_name == "Al#ice"

    def test_empty_display_name(self, valid_keypair):
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "")
        info = parse_invite(link)
        assert info.display_name == ""

    def test_format_structure(self, valid_keypair):
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Test")
        assert link.startswith("p2pchat://[200:abcd::1]:7331/")
        assert link.endswith("#Test")

    def test_spaces_in_display_name_url_encoded(self, valid_keypair):
        """Spaces in display name are percent-encoded in the link."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Alice Smith")
        # The fragment must contain %20, not a raw space.
        fragment = link.split("#", 1)[1]
        assert " " not in fragment
        assert "%20" in fragment or "+" in fragment
        # More specifically, quote(safe="") encodes spaces as %20.
        assert "Alice%20Smith" in fragment

    def test_url_encoded_display_name_roundtrip(self, valid_keypair):
        """Names with spaces round-trip through build -> parse."""
        _, pub_b64 = valid_keypair
        names = ["Alice Smith", "  leading", "trailing  ", "a  b  c"]
        for name in names:
            link = build_invite("200:abcd::1", 7331, pub_b64, name)
            info = parse_invite(link)
            assert info.display_name == name, f"Failed round-trip for {name!r}"

    def test_unicode_emoji_display_name(self, valid_keypair):
        """Emoji display names round-trip correctly."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "\U0001f680 Rocket")
        info = parse_invite(link)
        assert info.display_name == "\U0001f680 Rocket"

    def test_unicode_cjk_display_name(self, valid_keypair):
        """CJK characters in display names round-trip correctly."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "\u5f20\u4f1f")
        info = parse_invite(link)
        assert info.display_name == "\u5f20\u4f1f"

    def test_unicode_mixed_script_display_name(self, valid_keypair):
        """Mixed-script names (Latin + CJK + emoji) survive encoding."""
        _, pub_b64 = valid_keypair
        name = "Alice \u5f20\u4f1f \U0001f44b"
        link = build_invite("200:abcd::1", 7331, pub_b64, name)
        info = parse_invite(link)
        assert info.display_name == name


# ---------------------------------------------------------------------------
# TestInviteSecurityEdgeCases
# ---------------------------------------------------------------------------

class TestInviteSecurityEdgeCases:
    def test_xss_in_display_name(self, valid_keypair):
        """Display name with script tags is handled safely."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "<script>alert(1)</script>")
        info = parse_invite(link)
        # Name is stored as-is (no HTML context), but round-trips correctly.
        assert "<script>" in info.display_name

    def test_unicode_display_name(self, valid_keypair):
        """Unicode display names work correctly."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "\u0410\u043b\u0438\u0441\u0430")
        info = parse_invite(link)
        assert info.display_name == "\u0410\u043b\u0438\u0441\u0430"

    def test_long_display_name(self, valid_keypair):
        """Very long display names are handled without crash."""
        _, pub_b64 = valid_keypair
        name = "A" * 1000
        link = build_invite("200:abcd::1", 7331, pub_b64, name)
        info = parse_invite(link)
        assert info.display_name == name

    def test_newline_injection(self, valid_keypair):
        """Newlines in invite link are rejected."""
        _, pub_b64 = valid_keypair
        link = f"p2pchat://[200:abcd::1]:7331/{pub_b64}#Alice\nHTTP/1.1"
        with pytest.raises(ValueError, match="Invalid invite link format"):
            parse_invite(link)

    def test_null_byte_in_address(self, valid_keypair):
        """Null bytes in address part are rejected."""
        _, pub_b64 = valid_keypair
        link = f"p2pchat://[200:ab\x00cd::1]:7331/{pub_b64}#Alice"
        with pytest.raises(ValueError):
            parse_invite(link)


# ---------------------------------------------------------------------------
# TestShowInviteModal (async Textual tests)
# ---------------------------------------------------------------------------

class TestShowInviteModal:
    async def test_compose_shows_link(self, valid_keypair):
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Alice")

        class TestApp(App):
            def on_mount(self):
                self.push_screen(ShowInviteModal(link))

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            text_widget = screen.query_one("#invite-text")
            assert "p2pchat://" in str(text_widget._Static__content)

    async def test_close_button_dismisses(self, valid_keypair):
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Alice")
        dismissed = []

        class TestApp(App):
            def on_mount(self):
                self.push_screen(ShowInviteModal(link), callback=lambda r: dismissed.append(r))

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            btn = pilot.app.screen.query_one("#close-btn")
            await pilot.click(btn)
            await pilot.pause()
            assert None in dismissed

    async def test_copy_button_with_pyperclip_unavailable(self, valid_keypair):
        """Copy button handles missing pyperclip gracefully."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Alice")

        class TestApp(App):
            def on_mount(self):
                self.push_screen(ShowInviteModal(link))

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            from unittest.mock import patch as mock_patch
            with mock_patch.dict("sys.modules", {"pyperclip": None}):
                btn = pilot.app.screen.query_one("#copy-btn")
                await pilot.click(btn)
                await pilot.pause()
                # Should not crash


# ---------------------------------------------------------------------------
# TestConnectInviteModal (async Textual tests)
# ---------------------------------------------------------------------------

class TestConnectInviteModal:
    async def test_compose_has_input_and_buttons(self):
        class TestApp(App):
            def on_mount(self):
                self.push_screen(ConnectInviteModal())

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            assert screen.query_one("#invite-input")
            assert screen.query_one("#connect-btn")
            assert screen.query_one("#cancel-btn")

    async def test_cancel_dismisses_with_none(self):
        results = []

        class TestApp(App):
            def on_mount(self):
                self.push_screen(ConnectInviteModal(), callback=lambda r: results.append(r))

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            btn = pilot.app.screen.query_one("#cancel-btn")
            await pilot.click(btn)
            await pilot.pause()
            assert results == [None]

    async def test_connect_with_invalid_link_shows_error(self):
        class TestApp(App):
            def on_mount(self):
                self.push_screen(ConnectInviteModal())

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            from textual.widgets import Input
            inp = screen.query_one("#invite-input", Input)
            inp.value = "not-a-valid-link"
            btn = screen.query_one("#connect-btn")
            await pilot.click(btn)
            await pilot.pause()
            err = screen.query_one("#invite-error")
            assert "Invalid" in str(err._Static__content)

    async def test_connect_with_valid_link_dismisses(self, valid_keypair):
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "TestPeer")
        results = []

        class TestApp(App):
            def on_mount(self):
                self.push_screen(ConnectInviteModal(), callback=lambda r: results.append(r))

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            from textual.widgets import Input
            inp = screen.query_one("#invite-input", Input)
            inp.value = link
            btn = screen.query_one("#connect-btn")
            await pilot.click(btn)
            await pilot.pause()
            assert len(results) == 1
            assert results[0] is not None
            assert results[0].display_name == "TestPeer"

    async def test_submit_input_triggers_connect(self, valid_keypair):
        """Pressing Enter in the input field triggers connect."""
        _, pub_b64 = valid_keypair
        link = build_invite("200:abcd::1", 7331, pub_b64, "Alice")
        results = []

        class TestApp(App):
            def on_mount(self):
                self.push_screen(ConnectInviteModal(), callback=lambda r: results.append(r))

        async with TestApp().run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen = pilot.app.screen
            from textual.widgets import Input
            inp = screen.query_one("#invite-input", Input)
            inp.value = link
            inp.focus()
            await inp.action_submit()
            await pilot.pause()
            assert len(results) == 1
            assert results[0] is not None
