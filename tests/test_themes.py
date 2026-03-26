"""Tests for p2pchat built-in themes.

Validates that all theme definitions are well-formed, have required
properties, use valid color values, and can be registered with Textual.
"""

import re

from textual.app import App
from textual.theme import Theme as TextualTheme

from p2pchat.ui.themes import BUILTIN_THEMES


# Required color fields that every theme must define (non-None).
_REQUIRED_COLOR_FIELDS = [
    "primary",
    "secondary",
    "warning",
    "error",
    "success",
    "accent",
    "background",
    "surface",
    "panel",
]

# Regex for a valid 6-digit hex color (e.g. #FF7E5F).
_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


# ---------------------------------------------------------------------------
# TestThemeRegistry
# ---------------------------------------------------------------------------

class TestThemeRegistry:
    def test_builtin_themes_is_not_empty(self):
        """At least one theme is defined."""
        assert len(BUILTIN_THEMES) > 0

    def test_all_values_are_textual_theme_instances(self):
        """Every entry is a TextualTheme instance."""
        for name, theme in BUILTIN_THEMES.items():
            assert isinstance(theme, TextualTheme), (
                f"Theme '{name}' is not a TextualTheme instance"
            )

    def test_dict_key_matches_theme_name(self):
        """Dict key matches the .name attribute on each theme."""
        for key, theme in BUILTIN_THEMES.items():
            assert key == theme.name, (
                f"Dict key '{key}' != theme.name '{theme.name}'"
            )

    def test_theme_names_are_unique(self):
        """All theme names are unique (no duplicates)."""
        names = [t.name for t in BUILTIN_THEMES.values()]
        assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# TestThemeRequiredFields
# ---------------------------------------------------------------------------

class TestThemeRequiredFields:
    def test_all_required_color_fields_present(self):
        """Every theme has all required color fields set (non-None)."""
        for name, theme in BUILTIN_THEMES.items():
            for field in _REQUIRED_COLOR_FIELDS:
                value = getattr(theme, field, None)
                assert value is not None, (
                    f"Theme '{name}' is missing required field '{field}'"
                )

    def test_dark_field_is_bool(self):
        """The dark field is a boolean on every theme."""
        for name, theme in BUILTIN_THEMES.items():
            assert isinstance(theme.dark, bool), (
                f"Theme '{name}'.dark is {type(theme.dark)}, expected bool"
            )


# ---------------------------------------------------------------------------
# TestThemeColorValidity
# ---------------------------------------------------------------------------

class TestThemeColorValidity:
    def test_required_fields_are_valid_hex_colors(self):
        """All required color fields are valid 6-digit hex colors."""
        for name, theme in BUILTIN_THEMES.items():
            for field in _REQUIRED_COLOR_FIELDS:
                value = getattr(theme, field)
                assert _HEX_COLOR_RE.match(value), (
                    f"Theme '{name}'.{field} = '{value}' is not a valid hex color"
                )

    def test_variables_values_are_strings(self):
        """Theme variables dict maps strings to strings."""
        for name, theme in BUILTIN_THEMES.items():
            for var_key, var_val in theme.variables.items():
                assert isinstance(var_key, str), (
                    f"Theme '{name}' variable key {var_key!r} is not str"
                )
                assert isinstance(var_val, str), (
                    f"Theme '{name}' variable value {var_val!r} is not str"
                )


# ---------------------------------------------------------------------------
# TestThemeRegistration
# ---------------------------------------------------------------------------

class TestThemeRegistration:
    async def test_all_themes_register_without_error(self):
        """Every theme can be registered with a Textual App."""
        class ThemeApp(App):
            pass

        async with ThemeApp().run_test() as pilot:
            for name, theme in BUILTIN_THEMES.items():
                pilot.app.register_theme(theme)
                assert name in pilot.app.available_themes

    async def test_all_themes_can_be_activated(self):
        """Every registered theme can be set as the active theme."""
        class ThemeApp(App):
            pass

        async with ThemeApp().run_test() as pilot:
            for name, theme in BUILTIN_THEMES.items():
                pilot.app.register_theme(theme)
                pilot.app.theme = name
                assert pilot.app.theme == name


# ---------------------------------------------------------------------------
# TestThemeConsistency
# ---------------------------------------------------------------------------

class TestThemeConsistency:
    def test_at_least_one_light_theme_exists(self):
        """At least one theme has dark=False (light theme)."""
        light_themes = [n for n, t in BUILTIN_THEMES.items() if not t.dark]
        assert len(light_themes) >= 1, "No light themes found"

    def test_at_least_one_dark_theme_exists(self):
        """At least one theme has dark=True."""
        dark_themes = [n for n, t in BUILTIN_THEMES.items() if t.dark]
        assert len(dark_themes) >= 1, "No dark themes found"

    def test_theme_names_are_lowercase(self):
        """Theme names are lowercase identifiers."""
        for name in BUILTIN_THEMES:
            assert name == name.lower(), (
                f"Theme name '{name}' is not lowercase"
            )
            assert name.isidentifier() or "-" not in name, (
                f"Theme name '{name}' contains unexpected characters"
            )

    def test_no_empty_theme_name(self):
        """No theme has an empty name."""
        for name, theme in BUILTIN_THEMES.items():
            assert len(name) > 0
            assert len(theme.name) > 0


# ---------------------------------------------------------------------------
# TestThemeAccess
# ---------------------------------------------------------------------------

class TestThemeAccess:
    def test_known_theme_names_are_accessible(self):
        """All expected theme names are present in the registry."""
        expected = {
            "galaxy", "nebula", "sunset", "aurora", "nautilus",
            "cobalt", "twilight", "hacker", "manuscript",
            "hypernova", "synthwave",
        }
        assert expected == set(BUILTIN_THEMES.keys())

    def test_missing_theme_returns_none_via_get(self):
        """Accessing a nonexistent theme via dict .get() returns None."""
        assert BUILTIN_THEMES.get("nonexistent_theme") is None

    def test_missing_theme_raises_keyerror(self):
        """Accessing a nonexistent theme via [] raises KeyError."""
        import pytest
        with pytest.raises(KeyError):
            _ = BUILTIN_THEMES["nonexistent_theme"]


# ---------------------------------------------------------------------------
# TestThemeSwitching
# ---------------------------------------------------------------------------

class TestThemeSwitching:
    async def test_switch_between_all_themes_sequentially(self):
        """Can switch between every theme in sequence without error."""
        class ThemeApp(App):
            pass

        async with ThemeApp().run_test() as pilot:
            for name, theme in BUILTIN_THEMES.items():
                pilot.app.register_theme(theme)

            theme_names = list(BUILTIN_THEMES.keys())
            for name in theme_names:
                pilot.app.theme = name
                assert pilot.app.theme == name

            # Switch back to the first theme
            pilot.app.theme = theme_names[0]
            assert pilot.app.theme == theme_names[0]

    async def test_switch_dark_to_light_and_back(self):
        """Can switch from a dark theme to a light theme and back."""
        class ThemeApp(App):
            pass

        dark_name = next(n for n, t in BUILTIN_THEMES.items() if t.dark)
        light_name = next(n for n, t in BUILTIN_THEMES.items() if not t.dark)

        async with ThemeApp().run_test() as pilot:
            for theme in BUILTIN_THEMES.values():
                pilot.app.register_theme(theme)

            pilot.app.theme = dark_name
            assert pilot.app.theme == dark_name

            pilot.app.theme = light_name
            assert pilot.app.theme == light_name

            pilot.app.theme = dark_name
            assert pilot.app.theme == dark_name
