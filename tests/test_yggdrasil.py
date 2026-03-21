"""Tests for p2pchat.core.network.yggdrasil — config generation and binary discovery.

No real Yggdrasil binary is required; config tests patch the subprocess call
and binary-discovery tests manipulate PATH / file system via monkeypatch.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from p2pchat.core.network.yggdrasil import (
    PUBLIC_PEERS,
    YggdrasilNode,
    _extract_address,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_genconf_output() -> str:
    """Return a minimal JSON config that yggdrasil -genconf might produce."""
    return json.dumps({
        "PrivateKey": "deadbeef" * 8,
        "Peers": [],
        "IfName": "tun0",
        "AdminListen": "none",
        "NodeInfo": {"name": "old"},
        "NodeInfoPrivacy": False,
    })


def _mock_genconf(monkeypatch, output: str | None = None) -> None:
    """Patch subprocess.run to return a fake yggdrasil -genconf result."""
    import subprocess

    fake_output = output if output is not None else _minimal_genconf_output()

    def _fake_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = fake_output
        result.returncode = 0
        return result

    monkeypatch.setattr(subprocess, "run", _fake_run)


def _make_node(tmp_path: Path) -> YggdrasilNode:
    """Create a YggdrasilNode with a temporary config directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    return YggdrasilNode(config_dir=config_dir)


def _make_mock_process() -> MagicMock:
    """Create a mock process with a proper async wait() that hangs until cancelled."""
    mock_proc = MagicMock()
    mock_proc.pid = 12345
    mock_proc.returncode = None

    # Make wait() an async function that blocks until cancelled.
    async def _wait_forever():
        await asyncio.Event().wait()

    mock_proc.wait = _wait_forever
    return mock_proc


# ---------------------------------------------------------------------------
# TestConfig
# ---------------------------------------------------------------------------

class TestConfig:
    def test_generate_injects_public_peers(self, tmp_path, monkeypatch):
        """Generated config contains all PUBLIC_PEERS entries."""
        _mock_genconf(monkeypatch)
        monkeypatch.setattr(
            YggdrasilNode, "find_binary", staticmethod(lambda _=None: Path("/usr/bin/yggdrasil"))
        )

        node = _make_node(tmp_path)
        conf_str = node.generate_config()
        conf = json.loads(conf_str)

        assert conf["Peers"] == PUBLIC_PEERS

    def test_patch_existing_keeps_private_key(self, tmp_path, monkeypatch):
        """Patching an existing config preserves the PrivateKey field."""
        original_key = "cafebabe" * 8
        existing = json.dumps({
            "PrivateKey": original_key,
            "Peers": [],
            "IfName": "tun99",
            "AdminListen": "none",
            "NodeInfo": {},
            "NodeInfoPrivacy": False,
        })

        node = _make_node(tmp_path)
        conf_str = node.generate_config(existing_json=existing)
        conf = json.loads(conf_str)

        assert conf["PrivateKey"] == original_key

    def test_admin_listen_set_to_config_dir(self, tmp_path, monkeypatch):
        """N-04: AdminListen uses config_dir, not /tmp."""
        _mock_genconf(monkeypatch)
        monkeypatch.setattr(
            YggdrasilNode, "find_binary", staticmethod(lambda _=None: Path("/usr/bin/yggdrasil"))
        )

        node = _make_node(tmp_path)
        conf_str = node.generate_config()
        conf = json.loads(conf_str)

        expected_sock = str(tmp_path / "config" / "ygg.sock")
        assert conf["AdminListen"] == f"unix://{expected_sock}"
        # Must NOT use the old hardcoded /tmp path.
        assert "/tmp/p2pchat-ygg.sock" not in conf["AdminListen"]

    def test_node_info_privacy_set(self, tmp_path, monkeypatch):
        """NodeInfoPrivacy is True and NodeInfo is an empty dict."""
        _mock_genconf(monkeypatch)
        monkeypatch.setattr(
            YggdrasilNode, "find_binary", staticmethod(lambda _=None: Path("/usr/bin/yggdrasil"))
        )

        node = _make_node(tmp_path)
        conf_str = node.generate_config()
        conf = json.loads(conf_str)

        assert conf["NodeInfoPrivacy"] is True
        assert conf["NodeInfo"] == {}

    def test_if_name_set_to_auto(self, tmp_path, monkeypatch):
        """IfName is set to 'auto'."""
        existing = _minimal_genconf_output()
        node = _make_node(tmp_path)
        conf_str = node.generate_config(existing_json=existing)
        conf = json.loads(conf_str)
        assert conf["IfName"] == "auto"

    def test_patch_existing_injects_peers(self, tmp_path, monkeypatch):
        """Patching an existing config replaces the peer list."""
        existing = json.dumps({
            "PrivateKey": "aabbccdd" * 8,
            "Peers": ["tcp://old.peer.example.com:12345"],
            "IfName": "tun0",
            "AdminListen": "none",
            "NodeInfo": {},
            "NodeInfoPrivacy": False,
        })
        node = _make_node(tmp_path)
        conf_str = node.generate_config(existing_json=existing)
        conf = json.loads(conf_str)

        assert conf["Peers"] == PUBLIC_PEERS
        # Old peer should be gone.
        assert "tcp://old.peer.example.com:12345" not in conf["Peers"]

    def test_write_run_conf_creates_file_at_0600(self, tmp_path):
        """write_run_conf creates the file with 0600 permissions."""
        node = _make_node(tmp_path)
        conf_path = tmp_path / "ygg_run.conf"
        conf_content = _minimal_genconf_output()

        node.write_run_conf(conf_content, conf_path)

        assert conf_path.exists()
        mode = stat.S_IMODE(os.stat(conf_path).st_mode)
        assert mode == 0o600

        written = conf_path.read_text()
        assert written == conf_content

    def test_write_run_conf_content_is_valid_json(self, tmp_path):
        """The file written by write_run_conf contains valid JSON."""
        node = _make_node(tmp_path)
        conf_path = tmp_path / "ygg_run.conf"
        conf_str = node.generate_config(existing_json=_minimal_genconf_output())

        node.write_run_conf(conf_str, conf_path)

        parsed = json.loads(conf_path.read_text())
        assert "Peers" in parsed

    def test_write_run_conf_is_atomic(self, tmp_path):
        """N-32: write_run_conf writes via temp file + rename (atomic)."""
        node = _make_node(tmp_path)
        conf_path = tmp_path / "ygg_run.conf"

        # Write initial content.
        node.write_run_conf('{"first": true}', conf_path)
        assert conf_path.read_text() == '{"first": true}'

        # Overwrite — should be atomic (no .tmp file remaining).
        node.write_run_conf('{"second": true}', conf_path)
        assert conf_path.read_text() == '{"second": true}'

        # No .tmp file should remain.
        tmp_file = conf_path.with_suffix(conf_path.suffix + ".tmp")
        assert not tmp_file.exists()

    def test_write_run_conf_deduplicates_atexit(self, tmp_path):
        """N-49: Multiple writes to the same path register only one atexit handler."""
        node = _make_node(tmp_path)
        conf_path = tmp_path / "ygg_run.conf"

        path_str = str(conf_path)
        # Clear any prior state.
        YggdrasilNode._registered_cleanup_paths.discard(path_str)

        node.write_run_conf('{"a": 1}', conf_path)
        assert path_str in YggdrasilNode._registered_cleanup_paths

        # Writing again should NOT add another entry.
        initial_count = len(YggdrasilNode._registered_cleanup_paths)
        node.write_run_conf('{"a": 2}', conf_path)
        assert len(YggdrasilNode._registered_cleanup_paths) == initial_count

        # Cleanup.
        YggdrasilNode._registered_cleanup_paths.discard(path_str)


# ---------------------------------------------------------------------------
# TestFindBinary
# ---------------------------------------------------------------------------

class TestFindBinary:
    def test_returns_none_when_not_found(self, tmp_path, monkeypatch):
        """find_binary returns None if yggdrasil is absent from PATH and config dir."""
        monkeypatch.setenv("PATH", str(tmp_path / "empty_bin"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        import shutil
        monkeypatch.setattr(shutil, "which", lambda _name: None)

        result = YggdrasilNode.find_binary()
        assert result is None

    def test_finds_binary_in_path(self, tmp_path, monkeypatch):
        """find_binary returns the path when yggdrasil is on PATH."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        binary = bin_dir / "yggdrasil"
        binary.write_bytes(b"#!/bin/sh\n")
        binary.chmod(0o755)

        import shutil
        monkeypatch.setattr(shutil, "which", lambda _name: str(binary))

        result = YggdrasilNode.find_binary()
        assert result == binary

    def test_finds_binary_in_config_dir(self, tmp_path, monkeypatch):
        """find_binary finds the binary at config_dir/bin/yggdrasil."""
        import shutil
        monkeypatch.setattr(shutil, "which", lambda _name: None)

        config_dir = tmp_path / ".config" / "p2pchat"
        user_bin_dir = config_dir / "bin"
        user_bin_dir.mkdir(parents=True)
        binary = user_bin_dir / "yggdrasil"
        binary.write_bytes(b"#!/bin/sh\n")
        binary.chmod(0o755)

        result = YggdrasilNode.find_binary(config_dir)
        assert result == binary

    def test_path_search_takes_precedence_over_config_dir(self, tmp_path, monkeypatch):
        """If yggdrasil is in PATH, that takes precedence over the config dir."""
        path_binary = tmp_path / "path_bin" / "yggdrasil"
        (tmp_path / "path_bin").mkdir()
        path_binary.write_bytes(b"#!/bin/sh\n")
        path_binary.chmod(0o755)

        import shutil
        monkeypatch.setattr(shutil, "which", lambda _name: str(path_binary))

        user_bin_dir = tmp_path / ".config" / "p2pchat" / "bin"
        user_bin_dir.mkdir(parents=True)
        config_binary = user_bin_dir / "yggdrasil"
        config_binary.write_bytes(b"#!/bin/sh\n")
        config_binary.chmod(0o755)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = YggdrasilNode.find_binary()
        assert result == path_binary

    def test_rejects_symlink_in_config_dir(self, tmp_path, monkeypatch):
        """N-17: find_binary rejects symlinked binaries in the config dir."""
        import shutil
        monkeypatch.setattr(shutil, "which", lambda _name: None)

        user_bin_dir = tmp_path / ".config" / "p2pchat" / "bin"
        user_bin_dir.mkdir(parents=True)
        real_binary = tmp_path / "real_yggdrasil"
        real_binary.write_bytes(b"#!/bin/sh\n")
        real_binary.chmod(0o755)

        # Create symlink.
        symlink = user_bin_dir / "yggdrasil"
        symlink.symlink_to(real_binary)

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = YggdrasilNode.find_binary()
        assert result is None


# ---------------------------------------------------------------------------
# TestExtractAddress
# ---------------------------------------------------------------------------

class TestExtractAddress:
    def test_valid_yggdrasil_address(self):
        """Extracts a valid Yggdrasil IPv6 address."""
        text = "Your IPv6 address is 200:1234:5678:abcd::1"
        result = _extract_address(text)
        assert result == "200:1234:5678:abcd::1"

    def test_json_style_address(self):
        """Extracts address from JSON-style log line."""
        text = '{"level":"info","address":"200:cafe:beef::1"}'
        result = _extract_address(text)
        assert result == "200:cafe:beef::1"

    def test_rejects_invalid_hex_false_positive(self):
        """N-10: Rejects hex strings that match regex but aren't valid IPv6."""
        # This looks like it could match _ADDR_RE but is not valid IPv6.
        text = "version 2ab:not:a:valid:ipv6:address:at:all:extra"
        result = _extract_address(text)
        assert result is None

    def test_returns_none_for_no_address(self):
        """Returns None when no address is present."""
        text = "Starting Yggdrasil node..."
        result = _extract_address(text)
        assert result is None

    def test_regex_match_invalid_ipv6_continues(self):
        """N-10: Regex match that fails IPv6 validation is skipped."""
        # Matches _ADDR_RE pattern but has 9 groups — not valid IPv6.
        text = "address=2ff:1:2:3:4:5:6:7:8:9"
        result = _extract_address(text)
        assert result is None


# ---------------------------------------------------------------------------
# TestWaitForAddress
# ---------------------------------------------------------------------------

class TestWaitForAddress:
    async def test_parses_address_from_stdout(self, tmp_path):
        """_wait_for_address extracts an IPv6 address from simulated stdout."""
        node = _make_node(tmp_path)

        stdout_reader = asyncio.StreamReader()
        stderr_reader = asyncio.StreamReader()

        address_line = b"Your IPv6 address is 200:1234:5678:abcd::1\n"
        stdout_reader.feed_data(address_line)
        stdout_reader.feed_eof()
        stderr_reader.feed_eof()

        mock_proc = _make_mock_process()
        mock_proc.stdout = stdout_reader
        mock_proc.stderr = stderr_reader

        node._process = mock_proc

        address = await node._wait_for_address()
        assert address.startswith("200:")

    async def test_parses_address_from_stderr(self, tmp_path):
        """_wait_for_address extracts an IPv6 address from stderr output."""
        node = _make_node(tmp_path)

        stdout_reader = asyncio.StreamReader()
        stderr_reader = asyncio.StreamReader()

        stdout_reader.feed_eof()
        stderr_reader.feed_data(b"INFO address = 200:abcd::1\n")
        stderr_reader.feed_eof()

        mock_proc = _make_mock_process()
        mock_proc.stdout = stdout_reader
        mock_proc.stderr = stderr_reader

        node._process = mock_proc

        address = await node._wait_for_address()
        assert address.startswith("200:")

    async def test_parses_200_json_style_address(self, tmp_path):
        """_wait_for_address handles the '"200:..."' JSON-log format."""
        node = _make_node(tmp_path)

        stdout_reader = asyncio.StreamReader()
        stderr_reader = asyncio.StreamReader()

        log_line = b'{"level":"info","address":"200:cafe:beef::1"}\n'
        stdout_reader.feed_data(log_line)
        stdout_reader.feed_eof()
        stderr_reader.feed_eof()

        mock_proc = _make_mock_process()
        mock_proc.stdout = stdout_reader
        mock_proc.stderr = stderr_reader

        node._process = mock_proc

        address = await node._wait_for_address()
        assert "200:" in address

    async def test_timeout_raises(self, tmp_path):
        """_wait_for_address raises TimeoutError if no address appears."""
        node = _make_node(tmp_path)

        # Streams that never produce a valid address and stay open.
        stdout_reader = asyncio.StreamReader()
        stderr_reader = asyncio.StreamReader()
        stdout_reader.feed_data(b"Starting up...\n")
        stdout_reader.feed_data(b"Loading config...\n")
        # Do NOT feed EOF — simulate a running process with no address output.

        mock_proc = _make_mock_process()
        mock_proc.stdout = stdout_reader
        mock_proc.stderr = stderr_reader

        node._process = mock_proc

        # Patch asyncio.wait_for to use a very short timeout so the test is fast.
        original_wait_for = asyncio.wait_for

        async def _fast_wait_for(coro, timeout):
            return await original_wait_for(coro, timeout=0.1)

        with patch("p2pchat.core.network.yggdrasil.asyncio.wait_for", _fast_wait_for):
            with pytest.raises(TimeoutError, match="10 seconds"):
                await node._wait_for_address()

    async def test_early_exit_raises_runtime_error(self, tmp_path):
        """N-23: _wait_for_address raises RuntimeError if process exits early."""
        node = _make_node(tmp_path)

        stdout_reader = asyncio.StreamReader()
        stderr_reader = asyncio.StreamReader()
        stdout_reader.feed_data(b"Error: bad config\n")
        stdout_reader.feed_eof()
        stderr_reader.feed_eof()

        mock_proc = MagicMock()
        mock_proc.pid = 1
        mock_proc.returncode = 1
        mock_proc.stdout = stdout_reader
        mock_proc.stderr = stderr_reader

        # Make wait() return immediately (process already exited).
        mock_proc.wait = AsyncMock(return_value=None)

        node._process = mock_proc

        with pytest.raises(RuntimeError, match="exited with code"):
            await node._wait_for_address()

    async def test_long_line_truncated(self, tmp_path):
        """N-24: Lines over 64KB are truncated in _read_stream."""
        node = _make_node(tmp_path)

        # StreamReader has a default 64KB line limit; set higher for this test.
        stdout_reader = asyncio.StreamReader(limit=200_000)
        stderr_reader = asyncio.StreamReader()

        # Feed a very long line without an address, then a valid address.
        long_line = b"X" * 100_000 + b"\n"
        stdout_reader.feed_data(long_line)
        stdout_reader.feed_data(b"Your IPv6 address is 200:abcd::1\n")
        stdout_reader.feed_eof()
        stderr_reader.feed_eof()

        mock_proc = _make_mock_process()
        mock_proc.stdout = stdout_reader
        mock_proc.stderr = stderr_reader
        node._process = mock_proc

        address = await node._wait_for_address()
        assert address == "200:abcd::1"


# ---------------------------------------------------------------------------
# TestStop
# ---------------------------------------------------------------------------

class TestStop:
    async def test_stop_when_not_started(self, tmp_path):
        """stop() is safe when no process was started."""
        node = _make_node(tmp_path)
        await node.stop()  # Should not raise.

    async def test_stop_already_exited(self, tmp_path):
        """N-52: stop() logs exit code when process already exited."""
        node = _make_node(tmp_path)

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        node._process = mock_proc

        await node.stop()
        assert node._process is None

    async def test_stop_sends_sigterm(self, tmp_path):
        """stop() sends SIGTERM and waits."""
        import signal

        node = _make_node(tmp_path)

        mock_proc = MagicMock()
        mock_proc.returncode = None
        mock_proc.send_signal = MagicMock()
        mock_proc.wait = AsyncMock(return_value=None)

        # After wait, set returncode to simulate clean exit.
        async def _wait_and_exit():
            mock_proc.returncode = 0

        mock_proc.wait = AsyncMock(side_effect=_wait_and_exit)
        node._process = mock_proc

        await node.stop()
        mock_proc.send_signal.assert_called_with(signal.SIGTERM)

    async def test_stop_sigkill_on_timeout(self, tmp_path):
        """stop() sends SIGKILL if SIGTERM doesn't work within 3s."""
        import signal

        node = _make_node(tmp_path)

        mock_proc = MagicMock()
        mock_proc.returncode = None

        signals_sent = []
        mock_proc.send_signal = MagicMock(side_effect=lambda s: signals_sent.append(s))

        # First wait (SIGTERM) times out, second wait (SIGKILL) succeeds.
        call_count = 0

        async def _wait():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.TimeoutError()

        mock_proc.wait = _wait
        node._process = mock_proc

        await node.stop()
        assert signal.SIGTERM in signals_sent
        assert signal.SIGKILL in signals_sent


# ---------------------------------------------------------------------------
# TestValidateAdminAddress
# ---------------------------------------------------------------------------

class TestValidateAdminAddress:
    def test_valid_ipv6(self):
        """Valid IPv6 string passes validation."""
        from p2pchat.core.network.yggdrasil import _validate_admin_address
        assert _validate_admin_address("200:abcd::1") is True

    def test_rejects_non_string(self):
        """N-34: Non-string values are rejected."""
        from p2pchat.core.network.yggdrasil import _validate_admin_address
        assert _validate_admin_address(12345) is False
        assert _validate_admin_address(None) is False

    def test_rejects_too_long(self):
        """N-34: Strings longer than 45 chars are rejected."""
        from p2pchat.core.network.yggdrasil import _validate_admin_address
        assert _validate_admin_address("a" * 46) is False

    def test_rejects_invalid_ipv6(self):
        """N-34: Invalid IPv6 strings are rejected."""
        from p2pchat.core.network.yggdrasil import _validate_admin_address
        assert _validate_admin_address("not-an-ipv6") is False


# ---------------------------------------------------------------------------
# TestExtractAddressFromResponse
# ---------------------------------------------------------------------------

class TestExtractAddressFromResponse:
    def test_v5_format(self):
        """Extracts address from v0.5 response format."""
        data = {"response": {"address": "200:abcd::1"}}
        result = YggdrasilNode._extract_address_from_response(data)
        assert result == "200:abcd::1"

    def test_v4_format(self):
        """Extracts address from v0.4 response format."""
        data = {"response": {"self": {"IPv6address": "200:abcd::1"}}}
        result = YggdrasilNode._extract_address_from_response(data)
        assert result == "200:abcd::1"

    def test_v5_self_format(self):
        """Extracts address from v0.5 alternate format."""
        data = {"response": {"self": {"address": "200:abcd::1"}}}
        result = YggdrasilNode._extract_address_from_response(data)
        assert result == "200:abcd::1"

    def test_returns_none_for_empty(self):
        """Returns None when response has no address."""
        data = {"response": {}}
        result = YggdrasilNode._extract_address_from_response(data)
        assert result is None

    def test_rejects_invalid_address_in_response(self):
        """N-34: Invalid address values in response are rejected."""
        data = {"response": {"address": "not-valid"}}
        result = YggdrasilNode._extract_address_from_response(data)
        assert result is None


# ---------------------------------------------------------------------------
# TestStartMethod
# ---------------------------------------------------------------------------

class TestStartMethod:
    async def test_start_returns_address(self, tmp_path):
        """start() launches subprocess and returns the IPv6 address."""
        node = _make_node(tmp_path)
        conf_path = tmp_path / "config" / "ygg.conf"
        conf_path.write_text('{"test": true}')

        mock_proc = MagicMock()
        mock_proc.pid = 12345

        with patch.object(YggdrasilNode, "find_binary", return_value=Path("/usr/bin/yggdrasil")):
            with patch(
                "p2pchat.core.network.yggdrasil.asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ):
                with patch.object(
                    node, "_wait_for_address",
                    new_callable=AsyncMock,
                    return_value="200:abcd::1",
                ):
                    address = await node.start(conf_path)

        assert address == "200:abcd::1"
        assert node._process is mock_proc

    async def test_start_binary_not_found(self, tmp_path):
        """start() raises FileNotFoundError when binary is missing."""
        node = _make_node(tmp_path)
        conf_path = tmp_path / "config" / "ygg.conf"

        with patch.object(YggdrasilNode, "find_binary", return_value=None):
            with pytest.raises(FileNotFoundError, match="not found"):
                await node.start(conf_path)


# ---------------------------------------------------------------------------
# TestGetAddress
# ---------------------------------------------------------------------------

class TestGetAddress:
    async def test_v5_response(self, tmp_path):
        """get_address() parses v0.5 admin API response."""
        node = _make_node(tmp_path)

        response_data = json.dumps({"response": {"address": "200:abcd::1"}}).encode()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=response_data)
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "p2pchat.core.network.yggdrasil.asyncio.open_unix_connection",
            new_callable=AsyncMock,
            return_value=(mock_reader, mock_writer),
        ):
            address = await node.get_address()

        assert address == "200:abcd::1"

    async def test_v4_fallback(self, tmp_path):
        """get_address() falls back to v0.4 format when v0.5 lacks address."""
        node = _make_node(tmp_path)

        v5_resp = json.dumps({"response": {}}).encode()
        v4_resp = json.dumps(
            {"response": {"self": {"IPv6address": "200:beef::1"}}}
        ).encode()

        call_count = 0

        async def _mock_connect(path):
            nonlocal call_count
            call_count += 1
            r = AsyncMock()
            r.read = AsyncMock(
                return_value=v5_resp if call_count == 1 else v4_resp
            )
            w = MagicMock()
            w.write = MagicMock()
            w.drain = AsyncMock()
            w.close = MagicMock()
            w.wait_closed = AsyncMock()
            return r, w

        with patch(
            "p2pchat.core.network.yggdrasil.asyncio.open_unix_connection",
            side_effect=_mock_connect,
        ):
            address = await node.get_address()

        assert address == "200:beef::1"

    async def test_socket_unreachable(self, tmp_path):
        """get_address() raises ConnectionError when socket is unreachable."""
        node = _make_node(tmp_path)

        with patch(
            "p2pchat.core.network.yggdrasil.asyncio.open_unix_connection",
            new_callable=AsyncMock,
            side_effect=OSError("No such file"),
        ):
            with pytest.raises(ConnectionError, match="Cannot connect"):
                await node.get_address()

    async def test_invalid_json_response(self, tmp_path):
        """get_address() raises ValueError on malformed JSON response."""
        node = _make_node(tmp_path)

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"not json at all")
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "p2pchat.core.network.yggdrasil.asyncio.open_unix_connection",
            new_callable=AsyncMock,
            return_value=(mock_reader, mock_writer),
        ):
            with pytest.raises(ValueError, match="Invalid JSON"):
                await node.get_address()

    async def test_no_address_in_any_format(self, tmp_path):
        """get_address() raises ValueError when no format yields an address."""
        node = _make_node(tmp_path)

        empty_resp = json.dumps({"response": {"other": "data"}}).encode()

        async def _mock_connect(path):
            r = AsyncMock()
            r.read = AsyncMock(return_value=empty_resp)
            w = MagicMock()
            w.write = MagicMock()
            w.drain = AsyncMock()
            w.close = MagicMock()
            w.wait_closed = AsyncMock()
            return r, w

        with patch(
            "p2pchat.core.network.yggdrasil.asyncio.open_unix_connection",
            side_effect=_mock_connect,
        ):
            with pytest.raises(ValueError, match="could not find address"):
                await node.get_address()


# ---------------------------------------------------------------------------
# TestWaitForAddressPreconditions
# ---------------------------------------------------------------------------

class TestWaitForAddressPreconditions:
    async def test_no_process(self, tmp_path):
        """_wait_for_address raises RuntimeError when process is None."""
        node = _make_node(tmp_path)
        with pytest.raises(RuntimeError, match="not started"):
            await node._wait_for_address()

    async def test_no_stdout(self, tmp_path):
        """_wait_for_address raises RuntimeError when stdout is None."""
        node = _make_node(tmp_path)
        mock_proc = MagicMock()
        mock_proc.stdout = None
        mock_proc.stderr = MagicMock()
        node._process = mock_proc

        with pytest.raises(RuntimeError, match="stdout"):
            await node._wait_for_address()

    async def test_no_stderr(self, tmp_path):
        """_wait_for_address raises RuntimeError when stderr is None."""
        node = _make_node(tmp_path)
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stderr = None
        node._process = mock_proc

        with pytest.raises(RuntimeError, match="stderr"):
            await node._wait_for_address()


# ---------------------------------------------------------------------------
# TestStopEdgeCases
# ---------------------------------------------------------------------------

class TestStopEdgeCases:
    async def test_sigterm_process_already_gone(self, tmp_path):
        """stop() handles ProcessLookupError when SIGTERM fails."""
        node = _make_node(tmp_path)
        mock_proc = MagicMock()
        mock_proc.returncode = None
        mock_proc.send_signal = MagicMock(side_effect=ProcessLookupError())
        node._process = mock_proc

        await node.stop()
        assert node._process is None


# ---------------------------------------------------------------------------
# TestGenerateConfigErrors
# ---------------------------------------------------------------------------

class TestGenerateConfigErrors:
    def test_binary_not_found(self, tmp_path):
        """generate_config raises FileNotFoundError when no binary."""
        node = _make_node(tmp_path)
        with patch.object(YggdrasilNode, "find_binary", return_value=None):
            with pytest.raises(FileNotFoundError, match="not found"):
                node.generate_config()

    def test_genconf_nonzero_exit(self, tmp_path, monkeypatch):
        """generate_config raises RuntimeError on genconf failure."""
        import subprocess as sp

        node = _make_node(tmp_path)
        monkeypatch.setattr(
            YggdrasilNode, "find_binary",
            staticmethod(lambda _=None: Path("/usr/bin/yggdrasil")),
        )

        def _fail(cmd, **kwargs):
            raise sp.CalledProcessError(1, cmd, stderr="config error")

        monkeypatch.setattr(sp, "run", _fail)

        with pytest.raises(RuntimeError, match="genconf failed"):
            node.generate_config()

    def test_genconf_timeout(self, tmp_path, monkeypatch):
        """generate_config raises RuntimeError on timeout."""
        import subprocess as sp

        node = _make_node(tmp_path)
        monkeypatch.setattr(
            YggdrasilNode, "find_binary",
            staticmethod(lambda _=None: Path("/usr/bin/yggdrasil")),
        )

        def _timeout(cmd, **kwargs):
            raise sp.TimeoutExpired(cmd, 5)

        monkeypatch.setattr(sp, "run", _timeout)

        with pytest.raises(RuntimeError, match="timed out"):
            node.generate_config()


# ---------------------------------------------------------------------------
# TestFindBinaryEdgeCases
# ---------------------------------------------------------------------------

class TestFindBinaryEdgeCases:
    def test_lstat_oserror(self, tmp_path, monkeypatch):
        """find_binary returns None when lstat fails on user binary."""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda _name: None)

        user_bin_dir = tmp_path / ".config" / "p2pchat" / "bin"
        user_bin_dir.mkdir(parents=True)
        binary = user_bin_dir / "yggdrasil"
        binary.write_bytes(b"#!/bin/sh\n")
        binary.chmod(0o755)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        original_lstat = Path.lstat

        def _failing_lstat(self_path):
            if self_path.name == "yggdrasil":
                raise OSError("permission denied")
            return original_lstat(self_path)

        monkeypatch.setattr(Path, "lstat", _failing_lstat)

        result = YggdrasilNode.find_binary()
        assert result is None

    def test_ownership_mismatch(self, tmp_path, monkeypatch):
        """N-17: Rejects binary owned by a different user."""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda _name: None)

        user_bin_dir = tmp_path / ".config" / "p2pchat" / "bin"
        user_bin_dir.mkdir(parents=True)
        binary = user_bin_dir / "yggdrasil"
        binary.write_bytes(b"#!/bin/sh\n")
        binary.chmod(0o755)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        real_uid = os.getuid()
        monkeypatch.setattr(os, "getuid", lambda: real_uid + 999)

        result = YggdrasilNode.find_binary()
        assert result is None
