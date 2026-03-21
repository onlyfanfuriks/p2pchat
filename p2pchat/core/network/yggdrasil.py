"""Yggdrasil subprocess lifecycle management.

Handles starting/stopping the Yggdrasil binary, config generation/patching,
and querying the admin socket for the node's IPv6 address.
"""

from __future__ import annotations

import asyncio
import atexit
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

# Pinned Yggdrasil version — auto-downloaded if binary not found.
YGGDRASIL_VERSION = "0.5.13"

# -------------------------------------------------------------------------
# Public peers list
# -------------------------------------------------------------------------

PUBLIC_PEERS: list[str] = [
    "tls://pl1.yggdrasil.iamthefij.com:18999",
    "tls://ygg.loskiq.com:17314",
    "tcp://longseason.1200bps.com:13122",
    "tcp://188.225.9.167:18226",
    "tls://yggno.de:18226",
    "tls://ygg.mkg20001.io:443",
]

# Regex that matches Yggdrasil IPv6 addresses in log/stdout output.
# Yggdrasil addresses start with 02xx (first octet 0x02).
_ADDR_RE = re.compile(
    r"(?:Your IPv6 address is|address\s*[=:])?\s*(2[0-9a-f]{2}:[0-9a-f:]+)",
    re.IGNORECASE,
)

# Also catch the JSON-style "200:..." address format that newer builds log.
_ADDR_200_RE = re.compile(r'"(200:[0-9a-f:]+)"', re.IGNORECASE)

# N-24: Maximum line length before truncation (64 KB).
_MAX_LINE_LENGTH = 65536


def _extract_address(text: str) -> str | None:
    """Return the first valid Yggdrasil IPv6 address found in *text*, or None.

    N-10: Validates candidates with ``ipaddress.IPv6Address`` to avoid false
    positives from hex strings that happen to match the regex pattern.
    """
    for pattern in (_ADDR_200_RE, _ADDR_RE):
        m = pattern.search(text)
        if m:
            candidate = m.group(1)
            try:
                ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            return candidate
    return None


class YggdrasilNode:
    """Manages a single Yggdrasil subprocess.

    Parameters
    ----------
    config_dir:
        Directory for runtime files (admin socket, run config).
        Typically ``~/.config/p2pchat/``.  Created with mode 0700 if absent.
    """

    # N-49: Class-level set to deduplicate atexit cleanup registrations.
    _registered_cleanup_paths: set[str] = set()

    def __init__(self, config_dir: Path) -> None:
        self._config_dir = config_dir
        self._process: asyncio.subprocess.Process | None = None

        # N-04: Admin socket lives inside config_dir, not world-writable /tmp.
        self._admin_sock = config_dir / "ygg.sock"
        self._admin_listen_uri = f"unix://{self._admin_sock}"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, conf_path: Path) -> str:
        """Start the Yggdrasil subprocess and return its IPv6 address.

        Parameters
        ----------
        conf_path:
            Path to the run-time config file (created by write_run_conf).

        Returns
        -------
        str
            The Yggdrasil IPv6 address (e.g. ``"200:1234:..."``)

        Raises
        ------
        FileNotFoundError
            If the Yggdrasil binary cannot be found.
        TimeoutError
            If the IPv6 address is not logged within 10 seconds.
        RuntimeError
            If the process exits unexpectedly before providing an address.
        """
        binary = self.find_binary()
        if binary is None:
            raise FileNotFoundError(
                "Yggdrasil binary not found. Install it or place it at "
                f"{self._config_dir / 'bin' / 'yggdrasil'}"
            )

        # N-31: Isolate subprocess (new session, no stdin inheritance).
        self._process = await asyncio.create_subprocess_exec(
            str(binary),
            "-useconffile",
            str(conf_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )

        log.info("Yggdrasil process started (pid=%s)", self._process.pid)

        address = await self._wait_for_address()
        log.info("Yggdrasil address: %s", address)
        return address

    async def stop(self) -> None:
        """Stop the Yggdrasil subprocess gracefully.

        Sends SIGTERM, waits up to 3 seconds, then SIGKILL.
        """
        if self._process is None:
            return

        proc = self._process
        self._process = None

        if proc.returncode is not None:
            # N-52: Log exit code for post-mortem.
            log.info(
                "Yggdrasil already exited (returncode=%s)", proc.returncode
            )
            return

        try:
            proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            return  # process already gone

        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            log.warning("Yggdrasil did not exit after SIGTERM; sending SIGKILL")
            try:
                proc.send_signal(signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass

        # N-52: Log exit code for post-mortem.
        log.info(
            "Yggdrasil process stopped (returncode=%s)", proc.returncode
        )

    async def get_address(self) -> str:
        """Query the admin socket for the node's current IPv6 address.

        Supports both Yggdrasil v0.4.x and v0.5.x admin API formats.

        Returns
        -------
        str
            The IPv6 address string (e.g. ``"200:1234:..."``)

        Raises
        ------
        ConnectionError
            If the admin socket cannot be reached.
        ValueError
            If the response does not contain the expected address field.
        """
        sock_path = str(self._admin_sock)

        # N-25: Try v0.5 format first, then fall back to v0.4.
        request_v5 = json.dumps({"request": "getself"}).encode() + b"\n"
        request_v4 = json.dumps(
            {"keepalive": True, "request": "self"}
        ).encode() + b"\n"

        data: dict = {}
        for request in (request_v5, request_v4):
            try:
                reader, writer = await asyncio.open_unix_connection(sock_path)
            except OSError as exc:
                raise ConnectionError(
                    f"Cannot connect to Yggdrasil admin socket {sock_path}: {exc}"
                ) from exc

            try:
                writer.write(request)
                await writer.drain()

                raw = await asyncio.wait_for(reader.read(65536), timeout=5.0)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON from admin socket: {exc}"
                ) from exc

            # N-25: v0.5 response: {"response": {"address": "200:..."}}
            address = self._extract_address_from_response(data)
            if address is not None:
                return address

        raise ValueError(
            "Unexpected admin socket response shape — could not find address "
            f"in response: {data!r}"
        )

    @staticmethod
    def _extract_address_from_response(data: dict) -> str | None:
        """Extract and validate IPv6 address from admin API response.

        N-34: Validates that the address is a string, reasonable length,
        and a valid IPv6 address.
        """
        # v0.5: {"response": {"address": "200:..."}}
        try:
            address = data["response"]["address"]
        except (KeyError, TypeError):
            pass
        else:
            if _validate_admin_address(address):
                return str(address)

        # v0.4: {"response": {"self": {"IPv6address": "200:..."}}}
        try:
            address = data["response"]["self"]["IPv6address"]
        except (KeyError, TypeError):
            pass
        else:
            if _validate_admin_address(address):
                return str(address)

        # v0.5 alternate: {"response": {"self": {"address": "200:..."}}}
        try:
            address = data["response"]["self"]["address"]
        except (KeyError, TypeError):
            pass
        else:
            if _validate_admin_address(address):
                return str(address)

        return None

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def find_binary(config_dir: Path | None = None) -> Path | None:
        """Search PATH and ``config_dir/bin/yggdrasil`` for the binary.

        Returns the first found path, or ``None`` if not found.

        N-17: For user-dir binaries, rejects symlinks and files not owned by
        the current user to mitigate binary replacement attacks.
        """
        # Standard PATH search.
        found = shutil.which("yggdrasil")
        if found is not None:
            return Path(found)

        # User-specific install location inside config dir.
        from p2pchat.core.account import ACCOUNT_DIR
        base = config_dir or ACCOUNT_DIR
        user_bin = base / "bin" / "yggdrasil"
        if user_bin.exists() and os.access(str(user_bin), os.X_OK):
            # N-17: Validate ownership and reject symlinks.
            try:
                st = user_bin.lstat()
            except OSError:
                return None
            if stat.S_ISLNK(st.st_mode):
                log.warning(
                    "Rejecting user yggdrasil binary %s: is a symlink",
                    user_bin,
                )
                return None
            if st.st_uid != os.getuid():
                log.warning(
                    "Rejecting user yggdrasil binary %s: owned by uid %d, "
                    "not current user %d",
                    user_bin,
                    st.st_uid,
                    os.getuid(),
                )
                return None
            return user_bin

        return None

    @staticmethod
    def download_binary(config_dir: Path) -> Path:
        """Download Yggdrasil binary for the current platform.

        Downloads from the official GitHub releases, extracts the binary,
        and places it at ``config_dir/bin/yggdrasil``.

        Returns the path to the downloaded binary.

        Raises
        ------
        RuntimeError
            If the platform is unsupported or download/extraction fails.
        """
        machine = platform.machine()
        arch_map = {
            "x86_64": "amd64",
            "aarch64": "arm64",
            "armv7l": "armhf",
        }
        arch = arch_map.get(machine)
        if arch is None:
            raise RuntimeError(
                f"Unsupported architecture: {machine}. "
                "Install Yggdrasil manually and add it to PATH."
            )

        system = platform.system()
        if system != "Linux":
            raise RuntimeError(
                f"Auto-download not supported on {system}. "
                "Install Yggdrasil manually: "
                "https://yggdrasil-network.github.io/installation.html"
            )

        deb_name = f"yggdrasil-{YGGDRASIL_VERSION}-{arch}.deb"
        url = (
            f"https://github.com/yggdrasil-network/yggdrasil-go/"
            f"releases/download/v{YGGDRASIL_VERSION}/{deb_name}"
        )

        bin_dir = config_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)

        log.info("Downloading Yggdrasil %s for %s...", YGGDRASIL_VERSION, arch)

        with tempfile.TemporaryDirectory() as tmp:
            deb_path = Path(tmp) / deb_name

            try:
                urllib.request.urlretrieve(url, deb_path)
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to download Yggdrasil from {url}: {exc}"
                ) from exc

            # Extract binaries from .deb (ar archive containing data.tar.*).
            _extract_deb(deb_path, bin_dir)

        result = bin_dir / "yggdrasil"
        log.info("Yggdrasil %s installed at %s", YGGDRASIL_VERSION, result)
        return result

    def generate_config(self, existing_json: str | None = None) -> str:
        """Return a patched Yggdrasil JSON config string.

        If *existing_json* is ``None``, runs ``yggdrasil -genconf -json`` to
        produce a fresh config, then patches it.  If *existing_json* is
        provided, the existing private key is preserved and only the
        peer list and admin settings are updated.

        .. note::

           N-42: This method uses ``subprocess.run`` which blocks the event
           loop. Call from ``asyncio.to_thread`` if running in an async context.

        Raises
        ------
        FileNotFoundError
            If the binary is not found (only when generating from scratch).
        RuntimeError
            If ``yggdrasil -genconf`` exits with a non-zero status.
        """
        if existing_json is None:
            binary = self.find_binary()
            if binary is None:
                raise FileNotFoundError(
                    "Yggdrasil binary not found; cannot generate config"
                )
            try:
                result = subprocess.run(
                    [str(binary), "-genconf", "-json"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(
                    f"yggdrasil -genconf failed (exit {exc.returncode}): "
                    f"{exc.stderr.strip()}"
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    "yggdrasil -genconf timed out after 5 seconds"
                ) from exc
            conf: dict = json.loads(result.stdout)
        else:
            conf = json.loads(existing_json)

        # Inject / overwrite operational settings.
        # N-04: Use instance admin socket path instead of hardcoded /tmp.
        conf["Peers"] = PUBLIC_PEERS
        conf["IfName"] = "auto"
        conf["AdminListen"] = self._admin_listen_uri
        conf["NodeInfo"] = {}
        conf["NodeInfoPrivacy"] = True

        return json.dumps(conf, indent=2)

    def write_run_conf(self, conf: str, path: Path) -> None:
        """Write *conf* to *path* atomically at mode 0600 and register cleanup.

        N-32: Uses temp-file + atomic rename to prevent partial writes.
        N-49: Deduplicates atexit registrations for the same path.

        Parameters
        ----------
        conf:
            JSON string to write.
        path:
            Destination file path.  Parent directory must exist.
        """
        tmp_path = path.with_suffix(path.suffix + ".tmp")

        # N-32: Write to temp file first, then rename atomically.
        fd = os.open(
            str(tmp_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = -1  # fdopen took ownership; prevent double-close
                f.write(conf)
        except BaseException:
            if fd != -1:
                try:
                    os.close(fd)  # fdopen failed before taking ownership
                except OSError:
                    pass
            # Clean up temp file on failure.
            try:
                os.unlink(str(tmp_path))
            except OSError:
                pass
            raise

        # Atomic rename (POSIX rename is atomic on the same filesystem).
        os.rename(str(tmp_path), str(path))

        # N-49: Register atexit cleanup only once per path.
        path_str = str(path)
        if path_str not in YggdrasilNode._registered_cleanup_paths:
            YggdrasilNode._registered_cleanup_paths.add(path_str)

            def _cleanup(p: str = path_str) -> None:
                try:
                    os.unlink(p)
                except OSError:
                    pass

            atexit.register(_cleanup)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _wait_for_address(self) -> str:
        """Read stdout and stderr concurrently until an IPv6 address is found.

        Times out after 10 seconds.

        Raises
        ------
        TimeoutError
            If no address is found within 10 seconds.
        RuntimeError
            If the process exits before an address is found (N-23).
        """
        # N-47: Explicit checks instead of assert.
        if self._process is None:
            raise RuntimeError("Process not started")
        if self._process.stdout is None:
            raise RuntimeError("Process stdout not available")
        if self._process.stderr is None:
            raise RuntimeError("Process stderr not available")

        # N-22: Use get_running_loop() instead of deprecated get_event_loop().
        loop = asyncio.get_running_loop()
        address_found: asyncio.Future[str] = loop.create_future()

        # N-46: create_task instead of ensure_future.
        stdout_task = asyncio.create_task(
            self._read_stream(self._process.stdout, "stdout", address_found)
        )
        stderr_task = asyncio.create_task(
            self._read_stream(self._process.stderr, "stderr", address_found)
        )
        # N-23: Monitor for early exit before address is found.
        exit_task = asyncio.create_task(
            self._monitor_exit(self._process, address_found)
        )

        try:
            await asyncio.wait_for(asyncio.shield(address_found), timeout=10.0)
        except asyncio.TimeoutError:
            stdout_task.cancel()
            stderr_task.cancel()
            exit_task.cancel()
            raise TimeoutError(
                "Yggdrasil did not log an IPv6 address within 10 seconds"
            )

        stdout_task.cancel()
        stderr_task.cancel()
        exit_task.cancel()
        await asyncio.gather(
            stdout_task, stderr_task, exit_task, return_exceptions=True
        )

        return address_found.result()

    @staticmethod
    async def _monitor_exit(
        process: asyncio.subprocess.Process,
        address_found: asyncio.Future[str],
    ) -> None:
        """N-23: Set exception on *address_found* if process exits early."""
        await process.wait()
        if not address_found.done():
            address_found.set_exception(
                RuntimeError(
                    f"Yggdrasil process exited with code {process.returncode} "
                    f"before providing an IPv6 address"
                )
            )

    @staticmethod
    async def _read_stream(
        stream: asyncio.StreamReader,
        name: str,
        address_found: "asyncio.Future[str]",
    ) -> None:
        """Read lines from *stream*, resolve *address_found* on first IPv6 match."""
        while True:
            try:
                # N-24: Limit line length to prevent unbounded memory usage.
                line = await stream.readline()
            except Exception:
                break
            if not line:
                break
            # N-24: Truncate overly long lines.
            if len(line) > _MAX_LINE_LENGTH:
                line = line[:_MAX_LINE_LENGTH]
            text = line.decode(errors="replace").strip()
            log.debug("yggdrasil %s: %s", name, text)
            if address_found.done():
                continue
            addr = _extract_address(text)
            if addr:
                address_found.set_result(addr)


# -------------------------------------------------------------------------
# Module-level helpers
# -------------------------------------------------------------------------

def _extract_deb(deb_path: Path, bin_dir: Path) -> None:
    """Extract yggdrasil and yggdrasilctl from a .deb package.

    A .deb is an ar archive containing data.tar.* with the actual files.
    Uses subprocess ar/tar or dpkg-deb for extraction.
    """
    tmp_dir = deb_path.parent

    # Try dpkg-deb first (most reliable on Debian/Ubuntu).
    dpkg = shutil.which("dpkg-deb")
    if dpkg:
        subprocess.run(
            [dpkg, "-x", str(deb_path), str(tmp_dir / "extracted")],
            check=True,
            capture_output=True,
        )
    else:
        # Fallback: ar + tar (available on most Linux systems).
        ar_bin = shutil.which("ar")
        if not ar_bin:
            raise RuntimeError(
                "Neither dpkg-deb nor ar found. Cannot extract Yggdrasil .deb. "
                "Install binutils or dpkg, or install Yggdrasil manually."
            )
        extract_dir = tmp_dir / "extracted"
        extract_dir.mkdir()
        ar_dir = tmp_dir / "ar_out"
        ar_dir.mkdir()
        subprocess.run(
            [ar_bin, "x", str(deb_path)],
            check=True, capture_output=True, cwd=str(ar_dir),
        )
        # Find data.tar.* and extract it.
        data_tar = next(ar_dir.glob("data.tar.*"), None)
        if data_tar is None:
            raise RuntimeError("No data.tar.* found in .deb archive")
        with tarfile.open(data_tar) as tf:
            tf.extractall(extract_dir)

    # Copy binaries to bin_dir.
    for name in ("yggdrasil", "yggdrasilctl"):
        src = tmp_dir / "extracted" / "usr" / "bin" / name
        if not src.exists():
            if name == "yggdrasil":
                raise RuntimeError(f"Binary {name} not found in .deb package")
            continue
        dst = bin_dir / name
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)


def _validate_admin_address(value: object) -> bool:
    """N-34: Validate that an admin API address value is a reasonable IPv6 string."""
    if not isinstance(value, str):
        return False
    if len(value) > 45:
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True
