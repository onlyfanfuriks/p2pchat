"""Account identity management.

Supports multiple accounts. Each account lives in its own subdirectory
under ``~/.config/p2pchat/accounts/<name>/``. Holds two keypairs:

- Ed25519: permanent identity + message signing. Public key = user ID.
- X25519:  ECDH session key exchange.

Private material is encrypted at rest with AES-256-GCM (PBKDF2-derived key).
The ``display_name`` is stored in **plaintext** in the outer JSON envelope
so the unlock screen can list accounts without decryption (the display name
is public information — it is shared in invite links).
"""

import base64
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import (
    decrypt,
    encode_public_key,
    encrypt,
    ed25519_from_bytes,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    derive_account_key,
    private_key_to_bytes,
    x25519_from_bytes,
)

# Base configuration directory (shared across all accounts).
ACCOUNT_DIR = Path.home() / ".config" / "p2pchat"

# Per-account subdirectories live here.
ACCOUNTS_DIR = ACCOUNT_DIR / "accounts"

ACCOUNT_VERSION = 1
_ACCOUNT_FILENAME = "account.json"

# Kept for backward-compatibility with old single-account layout.
ACCOUNT_FILE = ACCOUNT_DIR / _ACCOUNT_FILENAME

_DIRNAME_RE = re.compile(r"[^\w\s-]", re.UNICODE)


def _sanitize_dirname(name: str) -> str:
    """Convert a display name into a filesystem-safe directory name."""
    safe = _DIRNAME_RE.sub("_", name).strip()
    safe = re.sub(r"\s+", "_", safe)
    safe = safe[:64] or "account"
    return safe


@dataclass
class AccountInfo:
    """Lightweight account metadata readable without decryption."""

    display_name: str
    account_dir: Path
    created_at: int


def list_accounts() -> list[AccountInfo]:
    """Scan ``ACCOUNTS_DIR`` and return metadata for each account found.

    Does NOT require a password — reads only plaintext fields.
    """
    results: list[AccountInfo] = []
    if not ACCOUNTS_DIR.is_dir():
        return results

    for entry in sorted(ACCOUNTS_DIR.iterdir()):
        acct_file = entry / _ACCOUNT_FILENAME
        if not entry.is_dir() or not acct_file.is_file():
            continue
        try:
            data = json.loads(acct_file.read_text(encoding="utf-8"))
            name = data.get("display_name_plain", entry.name)
            created = data.get("created_at", 0)
            results.append(AccountInfo(name, entry, created))
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable — still list it by dir name.
            results.append(AccountInfo(entry.name, entry, 0))

    return results


def migrate_legacy_account() -> None:
    """Move old single-account layout into ``accounts/<name>/``.

    Old layout:  ``~/.config/p2pchat/account.json`` (+ sibling files).
    New layout:  ``~/.config/p2pchat/accounts/<name>/...``.

    Called once at startup before listing accounts.
    """
    if not ACCOUNT_FILE.is_file():
        return
    # Already migrated?
    if ACCOUNTS_DIR.is_dir() and any(ACCOUNTS_DIR.iterdir()):
        return

    # Try to read the display name from the plaintext field.
    try:
        data = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
        name = data.get("display_name_plain", "default")
    except (json.JSONDecodeError, OSError):
        name = "default"

    dest = ACCOUNTS_DIR / _sanitize_dirname(name)
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Files that belong to a single account.
    siblings = [
        _ACCOUNT_FILENAME, "messages.db",
        "tls.crt", "tls.key",
        "ygg_run.conf", "ygg.sock",
    ]
    for fname in siblings:
        src = ACCOUNT_DIR / fname
        if src.exists():
            src.rename(dest / fname)


@dataclass(eq=False, repr=False)
class Account:
    """In-memory account holding decrypted keypairs and identity info.

    eq=False: Ed25519/X25519 key objects don't implement value equality —
              use __eq__ below which compares public key bytes instead.
    repr=False: prevents private key objects from appearing in logs.
    """

    ed25519_private: Ed25519PrivateKey
    ed25519_public: bytes           # 32 raw bytes
    x25519_private: X25519PrivateKey
    x25519_public: bytes            # 32 raw bytes
    display_name: str
    account_dir: Path = field(default_factory=lambda: ACCOUNT_DIR)
    created_at: int = field(default_factory=lambda: int(time.time()))
    ygg_address: str = ""           # set after Yggdrasil starts
    ygg_conf: str = ""              # yggdrasil.conf content (stored encrypted at rest)

    def __repr__(self) -> str:
        return f"Account(user_id={self.user_id!r}, display_name={self.display_name!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Account):
            return NotImplemented
        return (
            self.ed25519_public == other.ed25519_public
            and self.x25519_public == other.x25519_public
        )

    @property
    def user_id(self) -> str:
        """Base64url(ed25519_public) — the shareable permanent identifier."""
        return encode_public_key(self.ed25519_public)

    @staticmethod
    def exists(account_dir: Path | None = None) -> bool:
        """Check whether an account file exists in *account_dir*.

        If *account_dir* is ``None``, returns ``True`` if **any** account
        exists (either new multi-account layout or legacy single-account).
        """
        if account_dir is not None:
            return (account_dir / _ACCOUNT_FILENAME).is_file()
        # Any account at all?
        if ACCOUNT_FILE.is_file():
            return True
        return bool(list_accounts())

    @classmethod
    def create(
        cls,
        password: str,
        display_name: str,
        account_dir: Path | None = None,
    ) -> "Account":
        """Generate new keypairs and save encrypted account to disk.

        If *account_dir* is ``None``, a new subdirectory is created under
        ``ACCOUNTS_DIR`` derived from *display_name*.
        """
        if account_dir is None:
            dirname = _sanitize_dirname(display_name)
            account_dir = ACCOUNTS_DIR / dirname
            # Avoid collisions.
            if account_dir.exists():
                i = 2
                while (ACCOUNTS_DIR / f"{dirname}_{i}").exists():
                    i += 1
                account_dir = ACCOUNTS_DIR / f"{dirname}_{i}"

        ed_priv, ed_pub = generate_ed25519_keypair()
        x_priv, x_pub = generate_x25519_keypair()

        account = cls(
            ed25519_private=ed_priv,
            ed25519_public=ed_pub,
            x25519_private=x_priv,
            x25519_public=x_pub,
            display_name=display_name,
            account_dir=account_dir,
        )
        account.save(password)
        return account

    def save(self, password: str) -> None:
        """Encrypt all material and persist atomically to disk.

        Uses a write-to-tmp-then-rename pattern to prevent partial writes
        from corrupting the account file (the only copy of the private key).
        File is created with 0600 permissions from the start (no TOCTOU race).
        """
        self.account_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

        salt = os.urandom(32)
        key = derive_account_key(password, salt)

        def _enc(data: bytes) -> str:
            """Encrypt bytes -> urlsafe-base64(nonce || ciphertext)."""
            blob = encrypt(key, data)
            return base64.urlsafe_b64encode(blob.nonce + blob.ciphertext).decode()

        data = {
            "version": ACCOUNT_VERSION,
            "display_name_plain": self.display_name,
            "display_name": _enc(self.display_name.encode()),
            "ed25519_private": _enc(private_key_to_bytes(self.ed25519_private)),
            "x25519_private": _enc(private_key_to_bytes(self.x25519_private)),
            "ygg_conf": _enc(self.ygg_conf.encode()) if self.ygg_conf else "",
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "created_at": self.created_at,
        }

        json_str = json.dumps(data, indent=2)

        account_file = self.account_dir / _ACCOUNT_FILENAME
        tmp_path = account_file.with_suffix(".tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json_str)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        tmp_path.replace(account_file)

    @classmethod
    def load(cls, password: str, account_dir: Path | None = None) -> "Account":
        """Load and decrypt account from disk. Raises on wrong password.

        *account_dir* is the per-account directory containing ``account.json``.
        If ``None``, falls back to the legacy ``ACCOUNT_FILE`` location.
        """
        if account_dir is not None:
            account_file = account_dir / _ACCOUNT_FILENAME
        else:
            account_file = ACCOUNT_FILE
            account_dir = ACCOUNT_DIR

        if not account_file.exists():
            raise FileNotFoundError(
                f"No account found at {account_file}. "
                "Create one with Account.create() first."
            )

        raw = account_file.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Account file is corrupt (invalid JSON): {exc}") from exc

        if data.get("version") != ACCOUNT_VERSION:
            raise ValueError(
                f"Unsupported account version: {data.get('version')}. "
                f"Expected {ACCOUNT_VERSION}."
            )

        try:
            salt = base64.urlsafe_b64decode(data["salt"] + "=" * (-len(data["salt"]) % 4))
        except KeyError as exc:
            raise ValueError(f"Corrupt account file: missing field {exc}") from exc

        key = derive_account_key(password, salt)

        def _dec(encoded: str) -> bytes:
            """urlsafe-base64(nonce || ciphertext) -> decrypted bytes."""
            raw_bytes = base64.urlsafe_b64decode(
                encoded + "=" * (-len(encoded) % 4)
            )
            nonce, ciphertext = raw_bytes[:12], raw_bytes[12:]
            return decrypt(key, nonce, ciphertext)

        try:
            # cryptography raises InvalidTag on wrong password — let it bubble up
            ed_priv_bytes = _dec(data["ed25519_private"])
            x_priv_bytes = _dec(data["x25519_private"])
            display_name = _dec(data["display_name"]).decode()
        except KeyError as exc:
            raise ValueError(f"Corrupt account file: missing field {exc}") from exc

        ed_priv = ed25519_from_bytes(ed_priv_bytes)
        ed_pub = ed_priv.public_key().public_bytes_raw()

        x_priv = x25519_from_bytes(x_priv_bytes)
        x_pub = x_priv.public_key().public_bytes_raw()

        ygg_conf = ""
        if data.get("ygg_conf"):
            ygg_conf = _dec(data["ygg_conf"]).decode()

        return cls(
            ed25519_private=ed_priv,
            ed25519_public=ed_pub,
            x25519_private=x_priv,
            x25519_public=x_pub,
            display_name=display_name,
            account_dir=account_dir,
            created_at=data.get("created_at", int(time.time())),
            ygg_conf=ygg_conf,
        )
