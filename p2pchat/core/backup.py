"""Backup and restore for p2pchat account + message data.

Backup file format (binary):
    [4 bytes magic "P2PB"][1 byte version=0x01]
    [16 bytes PBKDF2 salt][12 bytes AES-GCM nonce]
    [N bytes AES-256-GCM ciphertext of gzipped tar archive]

The tar archive contains (if present):
    account.json   — already-encrypted account file
    messages.db    — SQLCipher-encrypted message database
    tls.crt        — TLS certificate
    tls.key        — TLS private key

Key derivation:
    PBKDF2-HMAC-SHA256(NFC(password), salt_16, iterations=600_000) → 32 bytes

WAL consistency:
    If a db_key is provided in the constructor, the backup opens a fresh
    connection to messages.db and runs PRAGMA wal_checkpoint(TRUNCATE) before
    archiving.  This ensures the main DB file is a consistent snapshot even
    when WAL mode is active.  Without db_key, the file is copied as-is (safe
    after Storage.close() has been called).

Blocking I/O note:
    export() and restore() perform CPU-bound PBKDF2 (~0.5 s) and file I/O.
    Wrap them in asyncio.to_thread() when calling from an async context
    (e.g. the Phase 4 TUI).

Output filename convention: p2pchat-backup-YYYYMMDD-HHMMSS.enc
"""

from __future__ import annotations

import io
import logging as _logging
import os
import tarfile
import tempfile
import unicodedata
import warnings
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_log = _logging.getLogger(__name__)

try:
    import sqlcipher3 as _sql  # type: ignore[import-untyped]

    _SQLCIPHER = True
except ImportError:
    _sql = None
    _SQLCIPHER = False

# -------------------------------------------------------------------------
# Format constants
# -------------------------------------------------------------------------
_MAGIC = b"P2PB"
_FORMAT_VERSION_1 = b"\x01"   # original; no AAD
_FORMAT_VERSION_2 = b"\x02"   # adds header bytes as AAD
_FORMAT_VERSION = _FORMAT_VERSION_2   # current default for new exports
_HEADER = _MAGIC + _FORMAT_VERSION    # 5 bytes — now ends with \x02
_SALT_LEN = 16
_NONCE_LEN = 12
_MIN_FILE_LEN = len(_HEADER) + _SALT_LEN + _NONCE_LEN + 17  # 17 = min AESGCM payload

_MAX_BACKUP_SIZE = 100 * 1024 * 1024  # 100 MB

_PBKDF2_ITERATIONS = 600_000

# Files included in the backup (relative to config_dir)
_BACKUP_NAMES = ("account.json", "messages.db", "tls.crt", "tls.key")


# -------------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 with NFC-normalised password."""
    normalised = unicodedata.normalize("NFC", password)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(normalised.encode("utf-8"))


def _write_secure(path: Path, data: bytes) -> None:
    """Write *data* to *path* with 0600 permissions from the first byte.

    Uses os.open to avoid the chmod-after-write race that shutil and
    Path.write_bytes() would create.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1  # fdopen() took ownership; prevent double-close
            f.write(data)
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)  # fdopen() failed before taking ownership
            except OSError:
                pass
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass
        raise


# -------------------------------------------------------------------------
# BackupManager
# -------------------------------------------------------------------------

class BackupManager:
    """Export and import encrypted backup archives.

    Parameters
    ----------
    config_dir:
        Path to ~/.config/p2pchat (or equivalent).  All backed-up files
        are read from / restored to this directory.
    db_key:
        Optional 32-byte SQLCipher key (from derive_db_key).  When given,
        the backup flushes the WAL to messages.db before archiving, ensuring
        a consistent snapshot.
    """

    def __init__(self, config_dir: Path, db_key: bytes | None = None) -> None:
        self._config_dir = config_dir
        self._db_key = db_key

    # -----------------------------------------------------------------------
    # Export
    # -----------------------------------------------------------------------

    def export(self, password: str, output_path: Path) -> None:
        """Create an encrypted backup archive at *output_path*.

        Raises
        ------
        FileNotFoundError
            If account.json does not exist (nothing to back up).
        ValueError
            If *output_path* already exists (prevents silent overwrite).
        """
        account_json = self._config_dir / "account.json"
        if not account_json.exists():
            raise FileNotFoundError(
                f"No account found at {account_json}; create one first."
            )
        if output_path.exists():
            raise ValueError(
                f"Output path already exists: {output_path}. "
                "Remove it or choose a different path."
            )

        self._checkpoint_wal()
        tar_bytes = self._build_tar()

        salt = os.urandom(_SALT_LEN)
        nonce = os.urandom(_NONCE_LEN)
        key = _derive_key(password, salt)
        aad = _MAGIC + _FORMAT_VERSION + salt + nonce
        ciphertext = AESGCM(key).encrypt(nonce, tar_bytes, aad)

        payload = _HEADER + salt + nonce + ciphertext

        # Atomic write: .tmp first, then rename so disk-full leaves no partial file
        tmp_fd, tmp_str = tempfile.mkstemp(dir=output_path.parent, suffix=".tmp")
        os.close(tmp_fd)
        tmp = Path(tmp_str)
        try:
            _write_secure(tmp, payload)
            tmp.replace(output_path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def _checkpoint_wal(self) -> None:
        """Flush WAL to messages.db so the backup gets a consistent snapshot."""
        db_path = self._config_dir / "messages.db"
        if not db_path.exists() or self._db_key is None or not _SQLCIPHER or _sql is None:
            return

        conn = _sql.connect(str(db_path), check_same_thread=False)

        # SEC: isolate PRAGMA key call so the hex key cannot appear in a
        # chained traceback if a subsequent operation raises.
        try:
            _key_pragma = f"PRAGMA key=\"x'{self._db_key.hex()}'\""
            conn.execute(_key_pragma)
            del _key_pragma
            conn.execute("PRAGMA foreign_keys=ON")
        except Exception:
            conn.close()
            return

        try:
            row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            # row = (busy, log, checkpointed); busy>0 means frames were not flushed.
            if row and row[0] != 0:
                warnings.warn(
                    "WAL checkpoint incomplete (DB busy); backup may be missing "
                    "recent writes. Close other connections before exporting.",
                    stacklevel=2,
                )
        except Exception as exc:
            _log.debug("WAL checkpoint failed: %s", exc)
            warnings.warn(
                "WAL checkpoint failed; backup may be inconsistent. "
                "See application logs for details.",
                stacklevel=2,
            )
        finally:
            conn.close()

    def _build_tar(self) -> bytes:
        """Build a gzipped tar archive of all backup files.

        Constructs each entry manually from raw bytes to avoid tar.add()'s
        default behaviour of following symlinks and including inode metadata
        (mtime, uid, gid) that could fingerprint the host machine.
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name in _BACKUP_NAMES:
                path = self._config_dir / name
                fd = -1
                try:
                    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, "rb") as f:
                        fd = -1  # fdopen took ownership
                        data = f.read()
                except FileNotFoundError:
                    continue
                except OSError:
                    if fd != -1:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    continue  # skip symlinks (ELOOP) and other errors
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    @staticmethod
    def default_output_path(directory: Path) -> Path:
        """Return a timestamped .enc path inside *directory*."""
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        return directory / f"p2pchat-backup-{ts}.enc"

    # -----------------------------------------------------------------------
    # Restore
    # -----------------------------------------------------------------------

    def restore(self, backup_path: Path, password: str) -> None:
        """Decrypt *backup_path* and restore files to config_dir.

        Raises
        ------
        FileNotFoundError
            If the backup file is missing.
        ValueError
            If the file is too short, has a wrong magic header, or an
            unsupported format version.
        cryptography.exceptions.InvalidTag
            If the password is wrong or the file is corrupted.
        """
        file_size = backup_path.stat().st_size
        if file_size > _MAX_BACKUP_SIZE:
            raise ValueError(
                f"Backup file too large ({file_size} bytes); "
                f"maximum supported size is {_MAX_BACKUP_SIZE} bytes."
            )
        raw = backup_path.read_bytes()

        if len(raw) < _MIN_FILE_LEN:
            raise ValueError(
                f"Backup file is too short ({len(raw)} bytes); not a valid backup."
            )
        if raw[:4] != _MAGIC:
            raise ValueError(
                "Not a p2pchat backup file (wrong magic bytes). "
                "Ensure you selected the correct file."
            )
        version = raw[4:5]
        if version not in (_FORMAT_VERSION_1, _FORMAT_VERSION_2):
            raise ValueError(
                f"Unsupported backup format version: {raw[4]}. "
                "This backup was created by a newer version of p2pchat."
            )

        salt = raw[len(_HEADER) : len(_HEADER) + _SALT_LEN]
        nonce = raw[len(_HEADER) + _SALT_LEN : len(_HEADER) + _SALT_LEN + _NONCE_LEN]
        ciphertext = raw[len(_HEADER) + _SALT_LEN + _NONCE_LEN :]

        if version == _FORMAT_VERSION_2:
            aad = _MAGIC + _FORMAT_VERSION_2 + salt + nonce
        else:
            aad = None

        key = _derive_key(password, salt)
        # Raises InvalidTag on wrong password or tampered data.
        tar_bytes = AESGCM(key).decrypt(nonce, ciphertext, aad)

        self._extract_tar(tar_bytes)

    def _extract_tar(self, tar_bytes: bytes) -> None:
        """Extract archive, staging all writes before committing to config_dir.

        All files are extracted to a staging temp directory on the same
        filesystem as config_dir, permissions are set to 0600, and then each
        file is atomically renamed (POSIX rename) into config_dir.  This
        ensures a partial failure (e.g. disk full) does not leave the account
        in a state where account.json is restored but messages.db is not.
        """
        self._config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._config_dir, 0o700)

        # Place the temp dir inside config_dir (already 0700) so that
        # src.replace(dst) is an atomic POSIX rename rather than a cross-device copy.
        with tempfile.TemporaryDirectory(dir=self._config_dir) as tmp:
            tmp_path = Path(tmp)
            buf = io.BytesIO(tar_bytes)
            with tarfile.open(fileobj=buf, mode="r:gz") as tar:
                # Whitelist + filter="data" together: whitelist prevents unwanted
                # names; filter="data" (Python 3.12+) strips UID/GID, symlinks,
                # and device files, and blocks path traversal like "../evil".
                members = [
                    m
                    for m in tar.getmembers()
                    if m.name in _BACKUP_NAMES and not os.path.isabs(m.name)
                ]
                tar.extractall(path=tmp_path, members=members, filter="data")

            # Enforce 0600 on every staged file before touching config_dir.
            staged = []
            for name in _BACKUP_NAMES:
                src = tmp_path / name
                if not src.exists():
                    continue
                os.chmod(src, 0o600)
                staged.append(name)

            # Save originals for best-effort rollback.
            originals: dict[str, bytes] = {}
            for name in staged:
                dst = self._config_dir / name
                if dst.exists():
                    originals[name] = dst.read_bytes()

            # Commit in dependency-safe order: TLS first, then DB, account.json last.
            # If a mid-commit failure occurs, the account key and DB key stay in sync.
            commit_order = [n for n in ("tls.crt", "tls.key", "messages.db", "account.json")
                            if n in staged]
            committed: list[str] = []
            try:
                for name in commit_order:
                    src = tmp_path / name
                    dst = self._config_dir / name
                    src.replace(dst)
                    committed.append(name)
            except Exception:
                for name in committed:
                    dst = self._config_dir / name
                    if name in originals:
                        try:
                            _write_secure(dst, originals[name])
                        except Exception:
                            pass
                    else:
                        try:
                            dst.unlink(missing_ok=True)
                        except Exception:
                            pass
                raise
