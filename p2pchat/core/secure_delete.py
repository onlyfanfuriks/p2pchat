"""Secure file deletion: overwrite contents before unlinking.

Follows the principle from OWASP / NIST SP 800-88:
overwrite file contents with random data, flush to disk, truncate, then unlink.
This prevents trivial recovery from filesystem journal or undelete tools.

Note: on SSDs with wear-leveling / COW filesystems (btrfs, ZFS) a single
overwrite pass does NOT guarantee physical erasure. Full-disk encryption
(LUKS, FileVault) is the only reliable protection on modern hardware.
This module provides a best-effort defense-in-depth layer.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

_CHUNK = 64 * 1024  # 64 KiB write chunks


def secure_delete_file(path: Path) -> None:
    """Overwrite *path* with random bytes, truncate, then unlink.

    Silently skips files that don't exist or aren't regular files.
    Uses O_NOFOLLOW and fstat on the fd to avoid TOCTOU races.
    """
    path = Path(path)

    # Open with O_NOFOLLOW to refuse symlinks, then check via the fd.
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_NOFOLLOW)
    except OSError:
        # File doesn't exist, is a symlink, or can't be opened — skip.
        return

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return

        size = st.st_size

        # Overwrite in chunks to keep memory usage bounded.
        remaining = size
        while remaining > 0:
            chunk = min(_CHUNK, remaining)
            os.write(fd, os.urandom(chunk))
            remaining -= chunk
        os.fsync(fd)
        os.ftruncate(fd, 0)
        os.fsync(fd)
    finally:
        os.close(fd)

    path.unlink()


def secure_delete_dir(path: Path) -> None:
    """Recursively secure-delete all files in *path*, then remove the directory.

    Preserves subdirectory named ``bin`` (shared Yggdrasil binary).
    """
    path = Path(path)
    if not path.is_dir():
        return

    for item in sorted(path.iterdir()):
        if item.is_dir():
            if item.name == "bin":
                continue
            secure_delete_dir(item)
        else:
            secure_delete_file(item)

    # Only rmdir if empty (bin/ may still be there).
    if not any(path.iterdir()):
        path.rmdir()
