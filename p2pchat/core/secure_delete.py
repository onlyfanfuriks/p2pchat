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
from pathlib import Path

_CHUNK = 64 * 1024  # 64 KiB write chunks


def secure_delete_file(path: Path) -> None:
    """Overwrite *path* with random bytes, truncate, then unlink.

    Silently skips files that don't exist or aren't regular files.
    """
    path = Path(path)
    if not path.is_file():
        return

    size = path.stat().st_size

    # Overwrite in chunks to keep memory usage bounded.
    fd = os.open(str(path), os.O_WRONLY)
    try:
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
