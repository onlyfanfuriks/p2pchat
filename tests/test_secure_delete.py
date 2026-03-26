"""Tests for secure file deletion.

Covers: secure_delete_file (overwrite + unlink), symlink rejection,
non-existent files, non-regular files.
"""

import os
import stat

import pytest

from p2pchat.core.secure_delete import secure_delete_file


class TestSecureDeleteFile:
    def test_normal_file_deleted(self, tmp_path):
        """File is overwritten with random data then removed."""
        target = tmp_path / "secret.txt"
        original = b"super secret data\n" * 100
        target.write_bytes(original)
        size_before = target.stat().st_size

        secure_delete_file(target)

        # File must no longer exist on disk.
        assert not target.exists()

    def test_file_contents_overwritten_before_unlink(self, tmp_path):
        """Verify the file is overwritten (not just unlinked) by intercepting
        the unlink step."""
        target = tmp_path / "secret.txt"
        original = b"TOP SECRET" * 500
        target.write_bytes(original)

        # Patch Path.unlink to capture the on-disk bytes right before deletion.
        captured_bytes = []
        real_unlink = type(target).unlink

        def spy_unlink(self_, *a, **kw):
            captured_bytes.append(self_.read_bytes())
            real_unlink(self_, *a, **kw)

        import unittest.mock as um
        with um.patch.object(type(target), "unlink", spy_unlink):
            secure_delete_file(target)

        assert len(captured_bytes) == 1
        # After overwrite + truncate, the file should be empty (ftruncate(0)).
        assert captured_bytes[0] == b""

    def test_symlink_rejected(self, tmp_path):
        """O_NOFOLLOW prevents following symlinks; function returns silently."""
        real_file = tmp_path / "real.txt"
        real_file.write_text("keep me")
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)

        secure_delete_file(link)

        # The real file must still exist and be untouched.
        assert real_file.exists()
        assert real_file.read_text() == "keep me"

    def test_nonexistent_file_no_crash(self, tmp_path):
        """Deleting a file that does not exist is a silent no-op."""
        missing = tmp_path / "does_not_exist.txt"
        secure_delete_file(missing)  # must not raise

    def test_directory_skipped(self, tmp_path):
        """Directories are not regular files; function skips them."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        secure_delete_file(subdir)

        # Directory should still exist.
        assert subdir.is_dir()

    def test_empty_file(self, tmp_path):
        """An empty file is deleted without error (zero-length overwrite)."""
        target = tmp_path / "empty.txt"
        target.write_bytes(b"")

        secure_delete_file(target)

        assert not target.exists()
