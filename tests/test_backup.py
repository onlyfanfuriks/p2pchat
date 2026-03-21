"""Tests for p2pchat.core.backup — export / restore encrypted archives."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from p2pchat.core.backup import (
    BackupManager,
    _HEADER,
    _MAGIC,
    _FORMAT_VERSION,
    _FORMAT_VERSION_1,
    _MIN_FILE_LEN,
    _NONCE_LEN,
    _SALT_LEN,
    _derive_key,
)
from p2pchat.core.crypto import generate_ed25519_keypair
from p2pchat.core.storage import Contact, Message, Storage, derive_db_key


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config_dir(tmp_path):
    """Fake ~/.config/p2pchat with all backed-up files present."""
    d = tmp_path / "config"
    d.mkdir()
    (d / "account.json").write_bytes(b'{"version": 1, "fake": "encrypted"}')
    (d / "messages.db").write_bytes(b"\x00SQLite\x00" + b"x" * 512)
    (d / "tls.crt").write_bytes(b"-----BEGIN CERTIFICATE-----\nfakecert\n")
    (d / "tls.key").write_bytes(b"-----BEGIN PRIVATE KEY-----\nfakekey\n")
    return d


@pytest.fixture
def restore_dir(tmp_path):
    d = tmp_path / "restore"
    d.mkdir()
    return d


@pytest.fixture
async def real_config_dir(tmp_path):
    """Config dir backed by a real SQLCipher Storage with data in it."""
    d = tmp_path / "real_config"
    d.mkdir()

    priv, _ = generate_ed25519_keypair()
    db_key = derive_db_key(priv)

    # Real encrypted messages.db
    st = Storage(d / "messages.db", db_key)
    await st.initialize()
    await st.upsert_contact(
        Contact(
            peer_id="peer1",
            display_name="Alice",
            x25519_pub="AAAA",
            trusted=True,
            added_at=1_000_000,
        )
    )
    await st.save_message(
        Message(
            peer_id="peer1",
            direction="sent",
            content="hello from backup test",
            timestamp=1_000_000_000,
        )
    )
    await st.close()

    # Fake account.json
    (d / "account.json").write_bytes(b'{"version":1,"fake":"data"}')

    return d, db_key


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestExport:
    def test_creates_output_file(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("secret", out)
        assert out.exists()

    def test_output_has_correct_magic_header(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        raw = out.read_bytes()
        assert raw[:4] == _MAGIC
        assert raw[4:5] == _FORMAT_VERSION

    def test_output_minimum_length(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        assert len(out.read_bytes()) >= _MIN_FILE_LEN

    def test_output_permissions_are_0600(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        assert oct(out.stat().st_mode & 0o777) == oct(0o600)

    def test_salt_is_random_each_call(self, config_dir, tmp_path):
        out1, out2 = tmp_path / "b1.enc", tmp_path / "b2.enc"
        BackupManager(config_dir).export("pw", out1)
        BackupManager(config_dir).export("pw", out2)
        offset = len(_HEADER)
        assert out1.read_bytes()[offset : offset + _SALT_LEN] != \
               out2.read_bytes()[offset : offset + _SALT_LEN]

    def test_raises_if_no_account_json(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(FileNotFoundError):
            BackupManager(empty).export("pw", tmp_path / "out.enc")

    def test_raises_if_output_already_exists(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        out.write_bytes(b"existing backup - must not be silently overwritten")
        with pytest.raises(ValueError, match="already exists"):
            BackupManager(config_dir).export("pw", out)

    def test_optional_tls_files_included_when_present(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        restore = tmp_path / "restore"
        restore.mkdir()
        BackupManager(restore).restore(out, "pw")
        assert (restore / "tls.crt").exists()
        assert (restore / "tls.key").exists()

    def test_optional_files_skipped_when_absent(self, tmp_path):
        cfg = tmp_path / "cfg"
        cfg.mkdir()
        (cfg / "account.json").write_bytes(b'{"v":1}')
        out = tmp_path / "backup.enc"
        BackupManager(cfg).export("pw", out)
        assert out.exists()

    def test_no_partial_file_on_disk_full_simulation(self, config_dir, tmp_path, monkeypatch):
        """Atomic write: a crash in _write_secure must not leave a valid .enc file."""
        import os as _os

        out = tmp_path / "backup.enc"

        def fail_fdopen(fd, *a, **kw):
            raise OSError("simulated disk full")

        monkeypatch.setattr(_os, "fdopen", fail_fdopen)
        with pytest.raises(OSError, match="simulated disk full"):
            BackupManager(config_dir).export("pw", out)

        assert not out.exists()
        assert not any(tmp_path.glob("*.tmp"))


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


class TestRestore:
    def test_round_trip_fake_db(self, config_dir, restore_dir):
        out = restore_dir.parent / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        BackupManager(restore_dir).restore(out, "pw")
        assert (restore_dir / "account.json").exists()
        assert (restore_dir / "messages.db").exists()

    def test_restored_content_matches_original(self, config_dir, restore_dir):
        original = (config_dir / "account.json").read_bytes()
        out = restore_dir.parent / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        BackupManager(restore_dir).restore(out, "pw")
        assert (restore_dir / "account.json").read_bytes() == original

    def test_restored_files_have_0600_permissions(self, config_dir, restore_dir):
        out = restore_dir.parent / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        BackupManager(restore_dir).restore(out, "pw")
        for name in ("account.json", "messages.db"):
            assert oct((restore_dir / name).stat().st_mode & 0o777) == oct(0o600)

    def test_wrong_password_raises_invalid_tag(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("correct_password", out)
        with pytest.raises(InvalidTag):
            BackupManager(tmp_path / "restore").restore(out, "wrong_password")

    def test_tampered_ciphertext_raises_invalid_tag(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        raw = bytearray(out.read_bytes())
        raw[-1] ^= 0xFF
        out.write_bytes(bytes(raw))
        with pytest.raises(InvalidTag):
            BackupManager(tmp_path / "restore").restore(out, "pw")

    def test_too_short_raises_value_error(self, tmp_path):
        bad = tmp_path / "bad.enc"
        bad.write_bytes(b"\x00" * 10)
        with pytest.raises(ValueError, match="too short"):
            BackupManager(tmp_path / "restore").restore(bad, "pw")

    def test_too_large_raises_value_error(self, tmp_path):
        """A backup file exceeding _MAX_BACKUP_SIZE must raise ValueError before decryption."""
        from p2pchat.core.backup import _MAX_BACKUP_SIZE
        big = tmp_path / "big.enc"
        big.write_bytes(b"\x00" * (_MAX_BACKUP_SIZE + 1))
        with pytest.raises(ValueError, match="too large"):
            BackupManager(tmp_path / "restore").restore(big, "pw")

    def test_wrong_magic_raises_value_error(self, tmp_path):
        bad = tmp_path / "bad.enc"
        bad.write_bytes(b"XXXX\x01" + b"\x00" * (_SALT_LEN + _NONCE_LEN + 20))
        with pytest.raises(ValueError, match="magic"):
            BackupManager(tmp_path / "restore").restore(bad, "pw")

    def test_unsupported_version_raises_value_error(self, tmp_path):
        bad = tmp_path / "bad.enc"
        bad.write_bytes(_MAGIC + b"\xFF" + b"\x00" * (_SALT_LEN + _NONCE_LEN + 20))
        with pytest.raises(ValueError, match="version"):
            BackupManager(tmp_path / "restore").restore(bad, "pw")

    def test_creates_config_dir_if_absent(self, config_dir, tmp_path):
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        restore = tmp_path / "brand_new_config"
        BackupManager(restore).restore(out, "pw")
        assert (restore / "account.json").exists()

    def test_restore_overwrites_existing_files(self, config_dir, tmp_path):
        """Restore must replace files that already exist in the target dir."""
        out = tmp_path / "backup.enc"
        BackupManager(config_dir).export("pw", out)
        restore = tmp_path / "restore"
        restore.mkdir()
        (restore / "account.json").write_bytes(b"old stale data")
        BackupManager(restore).restore(out, "pw")
        assert (restore / "account.json").read_bytes() != b"old stale data"

    def test_path_traversal_in_tar_is_rejected(self, config_dir, tmp_path):
        """A maliciously crafted tar with '../evil' must not escape the restore dir."""
        import io
        import tarfile as tf

        # Build a tar with a path-traversal entry
        buf = io.BytesIO()
        with tf.open(fileobj=buf, mode="w:gz") as tar:
            data = b"malicious content"
            info = tf.TarInfo(name="../evil.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar_bytes = buf.getvalue()

        # Manually build a fake backup using v1 format (no AAD)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        salt = os.urandom(_SALT_LEN)
        nonce = os.urandom(_NONCE_LEN)
        key = _derive_key("pw", salt)
        ct = AESGCM(key).encrypt(nonce, tar_bytes, None)
        evil_backup = tmp_path / "evil.enc"
        evil_backup.write_bytes(_MAGIC + _FORMAT_VERSION_1 + salt + nonce + ct)

        restore = tmp_path / "restore"
        restore.mkdir()
        BackupManager(restore).restore(evil_backup, "pw")
        assert not (tmp_path / "evil.txt").exists()


# ---------------------------------------------------------------------------
# WAL checkpoint warnings
# ---------------------------------------------------------------------------


class TestCheckpointWal:
    async def test_wrong_key_emits_warning(self, tmp_path):
        """_checkpoint_wal with wrong db_key must emit a UserWarning."""
        from p2pchat.core.storage import Storage, derive_db_key
        from p2pchat.core.crypto import generate_ed25519_keypair

        d = tmp_path / "config"
        d.mkdir()

        priv, _ = generate_ed25519_keypair()
        db_key = derive_db_key(priv)

        st = Storage(d / "messages.db", db_key)
        await st.initialize()
        await st.close()

        (d / "account.json").write_bytes(b'{"v":1}')

        wrong_key = os.urandom(32)
        out = tmp_path / "backup.enc"
        bm = BackupManager(d, db_key=wrong_key)

        with pytest.warns(UserWarning, match="checkpoint failed"):
            bm.export("pw", out)


# ---------------------------------------------------------------------------
# Round-trip with real SQLCipher storage
# ---------------------------------------------------------------------------


class TestRealStorageRoundTrip:
    async def test_backup_and_restore_preserves_data(self, real_config_dir, tmp_path):
        """Full round-trip: real SQLCipher DB → export → restore → re-open."""
        config, db_key = real_config_dir
        out = tmp_path / "backup.enc"
        BackupManager(config, db_key=db_key).export("pw", out)

        restore = tmp_path / "restore"
        restore.mkdir()
        BackupManager(restore, db_key=db_key).restore(out, "pw")

        assert (restore / "account.json").exists()
        assert (restore / "messages.db").exists()

        st = Storage(restore / "messages.db", db_key)
        await st.initialize()
        contacts = await st.list_contacts()
        msgs = await st.get_messages("peer1")
        await st.close()

        assert len(contacts) == 1
        assert contacts[0].display_name == "Alice"
        assert len(msgs) == 1
        assert msgs[0].content == "hello from backup test"


# ---------------------------------------------------------------------------
# Default output path
# ---------------------------------------------------------------------------


class TestDefaultOutputPath:
    def test_filename_has_expected_pattern(self, tmp_path):
        path = BackupManager.default_output_path(tmp_path)
        assert path.suffix == ".enc"
        assert "p2pchat-backup-" in path.name

    def test_path_is_inside_given_directory(self, tmp_path):
        assert BackupManager.default_output_path(tmp_path).parent == tmp_path


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


class TestKeyDerivation:
    def test_same_inputs_give_same_key(self):
        salt = os.urandom(_SALT_LEN)
        assert _derive_key("pw", salt) == _derive_key("pw", salt)
        assert len(_derive_key("pw", salt)) == 32

    def test_different_password_gives_different_key(self):
        salt = os.urandom(_SALT_LEN)
        assert _derive_key("pw1", salt) != _derive_key("pw2", salt)

    def test_different_salt_gives_different_key(self):
        assert _derive_key("pw", os.urandom(16)) != _derive_key("pw", os.urandom(16))

    def test_unicode_password_nfc_normalised(self):
        """NFC and NFD forms of the same string must produce the same key."""
        import unicodedata
        # é can be NFC (U+00E9) or NFD (e + U+0301)
        nfc = unicodedata.normalize("NFC", "\u00e9")
        nfd = unicodedata.normalize("NFD", "\u00e9")
        assert nfc != nfd  # confirm they differ as raw strings
        salt = os.urandom(_SALT_LEN)
        assert _derive_key(nfc, salt) == _derive_key(nfd, salt)


# ---------------------------------------------------------------------------
# Account key NFC normalization
# ---------------------------------------------------------------------------


class TestAccountKeyNfc:
    def test_derive_account_key_nfc_normalised(self):
        """derive_account_key must produce the same key for NFC and NFD input."""
        import unicodedata
        from p2pchat.core.crypto import derive_account_key
        nfc = unicodedata.normalize("NFC", "\u00e9")
        nfd = unicodedata.normalize("NFD", "\u00e9")
        assert nfc != nfd
        salt = os.urandom(16)
        assert derive_account_key(nfc, salt) == derive_account_key(nfd, salt)
