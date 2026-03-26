"""Tests for p2pchat.core.account — account creation, save, load."""

import json
import time
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag

import p2pchat.core.account as acc_module
from p2pchat.core.account import Account
from p2pchat.core.crypto import generate_ed25519_keypair, generate_x25519_keypair, derive_session_key


@pytest.fixture
def tmp_account(tmp_path):
    """Redirect account storage to a temp directory for each test."""
    accounts_dir = tmp_path / "accounts"
    accounts_dir.mkdir()
    tmp_file = tmp_path / "account.json"
    with (
        patch.object(acc_module, "ACCOUNT_DIR", tmp_path),
        patch.object(acc_module, "ACCOUNTS_DIR", accounts_dir),
        patch.object(acc_module, "ACCOUNT_FILE", tmp_file),
    ):
        yield tmp_path


def _account_file(account: Account):
    """Return the account.json path for a created/loaded account."""
    return account.account_dir / acc_module._ACCOUNT_FILENAME


class TestAccountExists:
    def test_no_account_initially(self, tmp_account):
        assert not Account.exists()

    def test_exists_after_create(self, tmp_account):
        Account.create("pw", "Alice")
        assert Account.exists()


class TestAccountCreate:
    def test_creates_account_file(self, tmp_account):
        account = Account.create("password", "Alice")
        assert _account_file(account).exists()

    def test_display_name_accessible(self, tmp_account):
        account = Account.create("pw", "Bob")
        assert account.display_name == "Bob"

    def test_keypairs_are_32_bytes(self, tmp_account):
        account = Account.create("pw", "Alice")
        assert len(account.ed25519_public) == 32
        assert len(account.x25519_public) == 32

    def test_user_id_is_nonempty_string(self, tmp_account):
        account = Account.create("pw", "Alice")
        assert isinstance(account.user_id, str)
        assert len(account.user_id) > 0

    def test_file_permissions_are_0600(self, tmp_account):
        account = Account.create("pw", "Alice")
        file_mode = _account_file(account).stat().st_mode
        assert oct(file_mode & 0o777) == oct(0o600)

    def test_account_json_has_expected_fields(self, tmp_account):
        account = Account.create("pw", "Alice")
        data = json.loads(_account_file(account).read_text())
        assert data["version"] == 1
        assert "ed25519_private" in data
        assert "x25519_private" in data
        assert "display_name" in data
        assert "salt" in data
        assert "created_at" in data

    def test_display_name_plaintext_in_envelope(self, tmp_account):
        """display_name_plain is stored in plaintext for account listing."""
        account = Account.create("pw", "Alice")
        data = json.loads(_account_file(account).read_text())
        assert data["display_name_plain"] == "Alice"

    def test_display_name_encrypted_field(self, tmp_account):
        """The encrypted display_name field must not contain plaintext."""
        account = Account.create("pw", "Alice")
        data = json.loads(_account_file(account).read_text())
        # The encrypted field is a long base64 blob, not the literal name.
        assert data["display_name"] != "Alice"
        assert len(data["display_name"]) > 10

    def test_private_keys_not_in_plaintext(self, tmp_account):
        account = Account.create("pw", "Alice")
        data = json.loads(_account_file(account).read_text())
        # Encrypted blobs are much longer than 32-byte raw keys
        assert isinstance(data["ed25519_private"], str)
        assert len(data["ed25519_private"]) > 40

    def test_created_at_is_set(self, tmp_account):
        before = int(time.time())
        account = Account.create("pw", "Alice")
        after = int(time.time())
        assert before <= account.created_at <= after

    def test_account_dir_is_under_accounts(self, tmp_account):
        account = Account.create("pw", "Alice")
        assert account.account_dir.parent == acc_module.ACCOUNTS_DIR


class TestAccountLoad:
    def test_round_trip_identity(self, tmp_account):
        original = Account.create("correct_password", "Alice")
        loaded = Account.load("correct_password", original.account_dir)

        assert loaded.user_id == original.user_id
        assert loaded.display_name == "Alice"
        assert loaded.ed25519_public == original.ed25519_public
        assert loaded.x25519_public == original.x25519_public

    def test_wrong_password_raises_invalid_tag(self, tmp_account):
        original = Account.create("correct_password", "Alice")
        with pytest.raises(InvalidTag):
            Account.load("wrong_password", original.account_dir)

    def test_no_account_raises_file_not_found(self, tmp_account):
        missing_dir = tmp_account / "accounts" / "nonexistent"
        missing_dir.mkdir(parents=True, exist_ok=True)
        with pytest.raises(FileNotFoundError):
            Account.load("any_password", missing_dir)

    def test_version_mismatch_raises_value_error(self, tmp_account):
        original = Account.create("pw", "Alice")
        acct_file = _account_file(original)
        data = json.loads(acct_file.read_text())
        data["version"] = 99
        acct_file.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="Unsupported account version"):
            Account.load("pw", original.account_dir)

    def test_corrupt_json_raises_value_error(self, tmp_account):
        acct_dir = tmp_account / "accounts" / "corrupt"
        acct_dir.mkdir(parents=True)
        (acct_dir / acc_module._ACCOUNT_FILENAME).write_text("not valid json", encoding="utf-8")
        with pytest.raises(ValueError, match="corrupt"):
            Account.load("pw", acct_dir)

    def test_loaded_keypairs_are_functional(self, tmp_account):
        """Loaded private keys must be able to sign and perform ECDH."""
        original = Account.create("pw", "Alice")
        loaded = Account.load("pw", original.account_dir)

        # Ed25519: sign and verify
        msg = b"test payload"
        sig = loaded.ed25519_private.sign(msg)
        loaded.ed25519_private.public_key().verify(sig, msg)  # no exception = pass

        # X25519: derive a session key using correct key types
        _, other_x25519_pub = generate_x25519_keypair()
        _, other_ed25519_pub = generate_ed25519_keypair()

        session_key = derive_session_key(
            loaded.x25519_private,
            other_x25519_pub,
            loaded.ed25519_public,   # identity key (Ed25519)
            other_ed25519_pub,       # identity key (Ed25519)
        )
        assert len(session_key) == 32

    def test_ygg_conf_round_trip(self, tmp_account):
        original = Account.create("pw", "Alice")
        original.ygg_conf = "PublicKey: abc\nPrivateKey: xyz\n"
        original.save("pw")

        loaded = Account.load("pw", original.account_dir)
        assert loaded.ygg_conf == "PublicKey: abc\nPrivateKey: xyz\n"

    def test_empty_ygg_conf_round_trip(self, tmp_account):
        original = Account.create("pw", "Alice")
        loaded = Account.load("pw", original.account_dir)
        assert loaded.ygg_conf == ""

    def test_ygg_conf_encrypted_at_rest(self, tmp_account):
        account = Account.create("pw", "Alice")
        account.ygg_conf = "PrivateKey: supersecret"
        account.save("pw")

        raw = _account_file(account).read_text()
        assert "supersecret" not in raw
        assert "PrivateKey" not in raw

    def test_created_at_preserved_across_saves(self, tmp_account):
        account = Account.create("pw", "Alice")
        original_ts = account.created_at

        account.display_name = "Alice v2"
        account.save("pw")

        loaded = Account.load("pw", account.account_dir)
        assert loaded.created_at == original_ts


class TestAccountTamperedFile:
    """Loading an account file that has been tampered with or truncated."""

    def test_tampered_salt_raises(self, tmp_account):
        """Changing the salt produces a different derived key, so decryption
        must fail with InvalidTag (GCM authentication failure)."""
        original = Account.create("pw", "Alice")
        acct_file = _account_file(original)
        data = json.loads(acct_file.read_text())

        import base64
        real_salt = base64.urlsafe_b64decode(data["salt"] + "=" * (-len(data["salt"]) % 4))
        fake_salt = bytes([b ^ 0xFF for b in real_salt])
        data["salt"] = base64.urlsafe_b64encode(fake_salt).decode().rstrip("=")
        acct_file.write_text(json.dumps(data))

        with pytest.raises(InvalidTag):
            Account.load("pw", original.account_dir)

    def test_tampered_ciphertext_raises(self, tmp_account):
        """Flipping a byte in the encrypted private key blob must fail
        GCM authentication (InvalidTag)."""
        original = Account.create("pw", "Alice")
        acct_file = _account_file(original)
        data = json.loads(acct_file.read_text())

        import base64
        raw = base64.urlsafe_b64decode(data["ed25519_private"] + "=" * (-len(data["ed25519_private"]) % 4))
        tampered = raw[:12] + bytes([raw[12] ^ 0xFF]) + raw[13:]
        data["ed25519_private"] = base64.urlsafe_b64encode(tampered).decode().rstrip("=")
        acct_file.write_text(json.dumps(data))

        with pytest.raises(InvalidTag):
            Account.load("pw", original.account_dir)

    def test_truncated_file_raises_value_error(self, tmp_account):
        """A file truncated mid-JSON must be handled gracefully as ValueError."""
        acct_dir = tmp_account / "accounts" / "truncated"
        acct_dir.mkdir(parents=True)
        (acct_dir / acc_module._ACCOUNT_FILENAME).write_text('{"version": 1, "salt":', encoding="utf-8")

        with pytest.raises(ValueError, match="corrupt"):
            Account.load("pw", acct_dir)

    def test_missing_encrypted_field_raises_value_error(self, tmp_account):
        """An account file with a missing encrypted field must raise ValueError."""
        original = Account.create("pw", "Alice")
        acct_file = _account_file(original)
        data = json.loads(acct_file.read_text())

        del data["ed25519_private"]
        acct_file.write_text(json.dumps(data))

        with pytest.raises((ValueError, InvalidTag)):
            Account.load("pw", original.account_dir)

    def test_empty_file_raises_value_error(self, tmp_account):
        """A completely empty file must raise ValueError (invalid JSON)."""
        acct_dir = tmp_account / "accounts" / "empty"
        acct_dir.mkdir(parents=True)
        (acct_dir / acc_module._ACCOUNT_FILENAME).write_text("", encoding="utf-8")

        with pytest.raises(ValueError, match="corrupt"):
            Account.load("pw", acct_dir)


class TestAccountSave:
    def test_save_updates_content(self, tmp_account):
        account = Account.create("pw", "Alice")
        account.display_name = "Alice Updated"
        account.save("pw")

        loaded = Account.load("pw", account.account_dir)
        assert loaded.display_name == "Alice Updated"

    def test_save_uses_fresh_salt_each_time(self, tmp_account):
        account = Account.create("pw", "Alice")
        acct_file = _account_file(account)
        data1 = json.loads(acct_file.read_text())
        account.save("pw")
        data2 = json.loads(acct_file.read_text())
        assert data1["salt"] != data2["salt"]

    def test_save_is_atomic_tmp_file_cleaned_up(self, tmp_account):
        """The .tmp file must not be left behind after a successful save."""
        account = Account.create("pw", "Alice")
        tmp_file = _account_file(account).with_suffix(".tmp")
        assert not tmp_file.exists()


class TestAccountEquality:
    def test_equal_after_round_trip(self, tmp_account):
        original = Account.create("pw", "Alice")
        loaded = Account.load("pw", original.account_dir)
        assert original == loaded

    def test_different_accounts_not_equal(self, tmp_account):
        acc1 = Account.create("pw", "Alice")
        acc2 = Account.create("pw", "Bob")
        assert acc1 != acc2

    def test_not_equal_to_non_account(self, tmp_account):
        account = Account.create("pw", "Alice")
        assert account != "not an account"
        assert account != 42


class TestAccountRepr:
    def test_repr_contains_user_id_and_display_name(self, tmp_account):
        account = Account.create("pw", "Alice")
        r = repr(account)
        assert "user_id" in r
        assert "Alice" in r

    def test_repr_does_not_contain_private_key(self, tmp_account):
        account = Account.create("pw", "Alice")
        r = repr(account)
        assert "ed25519_private" not in r
        assert "x25519_private" not in r


class TestMigrateLegacyAccount:
    """Tests for migrate_legacy_account — moving old single-account layout."""

    def test_successful_migration_moves_files(self, tmp_account):
        """A legacy account.json (+ siblings) should be moved into accounts/<name>/."""
        from p2pchat.core.account import migrate_legacy_account

        # Create a real account in the old flat layout.
        account = Account.create("pw", "Alice")
        acct_file = _account_file(account)
        data = json.loads(acct_file.read_text())

        # Simulate the legacy layout: move account.json to the top-level dir.
        legacy_file = tmp_account / "account.json"
        legacy_file.write_text(json.dumps(data), encoding="utf-8")
        # Add a sibling file that should also be migrated.
        (tmp_account / "messages.db").write_bytes(b"fake-db")

        # Remove the new-layout directory contents so migration is triggered.
        import shutil
        shutil.rmtree(acc_module.ACCOUNTS_DIR)
        acc_module.ACCOUNTS_DIR.mkdir()

        migrate_legacy_account()

        # The legacy file should no longer exist at the old location.
        assert not legacy_file.exists()
        assert not (tmp_account / "messages.db").exists()

        # Files should now be under accounts/<name>/.
        dest = acc_module.ACCOUNTS_DIR / "Alice"
        assert (dest / "account.json").exists()
        assert (dest / "messages.db").exists()

    def test_noop_when_no_legacy_account(self, tmp_account):
        """When no legacy account.json exists, migration does nothing."""
        from p2pchat.core.account import migrate_legacy_account

        legacy_file = tmp_account / "account.json"
        assert not legacy_file.exists()

        migrate_legacy_account()

        # accounts dir should still be empty (no crash, no new dirs).
        assert list(acc_module.ACCOUNTS_DIR.iterdir()) == []

    def test_noop_when_already_migrated(self, tmp_account):
        """If accounts/ already has content, migration is skipped even if legacy file exists."""
        from p2pchat.core.account import migrate_legacy_account

        # Create a proper account under accounts/ first.
        Account.create("pw", "Bob")

        # Also create a legacy file (should be ignored).
        legacy_file = tmp_account / "account.json"
        legacy_file.write_text('{"display_name_plain": "Old"}', encoding="utf-8")

        migrate_legacy_account()

        # Legacy file should still be there (not consumed) since migration was skipped.
        assert legacy_file.exists()

    def test_corrupted_legacy_file_uses_default_name(self, tmp_account):
        """If legacy account.json is corrupt, migration uses 'default' as dir name."""
        from p2pchat.core.account import migrate_legacy_account

        legacy_file = tmp_account / "account.json"
        legacy_file.write_text("not valid json at all{{{", encoding="utf-8")

        # Also add a sibling to verify it gets moved.
        (tmp_account / "messages.db").write_bytes(b"fake-db")

        # Clear accounts dir so migration runs.
        import shutil
        shutil.rmtree(acc_module.ACCOUNTS_DIR)
        acc_module.ACCOUNTS_DIR.mkdir()

        migrate_legacy_account()

        # Should have used "default" as the directory name.
        dest = acc_module.ACCOUNTS_DIR / "default"
        assert dest.is_dir()
        assert (dest / "account.json").exists()
        assert (dest / "messages.db").exists()
        # Original locations should be gone.
        assert not legacy_file.exists()
        assert not (tmp_account / "messages.db").exists()


class TestListAccounts:
    def test_empty_initially(self, tmp_account):
        from p2pchat.core.account import list_accounts
        assert list_accounts() == []

    def test_lists_created_accounts(self, tmp_account):
        from p2pchat.core.account import list_accounts
        Account.create("pw", "Alice")
        Account.create("pw", "Bob")
        accounts = list_accounts()
        names = {a.display_name for a in accounts}
        assert names == {"Alice", "Bob"}

    def test_account_dir_collision_avoidance(self, tmp_account):
        a1 = Account.create("pw", "Alice")
        a2 = Account.create("pw", "Alice")
        assert a1.account_dir != a2.account_dir
        assert a1.account_dir.exists()
        assert a2.account_dir.exists()
