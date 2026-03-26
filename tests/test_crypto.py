"""Tests for p2pchat.core.crypto — all cryptographic primitives."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from p2pchat.core.crypto import (
    decode_public_key,
    decrypt,
    decrypt_message,
    derive_account_key,
    derive_session_key,
    display_fingerprint,
    encrypt,
    encode_public_key,
    encrypt_message,
    fingerprint,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    private_key_to_bytes,
    ed25519_from_bytes,
    x25519_from_bytes,
)


class TestKeypairGeneration:
    def test_ed25519_returns_32_byte_public_key(self):
        priv, pub = generate_ed25519_keypair()
        assert len(pub) == 32
        assert priv is not None

    def test_x25519_returns_32_byte_public_key(self):
        priv, pub = generate_x25519_keypair()
        assert len(pub) == 32
        assert priv is not None

    def test_ed25519_keys_are_unique(self):
        _, pub1 = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        assert pub1 != pub2

    def test_x25519_keys_are_unique(self):
        _, pub1 = generate_x25519_keypair()
        _, pub2 = generate_x25519_keypair()
        assert pub1 != pub2


class TestAccountKeyDerivation:
    def test_same_password_and_salt_gives_same_key(self):
        salt = os.urandom(32)
        key1 = derive_account_key("password123", salt)
        key2 = derive_account_key("password123", salt)
        assert key1 == key2
        assert len(key1) == 32

    def test_different_password_gives_different_key(self):
        salt = os.urandom(32)
        key1 = derive_account_key("password123", salt)
        key2 = derive_account_key("wrong_password", salt)
        assert key1 != key2

    def test_different_salt_gives_different_key(self):
        key1 = derive_account_key("password", os.urandom(32))
        key2 = derive_account_key("password", os.urandom(32))
        assert key1 != key2

    def test_nfc_precomposed_and_decomposed_produce_same_key(self):
        """'\u00e9' (precomposed) and 'e\u0301' (e + combining accent) must derive the same key."""
        salt = os.urandom(32)
        precomposed = "\u00e9"          # NFC form
        decomposed = "e\u0301"          # NFD form
        assert precomposed != decomposed  # sanity: distinct codepoint sequences
        key1 = derive_account_key(precomposed, salt)
        key2 = derive_account_key(decomposed, salt)
        assert key1 == key2

    def test_combining_characters_normalized_before_kdf(self):
        """Passwords with combining characters are NFC-normalized so the same
        visual string always produces the same derived key regardless of how
        the input was composed."""
        salt = os.urandom(32)
        # U+00F1 (n-tilde precomposed) vs U+006E U+0303 (n + combining tilde)
        precomposed = "se\u00f1or"
        decomposed = "sen\u0303or"
        assert precomposed != decomposed
        key1 = derive_account_key(precomposed, salt)
        key2 = derive_account_key(decomposed, salt)
        assert key1 == key2


class TestEncryptDecrypt:
    def test_round_trip(self):
        key = os.urandom(32)
        plaintext = b"Hello, World!"
        blob = encrypt(key, plaintext)
        assert len(blob.nonce) == 12
        result = decrypt(key, blob.nonce, blob.ciphertext)
        assert result == plaintext

    def test_wrong_key_raises(self):
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        blob = encrypt(key, b"secret data")
        with pytest.raises(InvalidTag):
            decrypt(wrong_key, blob.nonce, blob.ciphertext)

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        blob = encrypt(key, b"secret data")
        tampered = bytes([blob.ciphertext[0] ^ 0xFF]) + blob.ciphertext[1:]
        with pytest.raises(InvalidTag):
            decrypt(key, blob.nonce, tampered)

    def test_nonce_is_random_each_call(self):
        key = os.urandom(32)
        blob1 = encrypt(key, b"same plaintext")
        blob2 = encrypt(key, b"same plaintext")
        assert blob1.nonce != blob2.nonce
        assert blob1.ciphertext != blob2.ciphertext

    def test_encrypts_empty_bytes(self):
        key = os.urandom(32)
        blob = encrypt(key, b"")
        result = decrypt(key, blob.nonce, blob.ciphertext)
        assert result == b""


class TestSessionKeyDerivation:
    def test_both_peers_derive_same_key(self):
        """Core ECDH property: Alice and Bob must get the same session key."""
        alice_priv, _ = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()

        _, alice_id_pub = generate_ed25519_keypair()
        _, bob_id_pub = generate_ed25519_keypair()

        # Alice derives using her private + Bob's ephemeral public
        alice_key = derive_session_key(alice_priv, bob_pub, alice_id_pub, bob_id_pub)

        # Bob derives using his private + Alice's ephemeral public (extracted from alice_priv)
        from cryptography.hazmat.primitives import serialization
        alice_pub = alice_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        bob_key = derive_session_key(bob_priv, alice_pub, alice_id_pub, bob_id_pub)

        assert alice_key == bob_key
        assert len(alice_key) == 32

    def test_key_order_independence(self):
        """Swapping alice/bob identity pub args must still produce same key."""
        alice_priv, _ = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()

        _, alice_id_pub = generate_ed25519_keypair()
        _, bob_id_pub = generate_ed25519_keypair()

        from cryptography.hazmat.primitives import serialization
        alice_pub = alice_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        # Alice passes (alice_id, bob_id), Bob passes (bob_id, alice_id)
        alice_key = derive_session_key(alice_priv, bob_pub, alice_id_pub, bob_id_pub)
        bob_key = derive_session_key(bob_priv, alice_pub, bob_id_pub, alice_id_pub)

        assert alice_key == bob_key

    def test_different_sessions_give_different_keys(self):
        """Different ephemeral keys must produce different session keys."""
        alice_priv1, _ = generate_x25519_keypair()
        alice_priv2, _ = generate_x25519_keypair()
        _, bob_pub = generate_x25519_keypair()

        _, alice_id = generate_ed25519_keypair()
        _, bob_id = generate_ed25519_keypair()

        key1 = derive_session_key(alice_priv1, bob_pub, alice_id, bob_id)
        key2 = derive_session_key(alice_priv2, bob_pub, alice_id, bob_id)

        assert key1 != key2

    def test_self_chat_same_identity_keys(self):
        """Edge case: alice_id == bob_id (user messaging themselves).

        sorted([key, key]) == [key, key], so info = tag + key + key.
        This must be deterministic and not raise.
        """
        alice_priv, _ = generate_x25519_keypair()
        bob_priv, bob_pub = generate_x25519_keypair()

        _, shared_id_pub = generate_ed25519_keypair()

        from cryptography.hazmat.primitives import serialization
        alice_pub = alice_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        alice_key = derive_session_key(alice_priv, bob_pub, shared_id_pub, shared_id_pub)
        bob_key = derive_session_key(bob_priv, alice_pub, shared_id_pub, shared_id_pub)

        assert alice_key == bob_key
        assert len(alice_key) == 32


class TestMessageEncryptDecrypt:
    def test_round_trip(self):
        session_key = os.urandom(32)
        ed_priv, ed_pub = generate_ed25519_keypair()

        msg = "Hello, encrypted world! 🔐"
        encrypted = encrypt_message(session_key, msg, ed_priv)

        assert len(encrypted.nonce) == 12
        assert len(encrypted.signature) == 64
        assert encrypted.ciphertext != msg.encode()

        decrypted = decrypt_message(
            session_key, encrypted.nonce, encrypted.ciphertext,
            encrypted.signature, ed_pub
        )
        assert decrypted == msg

    def test_bad_signature_raises_value_error(self):
        session_key = os.urandom(32)
        ed_priv, _ = generate_ed25519_keypair()
        _, wrong_pub = generate_ed25519_keypair()

        encrypted = encrypt_message(session_key, "test", ed_priv)

        with pytest.raises(ValueError, match="signature"):
            decrypt_message(
                session_key, encrypted.nonce, encrypted.ciphertext,
                encrypted.signature, wrong_pub
            )

    def test_tampered_ciphertext_fails_signature(self):
        session_key = os.urandom(32)
        ed_priv, ed_pub = generate_ed25519_keypair()

        encrypted = encrypt_message(session_key, "test", ed_priv)
        tampered = bytes([encrypted.ciphertext[0] ^ 0xFF]) + encrypted.ciphertext[1:]

        with pytest.raises(ValueError, match="signature"):
            decrypt_message(
                session_key, encrypted.nonce, tampered,
                encrypted.signature, ed_pub
            )

    def test_empty_message(self):
        session_key = os.urandom(32)
        ed_priv, ed_pub = generate_ed25519_keypair()

        encrypted = encrypt_message(session_key, "", ed_priv)
        assert decrypt_message(
            session_key, encrypted.nonce, encrypted.ciphertext,
            encrypted.signature, ed_pub
        ) == ""

    def test_invalid_public_key_bytes_raises(self):
        session_key = os.urandom(32)
        ed_priv, _ = generate_ed25519_keypair()
        encrypted = encrypt_message(session_key, "test", ed_priv)

        with pytest.raises(Exception):  # ValueError from cryptography library
            decrypt_message(
                session_key, encrypted.nonce, encrypted.ciphertext,
                encrypted.signature, b"\x00" * 31  # wrong length
            )


class TestDisplayFingerprint:
    def test_format(self):
        _, pub = generate_ed25519_keypair()
        fp = display_fingerprint(pub)
        # 16 bytes → 32 hex chars + 15 colons = 47 total
        assert len(fp) == 47
        parts = fp.split(":")
        assert len(parts) == 16
        assert all(len(p) == 2 for p in parts)
        assert all(c in "0123456789ABCDEF" for p in parts for c in p)

    def test_deterministic(self):
        _, pub = generate_ed25519_keypair()
        assert display_fingerprint(pub) == display_fingerprint(pub)

    def test_different_keys_give_different_fingerprints(self):
        _, pub1 = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        assert display_fingerprint(pub1) != display_fingerprint(pub2)

    def test_alias_works(self):
        """fingerprint() is an alias for display_fingerprint()."""
        _, pub = generate_ed25519_keypair()
        assert fingerprint(pub) == display_fingerprint(pub)


class TestKeyEncoding:
    def test_encode_decode_round_trip(self):
        _, pub = generate_ed25519_keypair()
        encoded = encode_public_key(pub)
        decoded = decode_public_key(encoded)
        assert decoded == pub

    def test_encoded_is_url_safe(self):
        _, pub = generate_ed25519_keypair()
        encoded = encode_public_key(pub)
        assert "+" not in encoded
        assert "/" not in encoded
        assert "=" not in encoded

    def test_decode_accepts_padded_input(self):
        _, pub = generate_ed25519_keypair()
        unpadded = encode_public_key(pub)
        padding = -len(unpadded) % 4
        padded = unpadded + ("=" * padding)
        assert decode_public_key(padded) == pub

    def test_decode_invalid_length_raises(self):
        """Length % 4 == 1 is never valid base64."""
        with pytest.raises(ValueError, match="Invalid base64url"):
            decode_public_key("a")

        with pytest.raises(ValueError, match="Invalid base64url"):
            decode_public_key("abcda")

    def test_decode_empty_string(self):
        with pytest.raises(ValueError, match="32 bytes"):
            decode_public_key("")


class TestPrivateKeySerialization:
    def test_ed25519_round_trip(self):
        priv, pub = generate_ed25519_keypair()
        raw = private_key_to_bytes(priv)
        assert len(raw) == 32
        restored = ed25519_from_bytes(raw)
        restored_pub = restored.public_key().public_bytes_raw()
        assert restored_pub == pub

    def test_x25519_round_trip(self):
        priv, pub = generate_x25519_keypair()
        raw = private_key_to_bytes(priv)
        assert len(raw) == 32
        restored = x25519_from_bytes(raw)
        restored_pub = restored.public_key().public_bytes_raw()
        assert restored_pub == pub
