"""Cryptographic primitives for p2pchat.

Uses the `cryptography` library exclusively. No pycryptodome, no nacl.
"""

import base64
import hashlib
import os
import unicodedata
from typing import NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000

# Static application tag used as HKDF info — binds derived keys to this protocol.
_HKDF_SESSION_INFO = b"p2pchat-v1-session-key"


class EncryptedBlob(NamedTuple):
    """Result of AES-256-GCM encryption (nonce stored separately)."""

    nonce: bytes       # 12 bytes
    ciphertext: bytes  # includes GCM auth tag


class EncryptedMessage(NamedTuple):
    """Encrypted + signed chat message payload."""

    nonce: bytes      # 12 bytes
    ciphertext: bytes # AES-GCM ciphertext
    signature: bytes  # Ed25519 over (nonce + ciphertext), 64 bytes


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate Ed25519 keypair. Returns (private_key, raw_public_key_bytes)."""
    private = Ed25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public_bytes


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Generate X25519 keypair. Returns (private_key, raw_public_key_bytes)."""
    private = X25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public_bytes


def derive_account_key(password: str, salt: bytes) -> bytes:
    """Derive 32-byte encryption key from password via PBKDF2-HMAC-SHA256.

    Uses 600,000 iterations (OWASP 2024 recommendation).
    The password is NFC-normalised before encoding to ensure consistent
    key derivation across platforms and input methods.
    """
    normalised = unicodedata.normalize("NFC", password)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(normalised.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes) -> EncryptedBlob:
    """Encrypt bytes with AES-256-GCM. Generates random 12-byte nonce."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return EncryptedBlob(nonce, ciphertext)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext. Raises InvalidTag on auth failure."""
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def derive_session_key(
    my_ephemeral_private: X25519PrivateKey,
    their_ephemeral_public_bytes: bytes,
    alice_id_pub: bytes,
    bob_id_pub: bytes,
    info_tag: bytes | None = None,
) -> bytes:
    """Derive shared 32-byte session key via X25519 ECDH + HKDF-SHA256.

    HKDF usage (RFC 5869):
    - salt:  sorted(my_ephemeral_pub, their_ephemeral_pub) — random per session,
             ideal entropy source for the Extract step.
    - info:  app tag + sorted(alice_id_pub, bob_id_pub) — binds the derived key
             to this protocol and these two specific peers.

    Both peers arrive at the same salt and info by sorting, so they derive the
    same session key without needing to agree on ordering out-of-band.

    alice_id_pub / bob_id_pub are the long-term Ed25519 identity public keys.

    info_tag: optional domain-separation tag. Defaults to _HKDF_SESSION_INFO.
              Use a distinct tag for non-session key derivations (e.g. outbox).
    """
    their_pub = X25519PublicKey.from_public_bytes(their_ephemeral_public_bytes)
    shared_secret = my_ephemeral_private.exchange(their_pub)

    my_ephemeral_pub = my_ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    # Salt: sorted ephemeral public keys — random, public, unique per session
    sorted_eph = sorted([my_ephemeral_pub, their_ephemeral_public_bytes])
    salt = sorted_eph[0] + sorted_eph[1]

    # Info: protocol tag + sorted long-term identity keys
    sorted_ids = sorted([alice_id_pub, bob_id_pub])
    info = (info_tag or _HKDF_SESSION_INFO) + sorted_ids[0] + sorted_ids[1]

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def encrypt_message(
    session_key: bytes,
    plaintext: str,
    ed25519_private: Ed25519PrivateKey,
) -> EncryptedMessage:
    """Encrypt a plaintext string and sign the ciphertext."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), None)
    signature = ed25519_private.sign(nonce + ciphertext)
    return EncryptedMessage(nonce, ciphertext, signature)


def decrypt_message(
    session_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    signature: bytes,
    ed25519_public_bytes: bytes,
) -> str:
    """Verify Ed25519 signature then decrypt. Raises ValueError on any failure."""
    pub_key = Ed25519PublicKey.from_public_bytes(ed25519_public_bytes)
    try:
        pub_key.verify(signature, nonce + ciphertext)
    except InvalidSignature as exc:
        raise ValueError("Message signature verification failed") from exc

    plaintext_bytes = AESGCM(session_key).decrypt(nonce, ciphertext, None)
    try:
        return plaintext_bytes.decode()
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted content is not valid UTF-8") from exc


def display_fingerprint(ed25519_public_bytes: bytes) -> str:
    """Human-readable fingerprint for out-of-band verification.

    Returns first 16 bytes of SHA-256(pubkey) as colon-separated uppercase hex.
    Example: AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90

    This is for DISPLAY ONLY. Do not use as a protocol identifier or key.
    """
    digest = hashlib.sha256(ed25519_public_bytes).digest()[:16]
    return ":".join(f"{b:02X}" for b in digest)


# Keep old name as alias so existing call sites don't break during transition.
fingerprint = display_fingerprint


def encode_public_key(pub_bytes: bytes) -> str:
    """Base64url-encode a public key without padding."""
    return base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()


def decode_public_key(encoded: str) -> bytes:
    """Decode a base64url-encoded public key (with or without padding).

    Raises ValueError for inputs with invalid base64 length or decoded
    length other than 32 bytes (the expected size for Ed25519/X25519 keys).
    """
    if len(encoded) % 4 == 1:
        raise ValueError(
            f"Invalid base64url key: length {len(encoded)} is not a valid base64 length"
        )
    decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if len(decoded) != 32:
        raise ValueError(
            f"Decoded public key must be 32 bytes, got {len(decoded)}"
        )
    return decoded


def private_key_to_bytes(key: Ed25519PrivateKey | X25519PrivateKey) -> bytes:
    """Serialize private key to raw bytes for encrypted storage."""
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def ed25519_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    """Restore Ed25519PrivateKey from raw bytes."""
    return Ed25519PrivateKey.from_private_bytes(raw)


def x25519_from_bytes(raw: bytes) -> X25519PrivateKey:
    """Restore X25519PrivateKey from raw bytes."""
    return X25519PrivateKey.from_private_bytes(raw)
