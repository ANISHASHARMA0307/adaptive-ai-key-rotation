"""
Low-level ChaCha20-Poly1305 primitives.

We deliberately use ChaCha20-Poly1305 (an AEAD cipher) instead of AES/DES:
- 256-bit key
- 96-bit (12-byte) nonce
- built-in authentication (integrity + confidentiality) via the Poly1305 MAC

This module has no knowledge of files, keys-on-disk, or the database —
it only knows how to generate keys/nonces and encrypt/decrypt bytes.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from config import KEY_SIZE, NONCE_SIZE


def generate_key() -> bytes:
    """Generate a fresh random 256-bit key."""
    return ChaCha20Poly1305.generate_key()


def generate_nonce() -> bytes:
    """Generate a fresh random 96-bit nonce. A nonce must NEVER be reused with the same key."""
    return os.urandom(NONCE_SIZE)


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with the given key.
    Returns (nonce, ciphertext) — ciphertext includes the Poly1305 auth tag appended.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    nonce = generate_nonce()
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt ciphertext with the given key + nonce.
    Raises cryptography.exceptions.InvalidTag if the data was tampered with
    or the wrong key/nonce was used.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, associated_data)
