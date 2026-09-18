"""
File-level encryption/decryption. Bridges raw file bytes <-> chacha.py
primitives, and handles reading/writing encrypted blobs on disk.
"""

import os

from config import ENCRYPTED_DIR
from crypto.chacha import encrypt_bytes, decrypt_bytes


def encrypted_path_for(stored_filename: str) -> str:
    return os.path.join(ENCRYPTED_DIR, stored_filename)


def encrypt_file(plaintext_path: str, stored_filename: str, key: bytes) -> tuple[bytes, int]:
    """
    Encrypt the file at plaintext_path with `key`, write ciphertext to
    ENCRYPTED_DIR/stored_filename. Returns (nonce, ciphertext_size_bytes).
    """
    with open(plaintext_path, "rb") as f:
        plaintext = f.read()

    nonce, ciphertext = encrypt_bytes(key, plaintext)

    out_path = encrypted_path_for(stored_filename)
    with open(out_path, "wb") as f:
        f.write(ciphertext)

    return nonce, len(ciphertext)


def encrypt_bytes_to_disk(plaintext: bytes, stored_filename: str, key: bytes) -> tuple[bytes, int]:
    """Same as encrypt_file but takes raw bytes directly (used during rotation)."""
    nonce, ciphertext = encrypt_bytes(key, plaintext)
    out_path = encrypted_path_for(stored_filename)
    with open(out_path, "wb") as f:
        f.write(ciphertext)
    return nonce, len(ciphertext)


def decrypt_file(stored_filename: str, key: bytes, nonce: bytes) -> bytes:
    """Read the encrypted blob for stored_filename and decrypt it, returning plaintext bytes."""
    in_path = encrypted_path_for(stored_filename)
    with open(in_path, "rb") as f:
        ciphertext = f.read()

    return decrypt_bytes(key, nonce, ciphertext)
