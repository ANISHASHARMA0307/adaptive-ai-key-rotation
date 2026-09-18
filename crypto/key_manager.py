"""
Key lifecycle management: per-file, per-version key generation, storage on
disk, loading, and fingerprinting.

Keys are stored one-file-per-key under KEYS_DIR, named:

    file_<file_id>_v<version>.key

We NEVER overwrite or delete an old key file when rotating — old keys are
kept (marked INACTIVE in the DB) so that key history / audit trail is
preserved, per project requirements.
"""

import hashlib
import os

from config import KEYS_DIR
from crypto.chacha import generate_key


def key_filename_for(file_id: int, version: int) -> str:
    return f"file_{file_id}_v{version}.key"


def key_path_for(file_id: int, version: int) -> str:
    return os.path.join(KEYS_DIR, key_filename_for(file_id, version))


def save_new_key(file_id: int, version: int) -> tuple[bytes, str]:
    """Generate a new key, persist it to disk, return (raw_key_bytes, filename)."""
    key = generate_key()
    filename = key_filename_for(file_id, version)
    path = key_path_for(file_id, version)

    # keys/ is sensitive material — restrict permissions on write
    with open(path, "wb") as f:
        f.write(key)
    os.chmod(path, 0o600)

    return key, filename


def load_key(key_filename: str) -> bytes:
    """Load raw key bytes from disk given a stored filename."""
    path = os.path.join(KEYS_DIR, key_filename)
    with open(path, "rb") as f:
        return f.read()


def fingerprint(key: bytes) -> str:
    """
    Return a SHA-256 fingerprint of the key, hex-encoded.
    This is safe to display in the UI/audit log — it identifies a key
    without exposing the key material itself.
    """
    return hashlib.sha256(key).hexdigest()


def short_fingerprint(key: bytes, length: int = 12) -> str:
    return fingerprint(key)[:length].upper()
