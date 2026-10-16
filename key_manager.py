"""AES key generation, Base64 import/export and local key file storage.

Local storage is for the course demonstration, NOT a production key vault.
The key is stored in readable (Base64) form; on POSIX newly created files
are owner-only. On Windows, security depends on folder/OS access controls.
"""

import base64
import binascii
import os
from pathlib import Path
import secrets
import tempfile

KEY_SIZE = 32
DEFAULT_KEY_PATH = Path(__file__).resolve().parent / ".keys" / "aes.key"


def get_key_path() -> Path:
    """Allow test/dev override without requiring the working directory."""
    custom = os.environ.get("SECURE_MESSAGE_KEY_FILE")
    return Path(custom).expanduser() if custom else DEFAULT_KEY_PATH


def generate_key() -> bytes:
    """Generate 256 unpredictable key bits from the system CSPRNG."""
    return secrets.token_bytes(KEY_SIZE)


def key_to_base64(key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must contain exactly 32 bytes.")
    return base64.b64encode(key).decode("ascii")


def key_from_base64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Key must be Base64 text.")
    try:
        key = base64.b64decode(value.strip().encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("The AES key is not valid Base64.") from exc
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must decode to exactly 32 bytes.")
    return key


def save_key(key: bytes, path: Path | str | None = None) -> Path:
    """Create a key file without overwriting one that already exists.

    POSIX modes 0700/0600 protect newly created directory/file, subject to
    OS policy. The O_EXCL flag prevents accidental key replacement.
    """
    key_to_base64(key)  # validation before touching filesystem
    destination = Path(path) if path is not None else get_key_path()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(key_to_base64(key) + "\n")
    except Exception:
        # The new key file should not be left partially written.
        destination.unlink(missing_ok=True)
        raise
    return destination


def load_key(path: Path | str | None = None) -> bytes:
    source = Path(path) if path is not None else get_key_path()
    return key_from_base64(source.read_text(encoding="ascii"))


def replace_key(key: bytes, path: Path | str | None = None) -> Path:
    """Replace an existing saved key with a new key using an atomic file swap.

    This function does NOT securely erase old filesystem blocks or backups.
    Call it only after explicit user confirmation (handled in main.py).
    The replacement is written to a private temporary file in the same
    directory before os.replace, so failed writes preserve the old key.
    """
    encoded = key_to_base64(key)  # Validate before changing any files.
    destination = Path(path) if path is not None else get_key_path()
    if not destination.is_file() or destination.is_symlink():
        raise FileNotFoundError("No regular saved key file is available to replace.")

    fd, name = tempfile.mkstemp(prefix=".aes-key-new-", dir=destination.parent)
    temporary = Path(name)
    try:
        # mkstemp creates an owner-only (0600) file on POSIX.
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(encoded + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination
