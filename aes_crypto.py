"""Authenticated AES-256-GCM encryption/decryption.

Transport format:
    AES1:<standard_base64(12-byte nonce || ciphertext || 16-byte GCM tag)>

A fresh random nonce is created for EVERY encryption. Never reuse a nonce with
the same AES-GCM key. AES1 indicates the format version, not a secret.
"""

import base64
import binascii
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32      # 256-bit key
NONCE_SIZE = 12    # 96-bit nonce recommended for GCM
TAG_SIZE = 16      # AESGCM.encrypt includes the tag in its output
TOKEN_PREFIX = "AES1:"


class MessageFormatError(ValueError):
    """Input is not a valid message in the expected AES1 transport format."""


class AuthenticationError(ValueError):
    """Authentication failed: wrong key or ciphertext was modified."""


def _check_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must contain exactly 32 bytes.")


def encrypt_aes(message: str, key: bytes) -> str:
    """Encrypt UTF-8 text, returning a copyable AES1-prefixed string."""
    if not isinstance(message, str):
        raise TypeError("The message must be a string.")
    _check_key(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    encrypted_with_tag = AESGCM(key).encrypt(nonce, message.encode("utf-8"), None)
    token = base64.b64encode(nonce + encrypted_with_tag).decode("ascii")
    return TOKEN_PREFIX + token


def decrypt_aes(token: str, key: bytes) -> str:
    """Verify the authentication tag and decrypt an AES1 message.

    The same error is reported for the wrong key and tampered ciphertext,
    since GCM does not reveal which one caused the authentication failure.
    """
    _check_key(key)
    if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX):
        raise MessageFormatError("Ciphertext must begin with 'AES1:'.")
    try:
        raw = base64.b64decode(token[len(TOKEN_PREFIX):].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise MessageFormatError("Ciphertext contains invalid Base64 data.") from exc
    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise MessageFormatError("Ciphertext is too short to be valid AES-GCM data.")
    nonce = raw[:NONCE_SIZE]
    encrypted_with_tag = raw[NONCE_SIZE:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, encrypted_with_tag, None)
    except InvalidTag as exc:
        raise AuthenticationError(
            "Authentication failed: incorrect key or modified ciphertext."
        ) from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MessageFormatError("Decrypted data is not valid UTF-8 text.") from exc
