"""Functional tests for COMP5507 Secure Message System.

Run from the part1 directory with:
    python -m unittest discover -s tests -v
"""
import base64
import tempfile
import unittest
from pathlib import Path

from aes_crypto import (
    AuthenticationError,
    MessageFormatError,
    decrypt_aes,
    encrypt_aes,
)
from classical_cipher import decrypt_caesar, encrypt_caesar
from key_manager import (
    generate_key,
    key_from_base64,
    key_to_base64,
    load_key,
    replace_key,
    save_key,
)


class SecureMessageSystemTests(unittest.TestCase):
    # 1
    def test_caesar_encrypts_known_example(self):
        self.assertEqual(encrypt_caesar("HELLO", 3), "KHOOR")

    # 2
    def test_caesar_decrypts_known_example(self):
        self.assertEqual(decrypt_caesar("KHOOR", 3), "HELLO")

    # 3
    def test_caesar_preserves_case_punctuation_and_digits(self):
        self.assertEqual(encrypt_caesar("Meet me at 10 PM!", 3), "Phhw ph dw 10 SP!")

    # 4
    def test_caesar_rejects_invalid_shift(self):
        for shift in (-1, 26, 3.5, True):
            with self.subTest(shift=shift):
                with self.assertRaises(ValueError):
                    encrypt_caesar("HELLO", shift)

    # 5
    def test_caesar_rejects_non_string_message(self):
        with self.assertRaises(TypeError):
            encrypt_caesar(123, 3)

    # 6
    def test_aes_encrypt_decrypt_round_trip(self):
        key = generate_key()
        message = "Meet me at 10 PM"
        token = encrypt_aes(message, key)
        self.assertTrue(token.startswith("AES1:"))
        self.assertEqual(decrypt_aes(token, key), message)

    # 7
    def test_aes_handles_unicode_and_empty_messages(self):
        key = generate_key()
        for message in ("مرحبا 👋", "", "line one\nline two"):
            with self.subTest(message=message):
                self.assertEqual(decrypt_aes(encrypt_aes(message, key), key), message)

    # 8
    def test_aes_uses_a_fresh_nonce_for_each_encryption(self):
        key = generate_key()
        first = encrypt_aes("same message", key)
        second = encrypt_aes("same message", key)
        self.assertNotEqual(first, second)

    # 9
    def test_aes_rejects_wrong_key(self):
        token = encrypt_aes("secret", generate_key())
        with self.assertRaises(AuthenticationError):
            decrypt_aes(token, generate_key())

    # 10
    def test_aes_rejects_modified_ciphertext(self):
        key = generate_key()
        token = encrypt_aes("secret", key)
        # Flip one Base64 payload character while preserving the AES1 prefix.
        payload = token[len("AES1:"):]
        replacement = "A" if payload[0] != "A" else "B"
        tampered = "AES1:" + replacement + payload[1:]
        with self.assertRaises((AuthenticationError, MessageFormatError)):
            decrypt_aes(tampered, key)

    # 11
    def test_aes_rejects_malformed_tokens(self):
        key = generate_key()
        invalid_tokens = ("not-an-aes-token", "AES1:%%%", "AES1:QQ==")
        for token in invalid_tokens:
            with self.subTest(token=token):
                with self.assertRaises(MessageFormatError):
                    decrypt_aes(token, key)

    # 12
    def test_key_generation_and_base64_round_trip(self):
        key = generate_key()
        self.assertEqual(len(key), 32)
        self.assertEqual(key_from_base64(key_to_base64(key)), key)
        with self.assertRaises(ValueError):
            key_to_base64(b"short")

    # 13
    def test_save_load_key_and_prevent_accidental_overwrite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / ".keys" / "aes.key"
            key = generate_key()
            save_key(key, path)
            self.assertEqual(load_key(path), key)
            with self.assertRaises(FileExistsError):
                save_key(generate_key(), path)
            self.assertEqual(load_key(path), key)

    # 14
    def test_replace_key_updates_existing_key_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / ".keys" / "aes.key"
            old_key = generate_key()
            new_key = generate_key()
            save_key(old_key, path)
            replace_key(new_key, path)
            self.assertEqual(load_key(path), new_key)
            self.assertNotEqual(load_key(path), old_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
