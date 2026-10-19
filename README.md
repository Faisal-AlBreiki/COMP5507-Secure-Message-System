# COMP5507 – Project Part 1: Secure Message System

A Python command-line application that demonstrates **classical Caesar cipher** and **modern AES-256-GCM** encryption and decryption. It supports cryptographically secure key generation, local key storage, explicit key replacement, and a sender/receiver message workflow.

## Features

- **Caesar cipher:** Encrypt and decrypt English letters using a shift key (0–25). Other characters are unchanged.
- **AES-256-GCM:** Authenticated encryption and decryption of UTF-8 messages (including English and Arabic).
- **Secure AES keys:** Generate random 256-bit keys with Python's `secrets` module.
- **Key management:** Keep an existing key or replace it only after explicit confirmation.
- **Terminal interface:** Generate Key, Encrypt Message, Decrypt Message, Exit.
- **Demonstration script:** Show round-trip encryption, an incorrect AES key, algorithm differences, and the importance of key management.

## Project Structure

```text
part1/
├── main.py
├── classical_cipher.py
├── aes_crypto.py
├── key_manager.py
├── demo.py
├── test_crypto.py
├── requirements.txt
├── README.md
└── .gitignore
```

The `.keys/` directory and `.keys/aes.key` file are **created locally when needed**; they are not included in the submission. Do not commit or send your real secret key.

## Requirements and Installation

- Python **3.10+**
- A terminal on Windows, Ubuntu/Linux, or macOS
- Python package `cryptography` (installed from `requirements.txt`)

Open the terminal **inside the `part1` folder** and install the dependency:

```bash
python -m pip install -r requirements.txt
```

Then start the program:

```bash
python main.py
```

On Linux/macOS, use `python3` if `python` is unavailable. On Windows, you can use `py` instead of `python`.

Optional: create and activate a virtual environment before installation. On some Linux distributions this is required when system-wide `pip` installs are restricted:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Using the Program

The main menu is:

```text
===== Secure Message System =====
1. Generate Key (AES-256)
2. Encrypt Message (Caesar or AES)
3. Decrypt Message (Caesar or AES)
4. Exit
```

### Classical Caesar Cipher

1. Select **2 → 1** (Encrypt Message → Caesar).
2. Enter shift **3** and plaintext **HELLO**; the result is **KHOOR**.
3. Select **3 → 1** (Decrypt Message → Caesar), enter shift **3** and **KHOOR**; the result is **HELLO**.

Caesar cipher is for historical/educational comparison only; it does **not** provide modern security.

### AES: Generate, Encrypt and Decrypt

1. Select **1** to generate a fresh AES-256 key if none is saved.
2. Select **2 → 2** (Encrypt Message → AES).
3. Choose **1** to use the saved key or **2** to paste a properly shared Base64 key.
4. Enter a message such as `Meet me at 10 PM` and copy the resulting **`AES1:...`** ciphertext.
5. Select **3 → 2** (Decrypt Message → AES), supply the **same key**, and paste the ciphertext to recover the original message.

To demonstrate two users on separate computers, the sender shares the ciphertext with the receiver. The receiver must receive the AES key through a **separate, trusted secure channel**. Never send the secret key alongside the ciphertext in an insecure channel.

### Existing AES Key: Keep or Replace

Selecting **1 Generate Key** when a key already exists displays:

```text
===== AES KEY MANAGEMENT =====
An AES key file already exists at: ...
1. Keep Current Key
2. Generate New Key (Replace Old)
3. Cancel
Select (1-3):
```

- **Keep Current Key:** Continue using the existing key without changing it.
- **Generate New Key:** Read the warning and type **`REPLACE`** exactly to confirm. Any other input cancels and preserves the old key. The new key is saved in place of the old one.
- **Cancel:** Return without modifying the key.

**Important:** A new key **cannot decrypt messages encrypted with the old key**. Before replacement, securely back up the old key if you need to retain access to old messages. Replacing a key does not re-encrypt older ciphertexts, and deleting the old file does not guarantee secure physical erasure.

### Wrong-Key Demonstration

Encrypt a message with one AES key, then try to decrypt it using a **different valid 256-bit AES key** (choose **Paste Base64 key**). The program reports:

```text
DECRYPTION FAILED: Authentication failed: incorrect key or modified ciphertext.
```

This is expected: AES-GCM checks an authentication tag and rejects decryption when the key is incorrect or the data has been changed.

## Quick Demonstration

Run the standalone demonstration from the `part1` folder:

```bash
python demo.py
```

The demonstration covers plaintext → ciphertext, ciphertext → plaintext, wrong-key rejection, the difference between classical encryption and AES, and secure key management. It generates temporary in-memory keys and **does not change your saved AES key**.

## Security and Implementation Notes

- AES uses a **256-bit key**, a fresh **96-bit nonce** per encryption, and a **128-bit GCM authentication tag**.
- Ciphertext format: `AES1:` + Base64(`nonce || ciphertext || tag`). The nonce is not secret and is required for decryption.
- Key generation uses `secrets.token_bytes(32)` backed by the operating system's secure random source.
- `.keys/aes.key` contains the **Base64-encoded plaintext secret key**; Base64 is **not encryption**. Local file protection is suitable for classroom demonstration, not production-level key security.
- The new key is written to a temporary file before replacing the saved key. Replacement requires user confirmation and does not guarantee secure erasure of older copies.
- Never hard-code secret keys, publish `.keys/`, or reuse the same AES-GCM (key, nonce) pair. Production systems should use proper access controls and secure key storage (such as a keystore or KMS).

## Automated Tests

The project includes 14 functional tests covering Caesar Cipher, AES-256-GCM encryption and decryption, incorrect keys, modified ciphertext, key generation, key storage, and key replacement.

To run the tests, open a terminal inside the `part1` directory and execute:

```bash
python -m unittest discover -s . -p "test_crypto.py" -v
```

All 14 tests passed during verification. These tests check expected functionality and do not constitute a formal security audit.

## References

- COMP5507 Project Part 1 - Classical & Symmetric Cryptography (assignment brief)
- Python `secrets` documentation: https://docs.python.org/3/library/secrets.html
- `cryptography` AESGCM documentation: https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
