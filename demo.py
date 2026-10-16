"""One-command demonstration of the assessment's five required points."""

from aes_crypto import AuthenticationError, decrypt_aes, encrypt_aes
from classical_cipher import decrypt_caesar, encrypt_caesar
from key_manager import generate_key


def run_demo() -> None:
    print("=" * 62)
    print("COMP5507 - Cryptography Project Part 1 - Demonstration")
    print("=" * 62)
    text = "Meet me at 10 PM"
    shift = 3
    print("\n[1] Classical Caesar: Plaintext -> Ciphertext -> Plaintext")
    caesar = encrypt_caesar(text, shift)
    print("Plaintext :", text)
    print("Shift key :", shift)
    print("Ciphertext:", caesar)
    print("Recovered :", decrypt_caesar(caesar, shift))

    print("\n[2] AES-256-GCM: Plaintext -> Ciphertext -> Plaintext")
    sender_key = generate_key()
    aes_token = encrypt_aes(text, sender_key)
    print("Plaintext :", text)
    print("Ciphertext:", aes_token)
    print("Recovered :", decrypt_aes(aes_token, sender_key))

    print("\n[3] Wrong AES key -> authenticated decryption is rejected")
    incorrect_key = generate_key()
    try:
        decrypt_aes(aes_token, incorrect_key)
    except AuthenticationError as exc:
        print("Expected failure:", exc)
    else:
        raise AssertionError("Wrong key unexpectedly decrypted the message!")

    print("\n[4] Difference: Caesar is predictable letter shifting;")
    print("    AES-GCM protects message confidentiality and integrity.")
    print("\n[5] Key management: use unpredictable keys, keep them secret,")
    print("    and exchange them through a separate trusted secure channel.")
    print("\nDemo completed successfully.")


if __name__ == "__main__":
    run_demo()
