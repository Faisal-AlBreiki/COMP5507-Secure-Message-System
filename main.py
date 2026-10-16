"""COMP5507 Secure Message System - simple terminal interface.

Menu required by project:
  1 Generate Key | 2 Encrypt Message | 3 Decrypt Message | 4 Exit

Users select either Caesar or AES inside Encrypt/Decrypt. For AES, users can
load a saved key or paste the Base64 key securely shared by the sender.
"""

from aes_crypto import AuthenticationError, MessageFormatError, decrypt_aes, encrypt_aes
from classical_cipher import decrypt_caesar, encrypt_caesar
from key_manager import (
    generate_key,
    get_key_path,
    key_from_base64,
    key_to_base64,
    load_key,
    replace_key,
    save_key,
)


def ask_yes_no(question: str) -> bool:
    return input(question).strip().lower() in ("y", "yes")


def choose_cipher() -> str | None:
    print("\nChoose encryption method:")
    print("  1. Caesar Cipher (classical / not secure)")
    print("  2. AES-256-GCM (modern / authenticated)")
    choice = input("Method (1/2): ").strip()
    if choice not in ("1", "2"):
        print("Invalid method. Choose 1 or 2.")
        return None
    return choice


def ask_caesar_shift() -> int | None:
    value = input("Enter Caesar shift (0-25): ").strip()
    try:
        shift = int(value)
        if 0 <= shift <= 25:
            return shift
    except ValueError:
        pass
    print("Invalid shift. Enter a whole number from 0 to 25.")
    return None


def choose_aes_key() -> bytes | None:
    print("\nAES key source:")
    print("  1. Use saved key (this computer)")
    print("  2. Paste a Base64 key (another user / wrong-key test)")
    option = input("Key source (1/2): ").strip()
    if option == "1":
        try:
            return load_key()
        except FileNotFoundError:
            print("No saved AES key. Choose 'Generate Key' from the main menu first.")
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"Cannot load saved AES key: {exc}")
        return None
    if option == "2":
        entered = input("Paste Base64 AES key (keep this private): ").strip()
        try:
            return key_from_base64(entered)
        except ValueError as exc:
            print(f"Invalid key: {exc}")
        return None
    print("Invalid key source. Choose 1 or 2.")
    return None


def handle_generate() -> None:
    path = get_key_path()
    if path.exists() or path.is_symlink():
        print("\n===== AES KEY MANAGEMENT =====")
        print(f"An AES key file already exists at: {path}")
        print("1. Keep Current Key")
        print("2. Generate New Key (Replace Old)")
        print("3. Cancel")
        choice = input("Select (1-3): ").strip()

        if choice == "1":
            try:
                key = load_key()
            except (OSError, UnicodeError, ValueError) as exc:
                print(f"Cannot read saved key: {exc}")
                return
            print("Current AES key kept unchanged.")
        elif choice == "2":
            print("\nWARNING: Replacing the saved key will make previous AES")
            print("messages impossible to decrypt using the new key.")
            print("Back up the old key securely first if you still need it.")
            print("This action does NOT re-encrypt older messages.")
            confirmation = input("Type REPLACE to confirm (anything else cancels): ").strip()
            if confirmation != "REPLACE":
                print("Cancelled. Your existing key has NOT been changed.")
                return
            try:
                key = generate_key()
                replace_key(key)
            except OSError as exc:
                print(f"Could not replace the AES key: {exc}")
                return
            print("\nSuccess: a NEW AES-256 key has replaced the saved key.")
            print(f"New key saved to: {path}")
        elif choice == "3":
            print("Cancelled. Your existing key has NOT been changed.")
            return
        else:
            print("Invalid choice. Existing key remains unchanged.")
            return
    else:
        try:
            key = generate_key()
            save_key(key)
        except FileExistsError:
            print("A key file was created by another process. Not overwriting it.")
            return
        except OSError as exc:
            print(f"Could not store the new key: {exc}")
            return
        print("\nSuccess: new AES-256 key generated with a secure random generator.")
        print(f"Key saved to: {path}")

    print("CAUTION: Anyone who obtains the secret key can read messages encrypted with it.")
    if ask_yes_no("Display Base64 key for secure sharing? (y/N): "):
        print("\nSECRET KEY (do not share publicly):")
        print(key_to_base64(key))
        print("Share the key ONLY through a separate, trusted secure channel.")


def handle_encrypt() -> None:
    method = choose_cipher()
    if method is None:
        return
    if method == "1":
        shift = ask_caesar_shift()
        if shift is None:
            return
        message = input("\nEnter plaintext: ")
        print("\nEncrypted Message (Caesar):")
        print(encrypt_caesar(message, shift))
        print("Reminder: Caesar is only a teaching example, not secure encryption.")
    else:
        key = choose_aes_key()
        if key is None:
            return
        message = input("\nEnter plaintext: ")
        print("\nEncrypted Message (AES-256-GCM; copy for receiver):")
        print(encrypt_aes(message, key))


def handle_decrypt() -> None:
    method = choose_cipher()
    if method is None:
        return
    if method == "1":
        shift = ask_caesar_shift()
        if shift is None:
            return
        token = input("\nEnter Caesar ciphertext: ")
        print("\nDecrypted Message:")
        print(decrypt_caesar(token, shift))
    else:
        key = choose_aes_key()
        if key is None:
            return
        token = input("\nEnter AES ciphertext (beginning with AES1:): ").strip()
        try:
            message = decrypt_aes(token, key)
        except (AuthenticationError, MessageFormatError) as exc:
            print(f"\nDECRYPTION FAILED: {exc}")
        else:
            print("\nDecrypted Message:")
            print(message)


def main() -> None:
    while True:
        print("\n" + "=" * 42)
        print("        Secure Message System")
        print("=" * 42)
        print("1. Generate Key (AES-256)")
        print("2. Encrypt Message (Caesar or AES)")
        print("3. Decrypt Message (Caesar or AES)")
        print("4. Exit")
        choice = input("\nSelect (1-4): ").strip()
        if choice == "1":
            handle_generate()
        elif choice == "2":
            handle_encrypt()
        elif choice == "3":
            handle_decrypt()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nSession ended.")
