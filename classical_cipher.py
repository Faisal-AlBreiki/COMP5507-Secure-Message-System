"""Classical Caesar cipher for education (NOT secure for real secrets).

Only ASCII letters A-Z and a-z are shifted; digits, punctuation, spaces,
and non-English characters are preserved unchanged.
"""


def _check_shift(shift: int) -> None:
    if isinstance(shift, bool) or not isinstance(shift, int) or not 0 <= shift <= 25:
        raise ValueError("Caesar shift must be an integer between 0 and 25.")


def encrypt_caesar(message: str, shift: int) -> str:
    """Return the Caesar-encrypted version of *message*."""
    if not isinstance(message, str):
        raise TypeError("The message must be a string.")
    _check_shift(shift)
    output = []
    for char in message:
        if "A" <= char <= "Z":
            output.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        elif "a" <= char <= "z":
            output.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        else:
            output.append(char)
    return "".join(output)


def decrypt_caesar(ciphertext: str, shift: int) -> str:
    """Undo a Caesar shift using the same numerical key."""
    _check_shift(shift)
    return encrypt_caesar(ciphertext, (26 - shift) % 26)
