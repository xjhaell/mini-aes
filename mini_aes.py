"""Simplified 2x2 AES implementation in GF(2^3)."""

import sys
import numpy as np
from utils import (
    text_to_matrices,
    matrices_to_hex,
    hex_to_matrices,
    matrices_to_text,
    matrix_to_block,
    block_to_matrix,
)


# ---------------------------------------------------------------------------
# S-Box (multiplicative inverses in GF(2^3), irreducible poly: x^3 + x + 1)
# ---------------------------------------------------------------------------

S_BOX = {
    '000': '000',  # 0 -> 0 (no inverse)
    '001': '001',  # 1 -> 1
    '010': '101',  # 2 -> 5
    '011': '110',  # 3 -> 6
    '100': '111',  # 4 -> 7
    '101': '010',  # 5 -> 2
    '110': '011',  # 6 -> 3
    '111': '100',  # 7 -> 4
}

INVERSE_S_BOX = {v: k for k, v in S_BOX.items()}


# ---------------------------------------------------------------------------
# GF(2^3) Arithmetic
# ---------------------------------------------------------------------------

def gf_add(a: str, b: str) -> str:
    """XOR two 3-bit elements (addition in GF(2^3))."""
    return format(int(a, 2) ^ int(b, 2), '03b')


def gf_multiply_by_2(value: str) -> str:
    """
    Multiply a 3-bit element by 2 (x) in GF(2^3).

    Left-shifts by 1. If the high bit was set, the result overflows
    to degree 3, so we reduce by XORing with 011 (x + 1), which
    represents the irreducible polynomial x^3 + x + 1.
    """
    shifted = value[1:] + '0'
    if value[0] == '1':
        shifted = format(int(shifted, 2) ^ 0b011, '03b')
    return shifted


def gf_multiply_by_4(value: str) -> str:
    """Multiply by 4 (x^2) in GF(2^3) — multiply by 2 twice."""
    return gf_multiply_by_2(gf_multiply_by_2(value))


# ---------------------------------------------------------------------------
# AES Transformations
# ---------------------------------------------------------------------------

def sub_bytes(matrix: np.ndarray, inverse: bool = False) -> np.ndarray:
    """Replace each cell with its S-Box (or inverse S-Box) lookup."""
    box = INVERSE_S_BOX if inverse else S_BOX
    result = matrix.copy()
    for i in range(2):
        for j in range(2):
            result[i][j] = box[result[i][j]]
    return result


def shift_rows(matrix: np.ndarray, inverse: bool = False) -> np.ndarray:
    """
    Shift the second row by one position.
    Encrypt: left shift. Decrypt: right shift. First row unchanged.
    """
    result = matrix.copy()
    direction = 1 if inverse else -1
    result[1] = np.roll(result[1], direction)
    return result


def mix_columns(matrix: np.ndarray, inverse: bool = False) -> np.ndarray:
    """
    MixColumns via matrix multiplication in GF(2^3).

    Encrypt uses M = [[1, 2], [2, 1]].
    Decrypt uses M^-1 = [[2, 4], [4, 2]].

    Each row is computed independently:
        Encrypt:  new[i] = [a + 2b, 2a + b]
        Decrypt:  new[i] = [2a + 4b, 4a + 2b]
    """
    a, b = matrix[0]
    c, d = matrix[1]

    if not inverse:
        e = gf_add(a, gf_multiply_by_2(b))
        f = gf_add(gf_multiply_by_2(a), b)
        g = gf_add(c, gf_multiply_by_2(d))
        h = gf_add(gf_multiply_by_2(c), d)
    else:
        e = gf_add(gf_multiply_by_2(a), gf_multiply_by_4(b))
        f = gf_add(gf_multiply_by_4(a), gf_multiply_by_2(b))
        g = gf_add(gf_multiply_by_2(c), gf_multiply_by_4(d))
        h = gf_add(gf_multiply_by_4(c), gf_multiply_by_2(d))

    return np.array([[e, f], [g, h]])


def add_round_key(matrix: np.ndarray, key: str) -> np.ndarray:
    """XOR the flattened 12-bit matrix with the 12-bit key."""
    flat = matrix_to_block(matrix)
    xored = format(int(flat, 2) ^ int(key, 2), '012b')
    return block_to_matrix(xored)


# ---------------------------------------------------------------------------
# Single Block Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt_block(matrix: np.ndarray, key: str) -> np.ndarray:
    """
    Encrypt one 2x2 block (single round).
    Order: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    """
    state = sub_bytes(matrix)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, key)
    return state


def decrypt_block(matrix: np.ndarray, key: str) -> np.ndarray:
    """
    Decrypt one 2x2 block (single round, inverse in reverse).
    Order: AddRoundKey -> InvMixColumns -> InvShiftRows -> InvSubBytes
    """
    state = add_round_key(matrix, key)
    state = mix_columns(state, inverse=True)
    state = shift_rows(state, inverse=True)
    state = sub_bytes(state, inverse=True)
    return state


# ---------------------------------------------------------------------------
# Multi-Block Encrypt / Decrypt
# ---------------------------------------------------------------------------

def validate_key(key: str) -> None:
    """Raise ValueError if the key is not exactly 12 binary digits."""
    if len(key) != 12 or not all(b in '01' for b in key):
        raise ValueError(
            f"Key must be exactly 12 binary digits. Got: '{key}'"
        )


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt a plaintext string with a 12-bit key. Returns hex ciphertext."""
    validate_key(key)
    matrices = text_to_matrices(plaintext)
    encrypted = [encrypt_block(m, key) for m in matrices]
    return matrices_to_hex(encrypted)


def decrypt(ciphertext_hex: str, key: str) -> str:
    """Decrypt a hex ciphertext string with a 12-bit key. Returns plaintext."""
    validate_key(key)
    matrices = hex_to_matrices(ciphertext_hex)
    decrypted = [decrypt_block(m, key) for m in matrices]
    return matrices_to_text(decrypted)


# ---------------------------------------------------------------------------
# Interactive CLI
# ---------------------------------------------------------------------------

def prompt_key() -> str:
    """Prompt the user for a valid 12-bit binary key."""
    while True:
        key = input("*  Enter a 12-bit binary key: ").strip()
        try:
            validate_key(key)
            return key
        except ValueError as e:
            print(f"*  Error: {e}")


def interactive_menu():
    """Run an interactive encrypt/decrypt menu."""
    print("*" * 50)
    print("*  Mini-AES  //  2x2 Simplified AES in GF(2^3)")
    print(f"*  Python {sys.version.split()[0]}")
    print("*" * 50)

    while True:
        print("\n*  [E] Encrypt")
        print("*  [D] Decrypt")
        print("*  [Q] Quit")
        choice = input("*  > ").strip().lower()

        if choice == 'e':
            key = prompt_key()
            plaintext = input("*  Enter plaintext: ")
            ciphertext = encrypt(plaintext, key)
            print(f"*  Ciphertext (hex): {ciphertext}")

        elif choice == 'd':
            key = prompt_key()
            ciphertext = input("*  Enter ciphertext (hex): ").strip()
            try:
                plaintext = decrypt(ciphertext, key)
                print(f"*  Plaintext: {plaintext}")
            except ValueError as e:
                print(f"*  Error: {e}")

        elif choice == 'q':
            print("*  Exiting.")
            break

        else:
            print("*  Invalid choice. Enter E, D, or Q.")


if __name__ == '__main__':
    interactive_menu()