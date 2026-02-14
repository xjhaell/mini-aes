"""Conversion and formatting utilities for Mini-AES."""

import numpy as np


# ---------------------------------------------------------------------------
# Text <-> Binary Conversions
# ---------------------------------------------------------------------------

def text_to_binary(text: str) -> str:
    """
    Convert a plaintext string into a concatenated binary string.
    Each character is represented as 8 bits (standard ASCII).

    Example:
        text_to_binary("ab") -> "0110000101100010"
    """
    return ''.join(format(ord(ch), '08b') for ch in text)


def binary_to_text(binary: str) -> str:
    """
    Convert a binary string back into readable text.
    Splits the binary into 8-bit chunks and maps each to its ASCII character.

    Example:
        binary_to_text("0110000101100010") -> "ab"
    """
    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)


# ---------------------------------------------------------------------------
# Hex <-> Binary Conversions
# ---------------------------------------------------------------------------

def hex_to_binary(hex_string: str) -> str:
    """
    Convert a hexadecimal string to its binary representation.
    Output length is always a multiple of 4 (zero-padded on the left).

    Example:
        hex_to_binary("b7") -> "10110111"
    """
    bit_length = len(hex_string) * 4
    return format(int(hex_string, 16), '0' + str(bit_length) + 'b')


def binary_to_hex(binary: str) -> str:
    """
    Convert a binary string to a lowercase hexadecimal string.

    Example:
        binary_to_hex("10110111") -> "b7"
    """
    return hex(int(binary, 2))[2:].zfill(len(binary) // 4)


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------

def pad_block(block: str, target_length: int = 12) -> str:
    """
    Pad a binary block with trailing zeros to reach the target length.
    This ensures every block is exactly 12 bits for the 2x2 matrix.

    Note: Zero-padding works here because the S-Box maps 000 -> 000,
    so padded zeros decrypt back to zeros (null characters), which
    can be stripped from the output.

    Example:
        pad_block("01100001") -> "011000010000"
    """
    return block.ljust(target_length, '0')


# ---------------------------------------------------------------------------
# Block <-> Matrix Formatting
# ---------------------------------------------------------------------------

def binary_to_blocks(binary: str, block_size: int = 12) -> list[str]:
    """
    Split a binary string into fixed-size blocks.
    The last block is zero-padded if it does not reach block_size.

    Example:
        binary_to_blocks("011000010110001001100011")
        -> ["011000010110", "001001100011"]
    """
    blocks = []
    for i in range(0, len(binary), block_size):
        block = binary[i:i + block_size]
        if len(block) < block_size:
            block = pad_block(block, block_size)
        blocks.append(block)
    return blocks


def block_to_matrix(block: str) -> np.ndarray:
    """
    Convert a 12-bit binary block into a 2x2 NumPy matrix of 3-bit strings.

    The 12 bits are split into four 3-bit cells, filled row by row:
        block = "abcdefghijkl"
        matrix = [["abc", "def"],
                  ["ghi", "jkl"]]

    Example:
        block_to_matrix("011000010110")
        -> [["011", "000"], ["010", "110"]]
    """
    cells = [block[i:i + 3] for i in range(0, 12, 3)]
    return np.array(cells).reshape(2, 2)


def matrix_to_block(matrix: np.ndarray) -> str:
    """
    Flatten a 2x2 matrix of 3-bit strings back into a 12-bit binary block.

    Example:
        matrix_to_block([["011", "000"], ["010", "110"]])
        -> "011000010110"
    """
    return ''.join(matrix.flatten())


# ---------------------------------------------------------------------------
# High-Level Pipelines
# ---------------------------------------------------------------------------
# These combine the above functions into full conversion chains,
# used by mini_aes.py to go from plaintext/ciphertext to matrices and back.

def text_to_matrices(plaintext: str) -> list[np.ndarray]:
    """Plaintext string -> list of 2x2 binary matrices."""
    binary = text_to_binary(plaintext)
    blocks = binary_to_blocks(binary)
    return [block_to_matrix(b) for b in blocks]


def matrices_to_hex(matrices: list[np.ndarray]) -> str:
    """List of 2x2 binary matrices -> hexadecimal ciphertext string."""
    combined = ''.join(matrix_to_block(m) for m in matrices)
    return binary_to_hex(combined)


def hex_to_matrices(hex_string: str) -> list[np.ndarray]:
    """Hexadecimal ciphertext string -> list of 2x2 binary matrices."""
    binary = hex_to_binary(hex_string)
    blocks = binary_to_blocks(binary)
    return [block_to_matrix(b) for b in blocks]


def matrices_to_text(matrices: list[np.ndarray]) -> str:
    """List of 2x2 binary matrices -> plaintext string."""
    combined = ''.join(matrix_to_block(m) for m in matrices)
    return binary_to_text(combined)