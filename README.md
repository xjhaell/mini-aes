# Mini-AES

A simplified 2x2 AES implementation in Python, operating in GF(2³).

This is a scaled-down version of the AES (Rijndael) algorithm. It runs all four transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey) on a 2x2 matrix with 3-bit cells instead of the standard 4x4 matrix with 8-bit cells. Small enough to trace by hand, but follows the same structure as the real thing.

> **Disclaimer:** This is an educational project. A 12-bit key has 4,096 possible values, trivially brute-forceable. Not for actual use.

---

## How It Works

Plaintext is converted to 8-bit ASCII, split into 12-bit blocks, and each block is loaded into a 2x2 matrix:

```
Plaintext "abc"
  -> 01100001 01100010 01100011       (ASCII to binary)
  -> [011000010110] [001001100011]    (12-bit blocks)

Block 1:              Block 2:
+-----+-----+        +-----+-----+
| 011 | 000 |        | 001 | 001 |
+-----+-----+        +-----+-----+
| 010 | 110 |        | 100 | 011 |
+-----+-----+        +-----+-----+
```

Each block goes through one round of four transformations:

### SubBytes

Each cell is replaced with its multiplicative inverse in GF(2³), using irreducible polynomial p(x) = x³ + x + 1. For example, `010` and `101` are inverses because `010 * 101 = 1` in GF(2³). Zero has no inverse and maps to itself.

| Input  | 000 | 001 | 010 | 011 | 100 | 101 | 110 | 111 |
|--------|-----|-----|-----|-----|-----|-----|-----|-----|
| Output | 000 | 001 | 101 | 110 | 111 | 010 | 011 | 100 |

### ShiftRows

Second row shifts left by one (right for decryption). First row stays put.

### MixColumns

Column-wise multiplication by a fixed matrix in GF(2³). Multiplying by 2 means left-shift + conditional XOR with `011` (reduction mod x³ + x + 1). The XOR happens when the shift produces a degree-3 term, which doesn't exist in GF(2³), so we reduce it back using the irreducible polynomial.

```
Encrypt:  M   = [[1, 2], [2, 1]]
Decrypt:  M⁻¹ = [[2, 4], [4, 2]]
```

### AddRoundKey

The 12-bit block is XORed with the 12-bit key. Its own inverse.

---

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/xjhaell/mini-aes.git
cd mini-aes
pip install -r requirements.txt
```

## Usage

**Run the examples:**

```bash
python3 examples.py
```

```
************************************************************
*  Mini-AES  //  Encrypt / Decrypt Round-Trip Tests
************************************************************
*  Test 1 -- Short string
*    Key:        010100111100
*    Plaintext:  "abc"
*    Ciphertext: 8ef3e4
*    Recovered:  "abc"
*    Result:     PASS
************************************************************
*  Test 3 -- Mixed content
*    Key:        101010101010
*    Plaintext:  "Hello World!"
*    Ciphertext: 3b48758f4985847af08f40cf
*    Recovered:  "Hello World!"
*    Result:     PASS
************************************************************
```

**Interactive mode:**

```bash
python3 mini_aes.py
```

**As a library:**

```python
from mini_aes import encrypt, decrypt

ciphertext = encrypt("Hello", "101010101010")
plaintext  = decrypt(ciphertext, "101010101010")
```

---

## Project Structure

```
mini-aes/
├── mini_aes.py        # AES transformations, encrypt/decrypt, CLI
├── utils.py           # Text/binary conversion, padding, matrix formatting
├── examples.py        # Non-interactive round-trip tests
├── requirements.txt   # numpy
├── LICENSE
└── README.md
```

---

## Design Decisions

**2x2 matrix in GF(2³):** Full AES uses a 4x4 matrix in GF(2⁸) with 128-bit blocks. Shrinking to 2x2 with 3-bit cells keeps all four transformations intact but makes the whole process easy to work through on paper.

**Zero-padding:** If the last block is under 12 bits, it gets padded with trailing zeros. Since the S-Box maps `000 -> 000`, padded values decrypt back to null characters, which get stripped from the output.

**Single round:** Full AES runs 10-14 rounds with key expansion. This uses one round with the raw key. The point is to see how the transformations work, not to be secure.

---

## Background

Built during [CS 747: Cryptography and Information Theory](https://catalog.unlv.edu/preview_course_nopop.php?catoid=40&coid=192173) at UNLV. This repo is a cleaned-up version of the original class assignment.