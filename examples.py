"""Non-interactive demo — runs encrypt/decrypt round-trip tests."""

from mini_aes import encrypt, decrypt


SEPARATOR = "*" * 60


def run_example(label: str, plaintext: str, key: str):
    """Encrypt, decrypt, and verify a single test case."""
    ciphertext = encrypt(plaintext, key)
    recovered = decrypt(ciphertext, key).rstrip('\x00')
    status = "PASS" if recovered == plaintext else "FAIL"

    print(f"*  {label}")
    print(f"*    Key:        {key}")
    print(f"*    Plaintext:  \"{plaintext}\"")
    print(f"*    Ciphertext: {ciphertext}")
    print(f"*    Recovered:  \"{recovered}\"")
    print(f"*    Result:     {status}")
    print(SEPARATOR)


def main():
    print(SEPARATOR)
    print("*  Mini-AES  //  Encrypt / Decrypt Round-Trip Tests")
    print(SEPARATOR)

    run_example(
        "Test 1 -- Short string",
        "abc",
        "010100111100",
    )

    run_example(
        "Test 2 -- Single character",
        "A",
        "110011001100",
    )

    run_example(
        "Test 3 -- Mixed content",
        "Hello World!",
        "101010101010",
    )

    run_example(
        "Test 4 -- Repeated characters",
        "aaaaaa",
        "111000111000",
    )

    run_example(
        "Test 5 -- Longer plaintext",
        "BoJack Horseman",
        "010100111100",
    )

    run_example(
        "Test 6 -- Exact block boundary (3 chars = 24 bits = 2 blocks)",
        "Hi!",
        "000111000111",
    )


if __name__ == '__main__':
    main()