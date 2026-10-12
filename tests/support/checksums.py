"""Independent formulations of the three checksums, for testing the scanner and the generators.

They are written differently from the code under test on purpose, so that one mistake cannot sit
in both the code and its check.
"""


def mod97_remainder(value: str) -> int:
    """The IBAN remainder of `value`, worked out digit by digit."""
    remainder = 0
    for char in value[4:] + value[:4]:
        for digit in str(int(char, 36)):
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder


def luhn_ok(number: str) -> bool:
    backwards = number[::-1]
    odd = [int(char) for char in backwards[0::2]]
    even = [int(char) for char in backwards[1::2]]
    return (sum(odd) + sum(sum(divmod(2 * digit, 10)) for digit in even)) % 10 == 0


def eleven_test_ok(number: str) -> bool:
    weights = (9, 8, 7, 6, 5, 4, 3, 2, -1)
    return sum(w * int(d) for w, d in zip(weights, number, strict=True)) % 11 == 0
