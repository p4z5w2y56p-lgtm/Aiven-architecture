"""Generated test values: IBANs, card numbers, BSNs and secret-like strings.

Nothing in here is a stored value. A complete token-shaped string, IBAN, card number or BSN in a
committed file would trip secret scanners such as GitHub push protection, and the project stores no
credentials anywhere. So every value is built when a test runs: check digits are computed, and
secret-like strings are joined from fragments that match no pattern on their own.

A fixed seed makes a run repeatable. The values still differ from call to call.
"""

import random
import string

_RANDOM = random.Random(20261012)

# Letters and digits for the free part of a generated string. No letter A, so a random string
# can never spell the AKIA or ASIA prefix of an AWS key.
_BODY_ALPHABET = string.ascii_uppercase.replace("A", "") + string.digits


def _letters(count: int) -> str:
    return "".join(_RANDOM.choices(string.ascii_uppercase, k=count))


def _digits(count: int) -> str:
    return "".join(_RANDOM.choices(string.digits, k=count))


def _digits_without_leading_zero(count: int) -> str:
    return _RANDOM.choice(string.digits[1:]) + _digits(count - 1)


def _numeric(text: str) -> int:
    """Letters and digits as one number, with the letters read as 10 to 35."""
    return int("".join(str(int(char, 36)) for char in text))


def _mod97(iban: str) -> int:
    return _numeric(iban[4:] + iban[:4]) % 97


def _iban_check_digits(country: str, bban: str) -> str:
    # The country code and 00 go behind the rest; the check digits are 98 minus the remainder.
    return f"{98 - _numeric(bban + country + '00') % 97:02d}"


def grouped(value: str, separator: str = " ", size: int = 4) -> str:
    """`value` cut into groups of `size`, the way IBANs and card numbers are often written."""
    return separator.join(value[i : i + size] for i in range(0, len(value), size))


def assignment(keyword: str, between: str = ": ", value: str = "Zq7f", quote: str = "") -> str:
    """A made-up credential assignment (keyword, separator, value) joined from its parts.

    Tests build these here, from parts, so that no keyword followed by a value stands in a test
    source. `quote` goes around the keyword and around the value, as in JSON.
    """
    return f"{quote}{keyword}{quote}{between}{quote}{value}{quote}"


def valid_iban(country: str = "NL") -> str:
    """A random IBAN that passes mod-97: NL, two check digits, four letters and ten digits."""
    if country != "NL":
        raise ValueError(f"only country NL is supported, not {country!r}")
    bban = _letters(4) + _digits(10)
    return country + _iban_check_digits(country, bban) + bban


def valid_iban_of_length(length: int) -> str:
    """A random string of `length` letters and digits that passes mod-97, for the length limits.

    National IBAN formats differ in length (15 to 34 characters). This is not any of them: it has
    only the shape the scanner looks at, two letters, two digits and a mod-97 sum that fits.
    """
    bban = "".join(_RANDOM.choices(_BODY_ALPHABET, k=length - 4))
    return "NL" + _iban_check_digits("NL", bban) + bban


def valid_mod97(head: str, length: int) -> str:
    """A random string of `length` letters and digits that starts with `head` and passes mod-97.

    For testing where the scanner lets a candidate start: unlike an IBAN, `head` may be any shape.
    """
    if length < len(head) + 4:
        raise ValueError("leave at least 4 characters after the head to adjust the sum")
    while True:
        candidate = head + "".join(_RANDOM.choices(_BODY_ALPHABET, k=length - len(head)))
        if _mod97(candidate) == 1:
            return candidate


def _luhn_number(length: int) -> str:
    payload = _digits_without_leading_zero(length - 1)
    total = 0
    for index, char in enumerate(reversed(payload)):
        digit = int(char)
        if index % 2 == 0:  # these digits sit in a doubled position once the check digit is added
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return payload + str((10 - total % 10) % 10)


def valid_card(length: int = 16, last_digit: str = "") -> str:
    """A random number of `length` digits (16 by default) that passes the Luhn check.

    With `last_digit`, numbers are drawn until one ends in it. The last digit is the check digit,
    so that takes ten draws on average.
    """
    if last_digit and not (len(last_digit) == 1 and last_digit in string.digits):
        raise ValueError(f"last_digit must be one digit, not {last_digit!r}")
    while True:
        card = _luhn_number(length)
        if card.endswith(last_digit):
            return card


def valid_bsn() -> str:
    """A random 9-digit number that passes the BSN eleven-test and is not all zeros."""
    while True:
        payload = _digits_without_leading_zero(8)
        total = sum(
            weight * int(digit) for weight, digit in zip(range(9, 1, -1), payload, strict=True)
        )
        if total % 11 != 10:  # a check digit cannot be 10, so draw again
            return payload + str(total % 11)


def secret_values() -> dict[str, list[str]]:
    """Credential-like strings by the kind that `scan` reports for them.

    There is at least one string per kind and one for each alternative of its pattern. Each is as
    short as the pattern allows, so a test can cut one character off and expect the match to go.
    They use the whole character class of their pattern, `-` and `_` where it allows them. The
    second Google key has a hyphen early in its body and another as its last character: a word
    that holds it is cut at the hyphen by anything that reads words.
    """
    return {
        "private key": [
            "-----BEGIN " + "PRIVATE KEY" + "-----",
            "-----BEGIN " + "RSA PRIVATE KEY" + "-----",
            "-----BEGIN " + "EC2 PRIVATE KEY" + "-----",
            "-----BEGIN " + "PGP PRIVATE KEY BLOCK" + "-----",
        ],
        "service account key": ['"private' + '_key"'],
        "Google API key": ["AIza" + "Sy-_" + "Q" * 31, "AIza" + "Q-" + "Z" * 32 + "-"],
        "OAuth token": ["ya29" + ".a-_" + "b" * 17, "1/" + "/0a-_" + "b" * 17],
        "GitHub token": ["gh" + "p_" + "a" * 36, "github" + "_pat_" + "A_1" * 7 + "x"],
        "Slack token": ["xox" + "b-" + "a1-" * 3 + "z"],
        "Anthropic API key": ["sk-" + "ant-" + "a-_" + "B" * 17],
        "OpenAI API key": ["sk-" + "a_-" + "B" * 17],
        "AWS access key": ["AKIA" + "Q" * 16, "ASIA" + "Z9" * 8],
        "JWT": ["eyJ" + "a-_" + "bb" + ".eyJ" + "c-_" + "dd" + "."],
        "password or secret value": [
            "pass" + "word" + ": " + "Zq7f",
            "client-secret" + "=" + "Zq7f",
            "TOKEN" + " = " + "Zq7f",
        ],
    }


def sensitive_samples() -> dict[str, tuple[str, int]]:
    """One value of each kind that a finding must not show, and the length of its public start.

    The public start is what every value of its kind begins with (`AKIA`, `gh`): a finding may
    show that, and nothing after it. A BSN, an IBAN and a card number have none, so for them the
    length is 0. The Google key comes twice, the second time with hyphens early and last.
    """
    secrets = secret_values()
    return {
        "BSN": (valid_bsn(), 0),
        "IBAN": (valid_iban(), 0),
        "card number": (valid_card(), 0),
        "Google API key": (secrets["Google API key"][0], len("AIza")),
        "Google API key with hyphens": (secrets["Google API key"][1], len("AIza")),
        "AWS access key": (secrets["AWS access key"][0], len("AKIA")),
        "GitHub token": (secrets["GitHub token"][0], len("ghp_")),
        "Slack token": (secrets["Slack token"][0], len("xoxb-")),
        "OpenAI API key": (secrets["OpenAI API key"][0], len("sk-")),
        "Anthropic API key": (secrets["Anthropic API key"][0], len("sk-ant-")),
        "OAuth token": (secrets["OAuth token"][0], len("ya29.")),
        "JWT": (secrets["JWT"][0], len("eyJ")),
        "password assignment": (assignment("password", "=", "Zq7f1234"), len("password=")),
    }
