"""Content safety (validator-spec section 3.8): what `scan` finds, where, and what it never says."""

import dataclasses
import string
import time

import pytest

from aiven.policy.content import KIND_CODES, ContentHit, scan
from tests.support import gen
from tests.support.checksums import eleven_test_ok, luhn_ok, mod97_remainder
from tests.support.gen import assignment, grouped
from tests.support.policies import valid_base
from tests.support.spec_tables import table_after

SECRET_KINDS = [
    "private key",
    "service account key",
    "Google API key",
    "OAuth token",
    "GitHub token",
    "Slack token",
    "Anthropic API key",
    "OpenAI API key",
    "AWS access key",
    "JWT",
    "password or secret value",
]
PASSWORD = "password or secret value"


def hits(text: str) -> list[tuple[str, int, int]]:
    return [(hit.kind, hit.line, hit.column) for hit in scan(text)]


# --- the contract


def test_a_hit_has_a_kind_a_line_and_a_column_and_nothing_else():
    assert [field.name for field in dataclasses.fields(ContentHit)] == ["kind", "line", "column"]
    hit = ContentHit("IBAN", 3, 7)
    assert (hit.kind, hit.line, hit.column) == ("IBAN", 3, 7)
    with pytest.raises(dataclasses.FrozenInstanceError):
        hit.line = 4


def test_the_kinds_and_their_codes_in_priority_order():
    assert list(KIND_CODES) == [*SECRET_KINDS, "IBAN", "card number", "BSN"]
    assert [KIND_CODES[kind] for kind in SECRET_KINDS] == ["E-SECRET"] * 11
    assert [KIND_CODES["IBAN"], KIND_CODES["card number"]] == ["E-BANK-DETAILS"] * 2
    assert KIND_CODES["BSN"] == "E-ID-NUMBER"


def test_kind_codes_cannot_be_changed():
    with pytest.raises(TypeError):
        KIND_CODES["IBAN"] = "E-SECRET"


def test_the_codes_are_the_ones_of_spec_section_3_8():
    header, *rows = table_after("3.8 Content safety")
    assert header == ["Code", "Fails when"]
    assert {row[0] for row in rows} == set(KIND_CODES.values())


def test_the_valid_base_has_nothing_sensitive():
    assert scan(valid_base().decode("utf-8")) == []


def test_clean_and_empty_text_have_no_hits():
    assert scan("") == []
    assert scan("\n\n") == []
    assert scan("Nothing to see here.\nNot even on the second line.\n") == []


# --- E-SECRET

SECRET_SAMPLES = [
    pytest.param(kind, value, id=f"{kind}-{number}")
    for kind, values in gen.secret_values().items()
    for number, value in enumerate(values, start=1)
]


@pytest.mark.parametrize(("kind", "value"), SECRET_SAMPLES)
def test_a_credential_is_found_at_its_line_and_column(kind, value):
    assert hits(f"first line\nsay {value} now\n") == [(kind, 2, 5)]


@pytest.mark.parametrize(("kind", "value"), SECRET_SAMPLES)
def test_one_character_less_is_no_longer_that_kind(kind, value):
    assert kind not in {found for found, _, _ in hits(f"say {value[:-1]} now")}


@pytest.mark.parametrize(("kind", "value"), SECRET_SAMPLES)
def test_a_longer_value_is_still_one_hit(kind, value):
    assert hits(f"say {value}{'x' * 40} now") == [(kind, 1, 5)]


@pytest.mark.parametrize("letter", "pousr")
def test_every_github_token_type_is_found(letter):
    assert hits("say gh" + letter + "_" + "a" * 36) == [("GitHub token", 1, 5)]


@pytest.mark.parametrize("letter", "abposr")
def test_every_slack_token_type_is_found(letter):
    assert hits("say xox" + letter + "-" + "a1" * 5) == [("Slack token", 1, 5)]


NOT_CREDENTIALS = {
    "public key header": "-----BEGIN " + "PUBLIC KEY" + "-----",
    "certificate header": "-----BEGIN " + "CERTIFICATE" + "-----",
    "key header in lower case": "-----BEGIN " + "private key" + "-----",
    "private key name without quotes": "private" + "_key",
    "private key name in single quotes": "'private" + "_key'",
    "Google prefix in lower case": "aiza" + "S" * 35,
    "OAuth prefix without the dot": "ya29" + "a" * 25,
    "GitHub prefix with another letter": "gh" + "x_" + "a" * 36,
    "Slack prefix with another letter": "xox" + "z-" + "a" * 12,
    "AWS prefix in lower case": "akia" + "Q" * 16,
    "AWS prefix with another letter": "AKIB" + "Q" * 16,
    "JWT with two segments": "eyJ" + "a" * 8 + ".eyJ" + "b" * 8,
    "JWT whose second segment is not a payload": "eyJ" + "a" * 8 + ".xyz" + "b" * 8 + ".c",
    "JWT with a short first segment": "eyJ" + "ab" + ".eyJ" + "b" * 8 + ".c",
}


@pytest.mark.parametrize("value", NOT_CREDENTIALS.values(), ids=NOT_CREDENTIALS)
def test_look_alikes_are_not_credentials(value):
    assert scan(f"see {value} here") == []


# Kinds that begin with a fixed prefix. The prefix inside a longer word is not the start of a token.
PREFIX_KINDS = [
    "Google API key",
    "OAuth token",
    "GitHub token",
    "Slack token",
    "Anthropic API key",
    "OpenAI API key",
    "AWS access key",
    "JWT",
]
PREFIX_SAMPLES = [
    pytest.param(kind, value, id=f"{kind}-{number}")
    for kind, values in gen.secret_values().items()
    if kind in PREFIX_KINDS
    for number, value in enumerate(values, start=1)
]
BEFORE_A_TOKEN = {
    "space": " ",
    "double quote": '"',
    "single quote": "'",
    "equals sign": "=",
    "colon": ":",
    "open parenthesis": "(",
    "slash": "/",
    "underscore": "_",
    "hyphen": "-",
    "period": ".",
}
HYPHENATED_WORDS = [
    "risk-adjusted-return-calculation",
    "task-oriented-workflow-management",
    "desk-" + "-".join(["abcde"] * 5),
    "-".join(["risk", *string.ascii_lowercase]),
]


@pytest.mark.parametrize(("kind", "value"), PREFIX_SAMPLES)
@pytest.mark.parametrize("glue", ["x", "X", "7"])
def test_a_token_glued_to_a_letter_or_digit_is_not_found(kind, value, glue):
    assert scan(f"say {glue}{value} now") == []


@pytest.mark.parametrize(("kind", "value"), PREFIX_SAMPLES)
@pytest.mark.parametrize("before", BEFORE_A_TOKEN.values(), ids=BEFORE_A_TOKEN)
def test_a_token_after_a_separator_is_still_found(kind, value, before):
    assert hits(f"{before}{value}") == [(kind, 1, 2)]


@pytest.mark.parametrize("word", HYPHENATED_WORDS)
def test_a_hyphenated_word_that_ends_in_sk_is_not_an_openai_key(word):
    assert scan(f"see the {word} here") == []


@pytest.mark.parametrize(
    ("after_prefix", "found"),
    [(5, True), (33, True), (300, True), (301, False)],
    ids=["shortest", "a usual header", "longest", "too long"],
)
def test_the_first_segment_of_a_jwt_may_be_up_to_300_characters(after_prefix, found):
    # A usual header is 36 characters, 33 of them after the eyJ. The cap keeps the scan linear.
    token = "eyJ" + "a" * after_prefix + ".eyJ" + "b" * 8 + "."
    assert hits(f"see {token} here") == ([("JWT", 1, 5)] if found else [])


def test_a_pgp_armor_header_is_a_private_key():
    private = "-----BEGIN " + "PGP PRIVATE KEY BLOCK" + "-----"
    public = "-----BEGIN " + "PGP PUBLIC KEY BLOCK" + "-----"
    cut_short = "-----BEGIN " + "PGP PRIVATE KEY BLOCKS" + "-----"
    no_space = "-----BEGIN " + "PGP PRIVATE KEYBLOCK" + "-----"
    assert hits(f"see {private} here") == [("private key", 1, 5)]
    assert scan(f"see {public} here") == []
    assert scan(f"see {cut_short} here") == []
    assert scan(f"see {no_space} here") == []


# A made-up value of the shortest length that counts, and a longer one.
SHORT = "Zq7f"
LONG = SHORT + "L2mA"

KEYWORDS = ["password", "secret", "token", "api_key", "api-key", "apikey"]

PASSWORD_HITS = [
    # (text, column where the keyword starts)
    (assignment("password", ": ", LONG), 1),
    (assignment("PASSWORD", "=", LONG), 1),
    (assignment("Secret", " : "), 1),
    (assignment("token", ": ", SHORT + "1234", quote='"'), 2),
    (assignment("api_key", " = ", quote="'"), 2),
    (assignment("api-key"), 1),
    (assignment("APIKEY", "="), 1),
    (assignment("client_secret", ":"), 1),
    (assignment("X-Password"), 3),
    ("set the " + assignment("secret", " = ") + " now", 9),
    # An identifier prefix that ends in _, - or . does not hide the keyword.
    (assignment("db_password", "="), 4),
    (assignment("x-api-key"), 3),
    (assignment("aws.secret", "="), 5),
    (assignment("GITHUB_TOKEN", "="), 8),
    (assignment("max_token", ": ", "4096"), 5),  # a false alarm, and the price of that rule
]
PASSWORD_MISSES = [
    "max_tokens: 5000",  # the keyword must be followed by : or =, and here comes an s
    assignment("mytoken"),  # a letter in front
    assignment("2token", "="),  # a digit in front
    assignment("passwords"),
    assignment("password", " "),  # neither : nor =
    "password:",
    assignment("password", ": ", "Zq7"),  # three characters are too few
    assignment("password", ": ", '"Zq"'),
    "password = ",
    "token-based: yes",
    assignment("password is"),
    "secret santa",
    "the token\n" + SHORT,
]


@pytest.mark.parametrize(("text", "column"), PASSWORD_HITS)
def test_a_keyword_followed_by_a_value_is_a_credential(text, column):
    assert hits(text) == [(PASSWORD, 1, column)]


@pytest.mark.parametrize("text", PASSWORD_MISSES)
def test_a_keyword_without_a_usable_value_is_not_a_credential(text):
    assert scan(text) == []


@pytest.mark.parametrize("prefix", ["db_", "x-", "aws.", "my_app_", "a.b-c_"])
@pytest.mark.parametrize("keyword", [*KEYWORDS, "client_secret", "client-secret"])
def test_an_identifier_prefix_ending_in_a_separator_does_not_hide_the_keyword(prefix, keyword):
    assert hits(assignment(prefix + keyword, "=")) == [(PASSWORD, 1, len(prefix) + 1)]


@pytest.mark.parametrize("prefix", ["a", "Z", "7", "ab_c", "x_9"])
@pytest.mark.parametrize("keyword", KEYWORDS)
def test_a_letter_or_digit_directly_in_front_hides_the_keyword(prefix, keyword):
    assert scan(assignment(prefix + keyword, "=")) == []


def test_every_keyword_is_found_in_every_case():
    for keyword in KEYWORDS:
        for spelled in (keyword, keyword.upper(), keyword.capitalize()):
            assert hits(assignment(spelled)) == [(PASSWORD, 1, 1)], spelled
    for keyword in ("client_secret", "client-secret"):
        assert hits(assignment(keyword, "=")) == [(PASSWORD, 1, 1)], keyword


def test_two_keywords_on_one_line_are_two_hits():
    text = assignment("password") + " and " + assignment("token", "=")
    assert hits(text) == [(PASSWORD, 1, 1), (PASSWORD, 1, 20)]


# --- E-BANK-DETAILS: IBAN


def test_an_iban_is_found_compact_grouped_and_in_lower_case():
    iban = gen.valid_iban()
    forms = [iban, grouped(iban), iban.lower(), grouped(iban).lower(), iban[:2].lower() + iban[2:]]
    for form in forms:
        assert hits(f"pay to {form} please") == [("IBAN", 1, 8)], form
        assert hits(form) == [("IBAN", 1, 1)], form
        assert hits(f"({form}).") == [("IBAN", 1, 2)], form
        assert hits(f"{form} ") == [("IBAN", 1, 1)], form


def test_a_grouped_iban_is_found_when_words_follow():
    iban = gen.valid_iban()
    assert hits(f"{grouped(iban)} and then more words") == [("IBAN", 1, 1)]
    assert hits(f"{grouped(iban)} 12 and 34") == [("IBAN", 1, 1)]


def test_an_iban_inside_a_longer_word_is_not_found():
    iban = gen.valid_iban()
    suffix = next(char for char in "x7yz8" if mod97_remainder(iban + char) != 1)
    assert hits(f"x{iban}") == []  # a letter in front
    assert hits(f"7{iban}") == []  # a digit in front
    assert hits(f"{iban}{suffix}") == []  # a letter or digit behind


def test_a_wrong_checksum_is_not_an_iban():
    # Nothing follows the value but a dot: a following word would extend the candidate, and the
    # longer candidate passes mod 97 by chance one time in 97.
    iban = gen.valid_iban()
    for position in range(2, len(iban)):
        if iban[position].isdigit():
            for digit in string.digits.replace(iban[position], ""):
                wrong = iban[:position] + digit + iban[position + 1 :]
                assert scan(f"x {wrong}.") == [], wrong


@pytest.mark.parametrize("length", [14, 15, 34, 35])
def test_an_iban_has_15_to_34_letters_and_digits(length):
    value = gen.valid_iban_of_length(length)
    expected = [("IBAN", 1, 5)] if 15 <= length <= 34 else []
    assert hits(f"see {value}.") == expected


@pytest.mark.parametrize("head", ["AB1C", "A1BC", "1ABC", "ABCD", "1234"])
def test_an_iban_starts_with_two_letters_and_two_digits(head):
    value = gen.valid_mod97(head, 18)
    assert mod97_remainder(value) == 1
    assert scan(f"see {value}.") == []


def test_only_a_single_space_may_separate_the_groups():
    iban = gen.valid_iban()
    assert scan(grouped(iban).replace(" ", "  ", 1)) == []
    assert scan(grouped(iban, "-")) == []
    assert scan(grouped(iban, "\t")) == []


# --- E-BANK-DETAILS: card number


@pytest.mark.parametrize("separator", ["", " ", "-"], ids=["none", "space", "dash"])
def test_a_card_number_is_found_with_or_without_separators(separator):
    card = gen.valid_card()
    assert hits(f"card {grouped(card, separator)} ok") == [("card number", 1, 6)]


def test_separators_may_be_mixed_but_not_doubled():
    card = gen.valid_card()
    mixed = f"{card[:4]}-{card[4:8]} {card[8:12]}-{card[12:]}"
    assert hits(f"card {mixed} ok") == [("card number", 1, 6)]
    assert scan(grouped(card, "  ")) == []
    assert scan(grouped(card, "--")) == []


@pytest.mark.parametrize("length", [12, 13, 16, 19, 20])
def test_a_card_number_has_13_to_19_digits(length):
    card = gen.valid_card(length)
    expected = [("card number", 1, 5)] if 13 <= length <= 19 else []
    assert hits(f"see {card} here") == expected


def test_a_wrong_luhn_digit_is_not_a_card_number():
    card = gen.valid_card()
    for position in range(len(card)):
        for digit in string.digits.replace(card[position], ""):
            wrong = card[:position] + digit + card[position + 1 :]
            assert scan(f"x {wrong} y") == [], wrong


def test_a_card_number_inside_a_longer_word_or_number_is_not_found():
    card = gen.valid_card()
    after = next(digit for digit in string.digits if not luhn_ok(card + digit))
    before = next(digit for digit in string.digits if not luhn_ok(digit + card))
    assert scan(f"x{card}") == []
    assert scan(f"{card}x") == []
    assert scan(card + after) == []
    assert scan(before + card) == []


@pytest.mark.parametrize("text", ["1234 ", "AB12 ", "1 ", "AB12 CD ", "1234 5678 ", "AB12 -"])
def test_a_separator_at_the_end_of_a_line_is_harmless(text):
    assert scan(text) == []


# --- E-ID-NUMBER: BSN


def test_a_bsn_is_found_alone_and_between_punctuation():
    bsn = gen.valid_bsn()
    for text, column in [
        (bsn, 1),
        (f"BSN {bsn}", 5),
        (f"({bsn})", 2),
        (f"{bsn}.", 1),
        (f"id:{bsn},", 4),
    ]:
        assert hits(text) == [("BSN", 1, column)], text


def test_nine_digits_that_fail_the_eleven_test_are_not_a_bsn():
    bsn = gen.valid_bsn()
    for position in range(9):
        for digit in string.digits.replace(bsn[position], ""):
            wrong = bsn[:position] + digit + bsn[position + 1 :]
            assert scan(f"x {wrong} y") == [], wrong


def test_a_bsn_must_stand_alone_and_have_exactly_nine_digits():
    bsn = gen.valid_bsn()
    assert scan(f"x{bsn}") == []
    assert scan(f"{bsn}x") == []
    assert scan(f"7{bsn}") == []
    assert scan(f"{bsn}7") == []
    assert scan(bsn[:8]) == []
    assert scan(f"{bsn[:3]} {bsn[3:6]} {bsn[6:]}") == []


def test_nine_zeros_pass_the_eleven_test_but_are_not_a_bsn():
    assert eleven_test_ok("0" * 9)
    assert scan("0" * 9) == []


# --- overlap and priority


def test_an_anthropic_key_is_not_also_an_openai_key():
    key = gen.secret_values()["Anthropic API key"][0]
    assert hits(f"key {key}") == [("Anthropic API key", 1, 5)]


def test_a_known_token_after_a_keyword_is_reported_as_that_token():
    aws = gen.secret_values()["AWS access key"][0]
    github = gen.secret_values()["GitHub token"][0]
    assert hits(f"password={aws}") == [("AWS access key", 1, 10)]
    assert hits(f'token: "{github}"') == [("GitHub token", 1, 9)]


def test_a_keyword_in_front_of_a_number_hides_only_the_number_hit():
    assert hits(f"password={gen.valid_bsn()}") == [(PASSWORD, 1, 1)]
    assert hits(f"token: {gen.valid_card()}") == [(PASSWORD, 1, 1)]
    assert hits(f"secret={gen.valid_iban()}") == [(PASSWORD, 1, 1)]


def test_the_key_name_and_the_pem_header_do_not_overlap_so_both_are_reported():
    header = gen.secret_values()["private key"][0]
    name = gen.secret_values()["service account key"][0]
    assert hits(f"{name}: {header}") == [("service account key", 1, 1), ("private key", 1, 16)]


def test_hits_that_only_touch_are_both_kept():
    header = gen.secret_values()["private key"][0]
    name = gen.secret_values()["service account key"][0]
    # The kind that is checked later may stand to the right of the first hit, or to its left.
    assert hits(f"{header}{name}") == [
        ("private key", 1, 1),
        ("service account key", 1, len(header) + 1),
    ]
    assert hits(f"{name}{header}") == [
        ("service account key", 1, 1),
        ("private key", 1, len(name) + 1),
    ]


def test_a_hit_is_dropped_only_by_a_hit_that_is_kept():
    # The keyword hit covers the whole value, so the key (earlier in the order) drops it. The card
    # overlaps only the dropped keyword hit, not the key, and stays.
    aws = gen.secret_values()["AWS access key"][0]
    card = grouped(gen.valid_card(), "-")
    assert hits(f"secret={aws}-{card}") == [("AWS access key", 1, 8), ("card number", 1, 29)]


def test_hits_that_share_one_character_are_one_hit():
    # The Google key ends in the s that starts a key of another kind. The first kind in the order
    # keeps the shared character, so the second hit is dropped.
    text = "AIza" + "-" * 34 + "s" + "k-" + "B" * 20
    assert hits(text) == [("Google API key", 1, 1)]


def test_a_card_number_and_a_token_that_share_one_digit():
    # The card number ends in a 1, and the token starts with that 1. The token comes first in the
    # order, so it keeps the 1 and the card number is dropped.
    card = gen.valid_card(13, last_digit="1")
    spaced = grouped(card)
    assert hits(spaced + "//0" + "b" * 20) == [("OAuth token", 1, len(spaced))]


def test_a_token_cannot_start_inside_a_run_of_digits():
    # With no group before the last digit, the 1 is glued to the digits and starts no token.
    card = gen.valid_card(16, last_digit="1")
    assert hits(card + "//0" + "b" * 20) == [("card number", 1, 1)]


def test_several_hits_on_one_line_are_listed_by_column():
    bsn, card, iban = gen.valid_bsn(), gen.valid_card(), gen.valid_iban()
    aws = gen.secret_values()["AWS access key"][0]
    text = f"{bsn} then {card} then {iban} then {aws}"
    assert hits(text) == [
        ("BSN", 1, 1),
        ("card number", 1, len(f"{bsn} then ") + 1),
        ("IBAN", 1, len(f"{bsn} then {card} then ") + 1),
        ("AWS access key", 1, len(f"{bsn} then {card} then {iban} then ") + 1),
    ]


def test_the_same_kind_twice_is_two_hits():
    aws = gen.secret_values()["AWS access key"][0]
    assert hits(f"{aws} {aws}\n{aws}") == [
        ("AWS access key", 1, 1),
        ("AWS access key", 1, len(aws) + 2),
        ("AWS access key", 2, 1),
    ]
    iban, other_iban = gen.valid_iban(), grouped(gen.valid_iban())
    assert hits(f"{iban} / {other_iban}") == [("IBAN", 1, 1), ("IBAN", 1, len(iban) + 4)]
    card, other_card = gen.valid_card(), grouped(gen.valid_card(), "-")
    assert hits(f"{card} / {other_card}") == [
        ("card number", 1, 1),
        ("card number", 1, len(card) + 4),
    ]
    # Not separated by a bare space: two numbers of 9 digits would be one candidate card number.
    bsn, other_bsn = gen.valid_bsn(), gen.valid_bsn()
    assert hits(f"{bsn} / {other_bsn}") == [("BSN", 1, 1), ("BSN", 1, 13)]


# --- positions


def test_lines_are_split_on_lf_only():
    aws = gen.secret_values()["AWS access key"][0]
    assert hits(f"a\rb\x0bc\u2028d\x85e\n{aws}") == [("AWS access key", 2, 1)]


def test_columns_count_code_points():
    aws = gen.secret_values()["AWS access key"][0]
    assert hits(f"\u20ac\U0001f600\u00e9 {aws}") == [("AWS access key", 1, 5)]


def test_a_cr_before_the_lf_does_not_hide_the_last_word_of_a_line():
    assert hits(assignment("password") + "\r\nnext\r\n") == [(PASSWORD, 1, 1)]
    bsn = gen.valid_bsn()
    assert hits(f"{bsn}\r\n") == [("BSN", 1, 1)]


# --- time stays linear on hostile input
#
# A pattern that rescans a long run from every start inside it takes minutes on lines like these;
# a linear scan takes a fraction of a second. The scan also runs on what agents write (M4, M6).

HOSTILE = {
    "many JWT starts in one run": lambda: "eyJ" * 70_000,
    "JWT starts after underscores": lambda: "eyJ_" * 50_000,
    "JWT starts after hyphens, then a long run": lambda: "eyJ-" * 75 + ".eyJ" + "a" * 200_000,
    "JWT segments back to back": lambda: ("eyJ" + "aaaaa.") * 25_000,
    "PEM header and a long run": lambda: "-----BEGIN " + "A" * 200_000,
    "many PEM headers": lambda: "-----BEGIN " * 20_000,
    "a PEM header that repeats its own words": lambda: "-----BEGIN " + "PRIVATE KEY " * 20_000,
    "keyword and a long run of spaces": lambda: "password" + " " * 200_000,
    "keyword, colon, spaces and a quote": lambda: "password:" + " " * 200_000 + '"',
    "many keywords": lambda: "password " * 20_000,
    "keywords behind identifier prefixes": lambda: "token_" * 40_000,
    "keywords behind dots and hyphens": lambda: "secret.api-key." * 15_000,
    "key prefixes back to back": lambda: "sk-" * 70_000,
    "key prefixes glued to letters": lambda: "xAKIA" * 40_000,
    "token prefixes": lambda: "ghp_" * 50_000,
    "a long digit run": lambda: "1" * 200_000,
    "digits with separators": lambda: "1 " * 12_000,
    "IBAN-like words": lambda: "AA11 " * 6_000,
    "a long letter run": lambda: "a" * 200_000,
    "a long dash run": lambda: "-" * 200_000,
    "many short lines": lambda: "x\n" * 40_000,
}


@pytest.mark.parametrize("make_text", HOSTILE.values(), ids=HOSTILE)
def test_scan_finishes_quickly_on_hostile_input(make_text):
    text = make_text()
    started = time.perf_counter()
    scan(text)
    # Generous: a linear scan takes a fraction of a second, a quadratic one minutes.
    assert time.perf_counter() - started < 5
