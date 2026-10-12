"""The generators of tests/support/gen.py: every value they make is valid, by independent checks."""

import re

import pytest

from aiven.policy.content import KIND_CODES
from tests.support import gen
from tests.support.checksums import eleven_test_ok, luhn_ok, mod97_remainder


def test_a_generated_iban_has_the_nl_shape_and_passes_mod_97():
    for _ in range(100):
        iban = gen.valid_iban()
        assert re.fullmatch(r"NL[0-9]{2}[A-Z]{4}[0-9]{10}", iban)
        assert mod97_remainder(iban) == 1


def test_an_iban_of_another_country_is_refused():
    with pytest.raises(ValueError, match="NL"):
        gen.valid_iban("DE")


@pytest.mark.parametrize("length", [15, 18, 34])
def test_a_generated_iban_of_a_given_length_passes_mod_97(length):
    for _ in range(20):
        value = gen.valid_iban_of_length(length)
        assert len(value) == length
        assert re.fullmatch(r"NL[0-9]{2}[A-Z0-9]+", value)
        assert mod97_remainder(value) == 1


@pytest.mark.parametrize("head", ["AB1C", "1234", "NL00"])
def test_a_generated_mod_97_string_starts_with_its_head(head):
    for _ in range(20):
        value = gen.valid_mod97(head, 20)
        assert value.startswith(head)
        assert re.fullmatch(r"[A-Z0-9]{20}", value)
        assert mod97_remainder(value) == 1


def test_a_mod_97_string_needs_room_after_its_head():
    with pytest.raises(ValueError, match="at least 4"):
        gen.valid_mod97("AB12", 7)
    assert len(gen.valid_mod97("AB12", 8)) == 8


@pytest.mark.parametrize("length", [13, 16, 19])
def test_a_generated_card_number_passes_luhn(length):
    for _ in range(100):
        card = gen.valid_card(length)
        assert re.fullmatch(r"[1-9][0-9]*", card) and len(card) == length
        assert luhn_ok(card)


@pytest.mark.parametrize("digit", ["0", "1", "9"])
def test_a_card_number_can_be_asked_to_end_in_a_digit(digit):
    for length in (13, 16):
        card = gen.valid_card(length, last_digit=digit)
        assert len(card) == length
        assert card.endswith(digit)
        assert luhn_ok(card)


@pytest.mark.parametrize("last_digit", ["x", "12", " "])
def test_the_last_digit_of_a_card_number_must_be_one_digit(last_digit):
    with pytest.raises(ValueError, match="digit"):
        gen.valid_card(last_digit=last_digit)


def test_a_generated_bsn_passes_the_eleven_test():
    for _ in range(200):
        bsn = gen.valid_bsn()
        assert re.fullmatch(r"[1-9][0-9]{8}", bsn)
        assert eleven_test_ok(bsn)


def test_generated_values_differ_from_call_to_call():
    assert len({gen.valid_iban() for _ in range(20)}) > 1
    assert len({gen.valid_card() for _ in range(20)}) > 1
    assert len({gen.valid_bsn() for _ in range(20)}) > 1


def test_every_secret_kind_has_a_sample_and_no_other_kind_does():
    secret_kinds = [kind for kind, code in KIND_CODES.items() if code == "E-SECRET"]
    assert list(gen.secret_values()) == secret_kinds


def test_grouped_cuts_a_value_into_groups():
    assert gen.grouped("abcdefghij") == "abcd efgh ij"
    assert gen.grouped("abcdefghij", "-", 3) == "abc-def-ghi-j"
    assert gen.grouped("abc") == "abc"


def test_an_assignment_joins_its_parts_and_can_quote_them():
    assert gen.assignment("key", "=", "value") == "key=value"
    assert gen.assignment("key") == "key: Zq7f"
    assert gen.assignment("key", ": ", "value", quote='"') == '"key": "value"'
    assert gen.assignment("key", " = ", "value", quote="'") == "'key' = 'value'"
