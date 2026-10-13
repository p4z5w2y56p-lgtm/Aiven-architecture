"""The hidden-character predicate (validator-spec section 3.1), used by the check and the guard."""

import pytest

from aiven.policy.chars import is_hidden
from tests.support.characters import HIDDEN_CHARACTERS, VISIBLE_CHARACTERS


@pytest.mark.parametrize("char", HIDDEN_CHARACTERS.values(), ids=HIDDEN_CHARACTERS)
def test_a_hidden_character_is_hidden(char):
    assert is_hidden(char)


@pytest.mark.parametrize("char", VISIBLE_CHARACTERS.values(), ids=VISIBLE_CHARACTERS)
def test_a_visible_character_is_not_hidden(char):
    assert not is_hidden(char)


def test_lf_and_the_normal_space_are_not_hidden():
    assert not is_hidden("\n")
    assert not is_hidden(" ")


def test_cr_is_hidden_by_the_definition():
    # The spec says Cc except LF, so CR is in the set. The E-HIDDEN-CHAR check leaves it to
    # E-LINE-ENDINGS (one defect, one code); that choice is the check's, not the definition's.
    assert is_hidden("\r")


def test_printable_ascii_is_never_hidden():
    # The guard skips the per-character test for text that is ASCII and printable.
    assert not any(is_hidden(chr(code)) for code in range(0x20, 0x7F))
