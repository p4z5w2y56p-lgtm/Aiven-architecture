"""The guard (validator-spec section 1: never print sensitive values, one finding per line).

`safe_text` and `escape_unprintable` (content.py) are the single place where text from a file
enters a message, and `Finding` runs every param and its path through them. So no check can put a
credential, a bank detail, an ID number or a newline into the output by mistake.
"""

import dataclasses
import json
import random
import string
import time
from dataclasses import replace

import pytest

from aiven.policy.content import escape_unprintable, is_sensitive, safe_text
from aiven.policy.findings import Finding, format_line, message
from tests.support import gen
from tests.support.characters import HIDDEN_CHARACTERS, VISIBLE_CHARACTERS
from tests.support.gen import grouped
from tests.support.policies import AGENTS_PROJECT, FOLDER_ID

ELLIPSIS = "\N{HORIZONTAL ELLIPSIS}"
HIDDEN = "[hidden]"

# Characters that are not printable, and how the guard writes them.
UNPRINTABLE = {
    "newline": ("\n", "\\u000a"),
    "carriage return": ("\r", "\\u000d"),
    "tab": ("\t", "\\u0009"),
    "escape": ("\x1b", "\\u001b"),
    "delete": ("\x7f", "\\u007f"),
    "next line": ("\x85", "\\u0085"),
    "no-break space": ("\xa0", "\\u00a0"),
    "zero width space": ("\U0000200b", "\\u200b"),
    "right-to-left override": ("\U0000202e", "\\u202e"),
    "line separator": ("\U00002028", "\\u2028"),
    "byte-order mark": ("\U0000feff", "\\ufeff"),
    "last code point of four digits": ("\U0000ffff", "\\uffff"),
    "tag letter": ("\U000e0041", "\\U000e0041"),
    "last code point": ("\U0010ffff", "\\U0010ffff"),
}

PRINTABLE = [
    "",
    "plain text",
    "REPLACE_ME_FOLDER_ID",
    "{braces} and a \\ backslash",
    "caf\xe9",
    "\U000020ac 5",
    "\U00004e2d",
    "\U0001f600",
]


def sensitive_values() -> dict[str, str]:
    """Every kind of value that `scan` flags, by a label for the test id."""
    values = {
        f"{kind} {number}": value
        for kind, kind_values in gen.secret_values().items()
        for number, value in enumerate(kind_values, start=1)
    }
    iban, card = gen.valid_iban(), gen.valid_card()
    values |= {
        "IBAN": iban,
        "IBAN in groups": grouped(iban),
        "card number": card,
        "card number with dashes": grouped(card, "-"),
        "BSN": gen.valid_bsn(),
    }
    return values


SENSITIVE = sensitive_values()


# --- escape_unprintable and safe_text


@pytest.mark.parametrize(("char", "shown"), UNPRINTABLE.values(), ids=UNPRINTABLE)
def test_an_unprintable_character_is_written_as_an_escape(char, shown):
    assert escape_unprintable(f"a{char}b") == f"a{shown}b"
    assert safe_text(f"a{char}b") == f"a{shown}b"


@pytest.mark.parametrize("text", PRINTABLE)
def test_printable_text_is_left_alone(text):
    assert escape_unprintable(text) == text
    assert safe_text(text) == text


@pytest.mark.parametrize("value", SENSITIVE.values(), ids=SENSITIVE)
def test_a_value_that_scan_flags_is_replaced_by_a_marker(value):
    assert safe_text(value) == HIDDEN
    assert safe_text(f"before {value} after") == HIDDEN
    assert safe_text(f"an earlier line\n{value}") == HIDDEN
    assert safe_text("x" * 500 + " " + value) == HIDDEN  # even beyond what would be shown


def test_escape_unprintable_neither_hides_nor_cuts():
    iban = gen.valid_iban()
    assert escape_unprintable(iban) == iban
    assert escape_unprintable("x" * 1000) == "x" * 1000


def test_a_long_value_is_cut_to_200_characters_ending_in_an_ellipsis():
    assert safe_text("x" * 1000) == "x" * 199 + ELLIPSIS
    assert safe_text("x" * 201) == "x" * 199 + ELLIPSIS
    assert safe_text("x" * 200) == "x" * 200
    assert safe_text("x" * 199) == "x" * 199


def test_escapes_count_toward_the_cut():
    assert safe_text("\n" * 100) == ("\\u000a" * 100)[:199] + ELLIPSIS


@pytest.mark.parametrize(
    "text",
    [char for char, _ in UNPRINTABLE.values()] + PRINTABLE + ["x" * 1000, "\n" * 100, HIDDEN],
)
def test_cleaning_twice_changes_nothing_for_ordinary_text(text):
    once = safe_text(text)
    assert safe_text(once) == once
    assert escape_unprintable(escape_unprintable(text)) == escape_unprintable(text)


def test_cleaning_again_can_hide_more_but_never_shows_more():
    # An escape ends in hex digits, and digits next to them can make a window that passes a
    # checksum: this private-use character and a 7 read, once escaped, as a nine-digit number
    # that passes the eleven-test. The expected text is joined from parts, like every number here.
    value = "\U00100000" + "7"
    assert safe_text(value) == "\\U" + "00100000" + "7"
    assert safe_text(safe_text(value)) == HIDDEN
    rng = random.Random(3)
    alphabet = [
        "a",
        "Z",
        "7",
        "0",
        "9",
        " ",
        "-",
        "_",
        "\n",
        "\x00",
        "\U0000200b",
        "\U000f0000",
        "NL",
        "91",
    ]
    for _ in range(3000):
        once = safe_text("".join(rng.choices(alphabet, k=rng.randint(0, 30))))
        assert safe_text(once) in (once, HIDDEN)


# --- the guard is more suspicious than scan: it also hides a value glued to a word

BEFORE_A_VALUE = {
    "REPLACE_ME": "REPLACE_ME",
    "REPLACE_ME_X": "REPLACE_ME_X",
    "a letter": "x",
    "a digit": "7",
    "a word and an underscore": "abc_",
}
AFTER_A_VALUE = {"a letter": "x", "a digit": "7", "letters": "xyz"}
STAY_VISIBLE = {
    "the test folder ID": FOLDER_ID,
    "a placeholder": "REPLACE_ME_AGENTS_PROJECT",
    "another placeholder": "REPLACE_ME_FOLDER_ID",
    "a service account": f"agent-invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.com",
    "a folder path": "AIVEN Architecture Sandbox / Invoices",
    "an action": "gmail.send_bulk",
    "an invoice number": "INV-2026-0042",
    "a version": "12",
    "a code point": "U+200B",
    "a column": "123",
    "a file size": "65537",
    "an email domain": "@aivenstudios.com",
}


@pytest.mark.parametrize("value", SENSITIVE.values(), ids=SENSITIVE)
@pytest.mark.parametrize("before", BEFORE_A_VALUE.values(), ids=BEFORE_A_VALUE)
def test_a_value_glued_to_a_word_in_front_is_hidden(value, before):
    assert safe_text(before + value) == HIDDEN


@pytest.mark.parametrize("value", SENSITIVE.values(), ids=SENSITIVE)
@pytest.mark.parametrize("after", AFTER_A_VALUE.values(), ids=AFTER_A_VALUE)
def test_a_value_with_word_characters_behind_it_is_hidden(value, after):
    assert safe_text(value + after) == HIDDEN


def test_a_run_of_digits_is_hidden_when_a_window_of_it_is_a_bsn_or_a_card_number():
    bsn, card = gen.valid_bsn(), gen.valid_card()
    assert safe_text("5" + bsn + "5") == HIDDEN  # a window of nine
    assert safe_text("5" + card + "5") == HIDDEN  # a window of sixteen


@pytest.mark.parametrize("value", STAY_VISIBLE.values(), ids=STAY_VISIBLE)
def test_ordinary_values_stay_visible(value):
    assert safe_text(value) == value


# --- is_sensitive: the check that safe_text uses, for checks that quote a part of a longer word


@pytest.mark.parametrize("value", [*SENSITIVE.values(), *STAY_VISIBLE.values(), *PRINTABLE])
def test_is_sensitive_is_what_safe_text_hides(value):
    assert is_sensitive(value) == (safe_text(value) == HIDDEN)


@pytest.mark.parametrize("value", SENSITIVE.values(), ids=SENSITIVE)
@pytest.mark.parametrize("before", ["", *BEFORE_A_VALUE.values()])
def test_is_sensitive_sees_a_value_glued_to_a_word(value, before):
    assert is_sensitive(before + value)
    assert is_sensitive(value + "7")


def test_is_sensitive_is_false_for_the_words_of_the_template():
    words = [
        "agent-invoice-reminder@REPLACE_ME_AGENTS_PROJECT.iam.gserviceaccount.com",
        "`agent-invoice-reminder@REPLACE_ME_AGENTS_PROJECT.iam.gserviceaccount.com`.",
        "REPLACE_ME_FOLDER_ID",
        "`REPLACE_ME_FOLDER_ID`)",
    ]
    assert not any(is_sensitive(word) for word in words)


def test_the_placeholder_and_the_folder_id_stay_visible_in_findings():
    placeholder = Finding(
        "E-PLACEHOLDER", "error", "a.md", 6, 38, {"token": "REPLACE_ME_AGENTS_PROJECT"}
    )
    assert placeholder.params == {"token": "REPLACE_ME_AGENTS_PROJECT"}
    scope = {"id": FOLDER_ID, "path": "AIVEN Architecture Sandbox / Invoices"}
    assert Finding("E-SCOPE-NOT-IN-SANDBOX", "error", "a.md", 25, 5, scope).params == scope


def test_the_guard_uses_the_real_checksums():
    bsn = gen.valid_bsn()
    one_digit_off = bsn[:-1] + str((int(bsn[-1]) + 1) % 10)
    assert safe_text("REPLACE_ME" + bsn) == HIDDEN
    assert safe_text("REPLACE_ME" + one_digit_off) == "REPLACE_ME" + one_digit_off


def test_random_ids_and_invoice_numbers_are_not_hidden_wholesale():
    rng = random.Random(7)
    alphabet = string.ascii_letters + string.digits + "_-"
    ids = ["1" + "".join(rng.choices(alphabet, k=32)) for _ in range(2000)]
    invoices = [f"INV-{rng.randint(2020, 2030)}-{rng.randint(0, 9999):04d}" for _ in range(2000)]
    assert sum(safe_text(value) == HIDDEN for value in ids) < 0.1 * len(ids)  # about 1.5 percent
    assert sum(safe_text(value) == HIDDEN for value in invoices) == 0


# --- the hidden characters of the spec (section 3.1) that str.isprintable() lets through

INVISIBLE_BUT_PRINTABLE = {
    "combining grapheme joiner": ("\U0000034f", "\\u034f"),
    "hangul choseong filler": ("\U0000115f", "\\u115f"),
    "hangul jungseong filler": ("\U00001160", "\\u1160"),
    "hangul filler": ("\U00003164", "\\u3164"),
    "halfwidth hangul filler": ("\U0000ffa0", "\\uffa0"),
    "variation selector 1": ("\U0000fe00", "\\ufe00"),
    "variation selector 16": ("\U0000fe0f", "\\ufe0f"),
    "variation selector 17": ("\U000e0100", "\\U000e0100"),
    "variation selector 256": ("\U000e01ef", "\\U000e01ef"),
}
VISIBLE_AND_PRINTABLE = {
    name: char for name, char in VISIBLE_CHARACTERS.items() if char.isprintable()
}


@pytest.mark.parametrize(
    "char", [char for char, _ in INVISIBLE_BUT_PRINTABLE.values()], ids=INVISIBLE_BUT_PRINTABLE
)
def test_python_calls_these_hidden_characters_printable(char):
    # This is why escaping what is not printable is not enough.
    assert char.isprintable()


@pytest.mark.parametrize(
    ("char", "shown"), INVISIBLE_BUT_PRINTABLE.values(), ids=INVISIBLE_BUT_PRINTABLE
)
def test_a_hidden_character_that_python_calls_printable_is_escaped(char, shown):
    assert escape_unprintable(f"a{char}b") == f"a{shown}b"
    assert safe_text(f"a{char}b") == f"a{shown}b"


@pytest.mark.parametrize("char", HIDDEN_CHARACTERS.values(), ids=HIDDEN_CHARACTERS)
def test_every_hidden_character_of_the_spec_is_escaped(char):
    shown = escape_unprintable(f"a{char}b")
    assert char not in shown
    assert shown.isascii()


@pytest.mark.parametrize("char", VISIBLE_AND_PRINTABLE.values(), ids=VISIBLE_AND_PRINTABLE)
def test_a_visible_character_is_left_alone(char):
    assert escape_unprintable(f"a{char}b") == f"a{char}b"


HOSTILE = {
    "many JWT starts in one run": "eyJ" * 70_000,
    "JWT starts after underscores": "eyJ_" * 50_000,
    "key prefixes back to back": "sk-" * 70_000,
    "keywords behind identifier prefixes": "token_" * 40_000,
    "a long text": "x" * 1_000_000,
    "a long digit run": "1" * 10_000,
    "digits with separators": "1 " * 6_000,
    "a compact IBAN-like run": "AB12" * 3_000,
    "IBAN-like words": "AB12 " * 2_500,
    "many unprintable characters": "\n" * 40_000,
    "many invisible but printable characters": "\U0000fe0f" * 100_000,
}


@pytest.mark.parametrize("value", HOSTILE.values(), ids=HOSTILE)
def test_safe_text_finishes_quickly_on_hostile_input(value):
    started = time.perf_counter()
    safe_text(value)
    assert time.perf_counter() - started < 5  # generous: it takes a fraction of a second


# --- Finding runs its params and its path through them


def test_a_newline_or_bidi_control_in_a_param_cannot_forge_a_line():
    finding = Finding(
        "E-INTERNAL", "error", "a.md", params={"detail": "x\nerror E-FORGED y.md: z\U0000202e"}
    )
    assert finding.params == {"detail": "x\\u000aerror E-FORGED y.md: z\\u202e"}
    for text in (format_line(finding), message(finding, "en"), message(finding, "nl")):
        assert text.splitlines() == [text]


def test_hidden_characters_in_a_param_and_a_path_come_out_escaped():
    finding = Finding(
        "E-INTERNAL", "error", "dir/a\U00003164b.md", params={"detail": "x\U00003164y\U0000fe0fz"}
    )
    assert finding.params == {"detail": "x\\u3164y\\ufe0fz"}
    assert finding.path == "dir/a\\u3164b.md"


def test_a_long_param_is_cut_to_200_characters():
    finding = Finding("E-INTERNAL", "error", "a.md", params={"detail": "y" * 1000})
    assert finding.params == {"detail": "y" * 199 + ELLIPSIS}


@pytest.mark.parametrize("value", SENSITIVE.values(), ids=SENSITIVE)
def test_a_param_that_holds_a_sensitive_value_is_hidden(value):
    finding = Finding("E-PLACEHOLDER", "error", "a.md", 1, 1, {"token": f"REPLACE_ME_{value}"})
    assert finding.params == {"token": HIDDEN}
    shown = [
        format_line(finding),
        message(finding, "en"),
        message(finding, "nl"),
        json.dumps(dataclasses.asdict(finding)),
    ]
    assert all(value not in text for text in shown)


def test_only_the_params_that_need_it_are_changed():
    finding = Finding(
        "E-RANGE", "error", "a.md", 3, 5, {"field": "version", "value": gen.valid_bsn(), "min": "1"}
    )
    assert finding.params == {"field": "version", "value": HIDDEN, "min": "1"}


def test_a_path_is_escaped_but_neither_hidden_nor_cut():
    name = "x" * 300
    finding = Finding("E-FINAL-NEWLINE", "error", "policies/a\nb\U0000202e" + name + ".md")
    assert finding.path == "policies/a\\u000ab\\u202e" + name + ".md"
    assert format_line(finding).splitlines() == [format_line(finding)]

    iban = gen.valid_iban()
    assert Finding("E-FINAL-NEWLINE", "error", f"policies/{iban}.md").path == f"policies/{iban}.md"


def test_a_param_changed_after_the_finding_was_made_is_cleaned_when_it_is_shown():
    # The dict of params is not frozen, so the guard in __post_init__ is not the last word: a
    # message cleans every param again as it fills it in.
    iban = gen.valid_iban()
    finding = Finding("E-PLACEHOLDER", "error", "a.md", 1, 1, {"token": "REPLACE_ME_X"})
    finding.params["token"] = iban + "\nerror E-FORGED y.md: z"
    for text in (format_line(finding), message(finding, "en"), message(finding, "nl")):
        assert iban not in text
        assert text.splitlines() == [text]
    assert (
        message(finding, "en") == "Placeholder [hidden] is still there. Fill it in before signing."
    )

    finding.params["token"] = "x\ny\U00003164" + "z" * 300  # escaped, then cut to 200
    cleaned = ("x\\u000ay\\u3164" + "z" * 300)[:199] + ELLIPSIS
    assert (
        message(finding, "en")
        == f"Placeholder {cleaned} is still there. Fill it in before signing."
    )


def test_cleaning_a_finding_again_changes_nothing():
    finding = Finding("E-INTERNAL", "error", "a\nb.md", 2, 3, {"detail": "p\nq" * 300})
    assert replace(finding) == finding
    assert hash(replace(finding)) == hash(finding)
    again = Finding(
        finding.code, finding.severity, finding.path, finding.line, finding.column, finding.params
    )
    assert again == finding
