"""The guard (validator-spec section 1: never print sensitive values, one finding per line).

`safe_text` and `escape_unprintable` (content.py) are the single place where text from a file
enters a message, and `Finding` runs every param and its path through them. So no check can put a
credential, a bank detail, an ID number or a newline into the output by mistake.
"""

import dataclasses
import json
import time
from dataclasses import replace

import pytest

from aiven.policy.content import escape_unprintable, safe_text
from aiven.policy.findings import Finding, format_line, message
from tests.support import gen
from tests.support.gen import grouped

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
def test_cleaning_twice_changes_nothing(text):
    once = safe_text(text)
    assert safe_text(once) == once
    assert escape_unprintable(escape_unprintable(text)) == escape_unprintable(text)


HOSTILE = {
    "many JWT starts in one run": "eyJ" * 70_000,
    "a long text": "x" * 1_000_000,
    "digits with separators": "1 " * 12_000,
    "many unprintable characters": "\n" * 40_000,
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


def test_cleaning_a_finding_again_changes_nothing():
    finding = Finding("E-INTERNAL", "error", "a\nb.md", 2, 3, {"detail": "p\nq" * 300})
    assert replace(finding) == finding
    assert hash(replace(finding)) == hash(finding)
    again = Finding(
        finding.code, finding.severity, finding.path, finding.line, finding.column, finding.params
    )
    assert again == finding
