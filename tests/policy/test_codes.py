"""One table for the codes of every check: a mutated valid policy yields exactly one new finding.

Each case is (code, mutation, expected_line). The mutation edits the bytes of `valid_base()`. The
validator must then report exactly one finding that the base does not have, with that code on that
line (None for a finding about the whole file). Findings that disappear are ignored, and the base
may carry warnings (later checks add W-TOOL-NOT-LIVE), so the full list is never compared.

Rules for a mutation:
- Edit text inside one free-text line of the body (Purpose, Why each tool, Data and risks). Never
  touch the front matter or the two generated sections, and never add or remove a line. The
  exceptions are the BOM at the very start and the cases about the end of the file.
- Use no URLs, links or HTML: later body checks reject them.
- Find the target line by content (`line_of`), not by number.
"""

import codecs
import dataclasses
import json
import re
from collections import Counter
from collections.abc import Callable

import pytest

from aiven.policy.catalog import load_catalog
from aiven.policy.config import load_platform_config
from aiven.policy.fileformat import decode_text
from aiven.policy.findings import Finding, format_line, message
from aiven.policy.validate import validate_file
from tests.support import REPO_ROOT, gen
from tests.support.gen import grouped
from tests.support.policies import BASE_PATH, line_of, valid_base

CFG = load_platform_config(REPO_ROOT / "config" / "platform.example.yaml")
CATALOG = load_catalog(REPO_ROOT / "catalog" / "catalog-v1.yaml")

BASE = valid_base()
BASE_TEXT = BASE.decode("utf-8")

# Text that occurs once in the base, on a free-text line.
PURPOSE = "Once a day, this agent reads"
PURPOSE_END = "no email goes to clients."
READS = "Reads: only the tracker columns listed above."
WHY_DRAFT = "writes one internal reminder draft"
RISKS_WRITES = "Writes: internal reminder drafts in the agent mailbox."

PURPOSE_LINE = line_of(BASE_TEXT, PURPOSE)
READS_LINE = line_of(BASE_TEXT, READS)
WHY_LINE = line_of(BASE_TEXT, WHY_DRAFT)
RISKS_LINE = line_of(BASE_TEXT, RISKS_WRITES)

Mutation = Callable[[bytes], bytes]


def insert_after(anchor: str, payload: str | bytes) -> Mutation:
    """Insert `payload` right behind the one place where `anchor` occurs. No line is added."""

    def mutate(data: bytes) -> bytes:
        marker = anchor.encode("utf-8")
        assert data.count(marker) == 1, f"{anchor!r} must occur exactly once"
        raw = payload.encode("utf-8") if isinstance(payload, str) else payload
        assert b"\n" not in raw
        return data.replace(marker, marker + raw, 1)

    return mutate


def grow_to(size: int, anchor: str) -> Mutation:
    """Pad the line of `anchor` with filler until the file is `size` bytes."""
    return lambda data: insert_after(anchor, "x" * (size - len(data)))(data)


def findings_of(data: bytes) -> list[Finding]:
    return validate_file(BASE_PATH, data, CFG, CATALOG)


def new_findings(data: bytes) -> list[Finding]:
    """What `data` reports and the valid base does not: the multiset difference, in report order."""
    return list((Counter(findings_of(data)) - Counter(findings_of(BASE))).elements())


def case(code: str, label: str, mutation: Mutation, line: int | None):
    return pytest.param(code, mutation, line, id=f"{code} {label}")


def content_samples() -> list[tuple[str, str, str, str]]:
    """(code, kind, label, value) for each kind of content that must be refused."""
    samples = [
        ("E-SECRET", kind, f"{kind} {number}", value)
        for kind, values in gen.secret_values().items()
        for number, value in enumerate(values, start=1)
    ]
    iban, card = gen.valid_iban(), gen.valid_card()
    samples += [
        ("E-BANK-DETAILS", "IBAN", "IBAN", iban),
        ("E-BANK-DETAILS", "IBAN", "IBAN in groups", grouped(iban)),
        ("E-BANK-DETAILS", "IBAN", "IBAN in lower case", iban.lower()),
        ("E-BANK-DETAILS", "card number", "card number", card),
        ("E-BANK-DETAILS", "card number", "card number in groups", grouped(card)),
        ("E-BANK-DETAILS", "card number", "card number with dashes", grouped(card, "-")),
        ("E-ID-NUMBER", "BSN", "BSN", gen.valid_bsn()),
    ]
    return samples


CONTENT_SAMPLES = content_samples()

# Task 1.2: the file checks (validator-spec 3.1) and content safety (3.8). E-FILENAME is checked
# with the front matter, in Task 1.3.
CASES = [
    case("E-ENCODING", "byte-order mark", lambda data: codecs.BOM_UTF8 + data, 1),
    case("E-ENCODING", "invalid byte", insert_after(PURPOSE, b"\xff"), PURPOSE_LINE),
    case("E-LINE-ENDINGS", "CR before the LF", insert_after(PURPOSE_END, "\r"), PURPOSE_LINE),
    case("E-FINAL-NEWLINE", "no newline", lambda data: data.rstrip(b"\n"), None),
    case("E-FINAL-NEWLINE", "two newlines", lambda data: data + b"\n", None),
    case("E-FILE-SIZE", "65537 bytes", grow_to(65_537, PURPOSE), None),
    case("E-HIDDEN-CHAR", "zero width space", insert_after(PURPOSE, "\u200b"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "bidi override", insert_after(PURPOSE, "\u202e"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "tag letter", insert_after(PURPOSE, "\U000e0041"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "no-break space", insert_after(PURPOSE, "\u00a0"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "tab", insert_after(PURPOSE, "\t"), PURPOSE_LINE),
    *[
        case("E-PLACEHOLDER", token, insert_after(WHY_DRAFT, f" {token}"), WHY_LINE)
        for token in ("REPLACE_ME_X", "TODO", "TBD", "FIXME")
    ],
    *[
        case(code, label, insert_after(RISKS_WRITES, f" {value}"), RISKS_LINE)
        for code, _, label, value in CONTENT_SAMPLES
    ],
]


def test_valid_base_has_no_errors():
    assert [f for f in findings_of(BASE) if f.severity == "error"] == []


@pytest.mark.parametrize(("code", "mutation", "expected_line"), CASES)
def test_mutation_yields_exactly_one_new_finding(code, mutation, expected_line):
    new = new_findings(mutation(BASE))
    assert [(f.code, f.line) for f in new] == [(code, expected_line)]
    finding = new[0]
    assert finding.severity == ("error" if code.startswith("E-") else "warning")
    for lang in ("en", "nl"):
        text = message(finding, lang)  # raises KeyError if the finding lacks a parameter
        assert "{" not in text and "}" not in text
    assert format_line(finding).startswith(f"{finding.severity} {code} {BASE_PATH}")


@pytest.mark.parametrize(("code", "kind", "label", "value"), CONTENT_SAMPLES)
def test_content_finding_has_the_kind_as_its_only_parameter(code, kind, label, value):
    (finding,) = new_findings(insert_after(RISKS_WRITES, f" {value}")(BASE))
    assert finding.path == str(BASE_PATH)
    assert finding.params == ({} if code == "E-ID-NUMBER" else {"kind": kind})


@pytest.mark.parametrize(("code", "kind", "label", "value"), CONTENT_SAMPLES)
def test_content_findings_never_contain_value(code, kind, label, value):
    (finding,) = new_findings(insert_after(RISKS_WRITES, f" {value}")(BASE))
    shown = [
        format_line(finding),
        message(finding, "en"),
        message(finding, "nl"),
        json.dumps(dataclasses.asdict(finding)),  # stands in for --json until the CLI exists
    ]
    squeezed = re.sub(r"[ -]", "", value)  # also catch the value printed without its separators
    for text in shown:
        assert value not in text
        assert squeezed not in text


# A value joined to a placeholder word: the placeholder's own text would carry it into a finding.
# `scan` sees the value only where no letter or digit stands in front of it, which is after the
# underscore of `REPLACE_ME_`. The guard hides it whichever way it is glued.
GOOGLE_KEYS = gen.secret_values()["Google API key"]
GLUED_VALUES = {
    "BSN": ("E-ID-NUMBER", gen.valid_bsn()),
    "IBAN": ("E-BANK-DETAILS", gen.valid_iban()),
    "card number": ("E-BANK-DETAILS", gen.valid_card()),
    "Google API key": ("E-SECRET", GOOGLE_KEYS[0]),
    "Google API key with hyphens": ("E-SECRET", GOOGLE_KEYS[1]),
    "AWS access key": ("E-SECRET", gen.secret_values()["AWS access key"][0]),
    "GitHub token": ("E-SECRET", gen.secret_values()["GitHub token"][0]),
}
GLUE = {  # the text in front of the value, and whether the content check must report it too
    "REPLACE_ME_": True,
    "REPLACE_ME": False,
    "REPLACE_ME_X": False,
}


@pytest.mark.parametrize(("glue", "must_be_reported"), GLUE.items(), ids=GLUE)
@pytest.mark.parametrize(("code", "value"), GLUED_VALUES.values(), ids=GLUED_VALUES)
def test_a_placeholder_glued_to_a_value_does_not_echo_it(glue, must_be_reported, code, value):
    new = new_findings(insert_after(WHY_DRAFT, f" {glue}{value}")(BASE))
    # The placeholder is always reported, and the value where `scan` can see it. Other findings
    # on the line are allowed: `ME`, two digits and the words behind a number can read as an IBAN
    # by chance (about once in 97 candidates), and this test is not about that. Neither output
    # holds the value. That `scan` misses a value glued to a letter is tested in test_content.
    codes = {f.code for f in new}
    assert "E-PLACEHOLDER" in codes
    assert code in codes or not must_be_reported
    assert {f.line for f in new} == {WHY_LINE}
    for finding in new:
        shown = [
            format_line(finding),
            message(finding, "en"),
            message(finding, "nl"),
            json.dumps(dataclasses.asdict(finding)),
        ]
        assert all(value not in text for text in shown)
    placeholder = next(f for f in new if f.code == "E-PLACEHOLDER")
    assert placeholder.params == {"token": "[hidden]"}


SAMPLES = gen.sensitive_samples()


@pytest.mark.parametrize(("value", "start"), SAMPLES.values(), ids=SAMPLES)
def test_a_value_after_a_template_placeholder_shows_at_most_its_public_start(value, start):
    new = new_findings(insert_after(WHY_DRAFT, f" REPLACE_ME_FOLDER_ID{value}")(BASE))
    # The word that holds the placeholder holds the value, so the token is not shown at all. Other
    # findings on the line are allowed. Whatever they are, the part of the value after its public
    # start (`AKIA`, `gh`) is in none of the outputs.
    placeholder = next(f for f in new if f.code == "E-PLACEHOLDER")
    assert placeholder.params == {"token": "[hidden]"}
    for finding in new:
        shown = [
            format_line(finding),
            message(finding, "en"),
            message(finding, "nl"),
            json.dumps(dataclasses.asdict(finding)),
        ]
        assert all(value[start:] not in text for text in shown)


def test_validate_file_decodes_the_bytes_once(monkeypatch):
    calls = []

    def counting(data: bytes) -> str:
        calls.append(len(data))
        return decode_text(data)

    monkeypatch.setattr("aiven.policy.validate.decode_text", counting)
    monkeypatch.setattr("aiven.policy.fileformat.decode_text", counting)
    findings_of(BASE)
    assert calls == [len(BASE)]


def test_content_columns_do_not_count_the_byte_order_mark():
    data = codecs.BOM_UTF8 + gen.assignment("password").encode() + b"\n"
    assert ("E-SECRET", 1, 1) in {(f.code, f.line, f.column) for f in findings_of(data)}


def test_findings_are_sorted_whole_file_first_then_by_line_column_and_code():
    # Built so that emission order differs from report order: the hidden character comes later
    # in the Purpose line than the placeholder, and the whole-file findings tie on position.
    aws = gen.secret_values()["AWS access key"][0]
    bsn = gen.valid_bsn()
    data = insert_after("Once a day,", " TODO")(BASE)
    data = insert_after("this agent reads", "\u200b")(data)
    data = insert_after(WHY_DRAFT, f" {aws}")(data)
    data = insert_after(RISKS_WRITES, f" {bsn}")(data)
    data = codecs.BOM_UTF8 + data.rstrip(b"\n")
    data = grow_to(65_537, READS)(data)

    lines = data[len(codecs.BOM_UTF8) :].decode("utf-8").split("\n")

    def column(line: int, needle: str) -> int:
        return lines[line - 1].index(needle) + 1

    assert [(f.code, f.line, f.column) for f in new_findings(data)] == [
        ("E-FILE-SIZE", None, None),
        ("E-FINAL-NEWLINE", None, None),
        ("E-ENCODING", 1, None),
        ("E-PLACEHOLDER", PURPOSE_LINE, column(PURPOSE_LINE, "TODO")),
        ("E-HIDDEN-CHAR", PURPOSE_LINE, column(PURPOSE_LINE, "\u200b")),
        ("E-SECRET", WHY_LINE, column(WHY_LINE, aws)),
        ("E-ID-NUMBER", RISKS_LINE, column(RISKS_LINE, bsn)),
    ]
