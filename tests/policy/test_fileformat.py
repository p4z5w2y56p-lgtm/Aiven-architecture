"""File format checks (validator-spec section 3.1): bytes, line endings, hidden characters."""

import codecs
import re
from pathlib import Path

import pytest

from aiven.policy import constants
from aiven.policy.fileformat import check_file, decode_text
from aiven.policy.findings import Finding, load_messages, message
from tests.support.policies import BASE_PATH, TEMPLATE_PATH, valid_base
from tests.support.spec_tables import code_spans, line_starting_with, table_after

PATH = Path("policies/example.md")


def check(data: str | bytes) -> list[Finding]:
    return check_file(PATH, data.encode("utf-8") if isinstance(data, str) else data)


def places(findings: list[Finding]) -> list[tuple[str, int | None, int | None]]:
    """(code, line, column) of each finding, in report order: whole-file first, then by position."""
    ordered = sorted(findings, key=lambda f: (f.line or 0, f.column or 0, f.code))
    return [(f.code, f.line, f.column) for f in ordered]


# --- the text every check reads


def test_decode_text_drops_one_leading_byte_order_mark():
    assert decode_text(codecs.BOM_UTF8 + b"abc") == "abc"
    assert decode_text(codecs.BOM_UTF8 * 2 + b"abc") == "\ufeffabc"


def test_decode_text_replaces_invalid_bytes_and_changes_nothing_else():
    assert decode_text(b"a\xffb\r\n\xe2\x82\xac\n") == "a\ufffdb\r\n\u20ac\n"


# --- clean files


def test_a_clean_file_has_no_findings():
    assert check("hello\n") == []
    assert check_file(BASE_PATH, valid_base()) == []


def test_findings_are_errors_for_the_path_that_was_given():
    findings = check_file(Path("some/dir/file.md"), b"TODO")
    assert {f.code for f in findings} == {"E-PLACEHOLDER", "E-FINAL-NEWLINE"}
    assert {f.path for f in findings} == {"some/dir/file.md"}
    assert {f.severity for f in findings} == {"error"}


def test_every_problem_is_reported_not_only_the_first():
    data = codecs.BOM_UTF8 + b"TODO\r\n\xff\xe2\x80\x8b"
    assert {f.code for f in check(data)} == {
        "E-ENCODING",
        "E-LINE-ENDINGS",
        "E-FINAL-NEWLINE",
        "E-PLACEHOLDER",
        "E-HIDDEN-CHAR",
    }


# --- E-ENCODING

INVALID_BYTES = {
    "lone continuation byte": b"\x80",
    "byte that never occurs": b"\xff",
    "overlong slash": b"\xc0\xaf",
    "encoded surrogate": b"\xed\xa0\x80",
    "cut-off euro sign": b"\xe2\x82",
    "beyond U+10FFFF": b"\xf4\x90\x80\x80",
    "UTF-16 byte-order mark": b"\xff\xfe",
}


def test_a_byte_order_mark_is_reported_once_at_line_1():
    assert places(check(codecs.BOM_UTF8 + b"one\ntwo\n")) == [("E-ENCODING", 1, None)]


@pytest.mark.parametrize("bad", INVALID_BYTES.values(), ids=INVALID_BYTES)
def test_an_invalid_byte_is_reported_at_its_line(bad):
    assert places(check(b"one\ntwo\nth" + bad + b"ree\n")) == [("E-ENCODING", 3, None)]


def test_only_the_first_invalid_byte_is_reported():
    assert places(check(b"ok\n\xff\nand\n\xfe\n")) == [("E-ENCODING", 2, None)]


def test_a_byte_order_mark_wins_over_a_later_invalid_byte():
    assert places(check(codecs.BOM_UTF8 + b"ok\n\xff\n")) == [("E-ENCODING", 1, None)]


def test_valid_multibyte_text_is_not_an_encoding_error():
    assert check("\u20ac \u00e9 \u4e2d \U0001f600\n") == []


def test_the_other_checks_still_run_after_an_encoding_error():
    # TODO at column 1, the replacement character at 6, the zero-width space at 7.
    assert places(check(b"TODO \xff\xe2\x80\x8b\n")) == [
        ("E-ENCODING", 1, None),
        ("E-PLACEHOLDER", 1, 1),
        ("E-HIDDEN-CHAR", 1, 7),
    ]


def test_the_byte_order_mark_does_not_shift_the_columns_after_it():
    assert places(check(codecs.BOM_UTF8 + "a\u200b\n".encode())) == [
        ("E-ENCODING", 1, None),
        ("E-HIDDEN-CHAR", 1, 2),
    ]


# --- E-LINE-ENDINGS


def test_crlf_is_reported_once_at_the_first_cr():
    assert places(check(b"one\r\ntwo\r\nthree\r\n")) == [("E-LINE-ENDINGS", 1, None)]


def test_a_lone_cr_is_reported_at_its_line():
    assert places(check(b"one\ntwo\nth\rree\n")) == [("E-LINE-ENDINGS", 3, None)]


def test_a_cr_is_not_also_a_hidden_character():
    assert [f.code for f in check(b"a\rb\n")] == ["E-LINE-ENDINGS"]


# --- E-FINAL-NEWLINE

NOT_ONE_FINAL_NEWLINE = {
    "empty file": b"",
    "no newline": b"a",
    "two newlines": b"a\n\n",
    "three newlines": b"a\n\n\n",
    "only newlines": b"\n\n",
    "blank lines at the end": b"a\n\n\n\n",
}


@pytest.mark.parametrize("data", NOT_ONE_FINAL_NEWLINE.values(), ids=NOT_ONE_FINAL_NEWLINE)
def test_final_newline_is_reported_once_without_a_line(data):
    assert places(check(data)) == [("E-FINAL-NEWLINE", None, None)]


@pytest.mark.parametrize("data", [b"a\n", b"\n", b"a\n \n"], ids=["text", "only LF", "space line"])
def test_exactly_one_final_newline_is_fine(data):
    assert check(data) == []


def test_a_crlf_ending_is_a_line_ending_problem_only():
    assert places(check(b"a\r\n")) == [("E-LINE-ENDINGS", 1, None)]


# --- E-FILE-SIZE


def test_the_size_limit_is_64_kib_and_inclusive():
    assert constants.MAX_FILE_BYTES == 65536
    at_limit = b"x" * (constants.MAX_FILE_BYTES - 1) + b"\n"
    assert len(at_limit) == 65536
    assert check(at_limit) == []
    (finding,) = check(b"x" * constants.MAX_FILE_BYTES + b"\n")
    assert (finding.code, finding.line, finding.column) == ("E-FILE-SIZE", None, None)
    assert finding.params == {"size": "65537"}
    assert message(finding, "en") == "File is 65537 bytes; the maximum is 65536."


def test_the_size_is_counted_in_bytes_not_characters():
    assert check("\u20ac" * 21845 + "\n") == []  # 3 bytes each: exactly 65536
    (finding,) = check("\u20ac" * 21846 + "\n")
    assert finding.params == {"size": "65539"}


def test_the_other_checks_still_run_on_a_file_that_is_too_large():
    findings = check(b"TODO " + b"x" * 70_000 + b"\n")
    assert sorted(f.code for f in findings) == ["E-FILE-SIZE", "E-PLACEHOLDER"]


def test_the_size_limit_equals_the_spec():
    rows = {row[0]: row[1] for row in table_after("3.1 File")[1:]}
    assert rows["E-FILE-SIZE"] == "It is larger than 64 KiB"
    assert constants.MAX_FILE_BYTES == 64 * 1024
    assert f"the maximum is {constants.MAX_FILE_BYTES}." in load_messages("en")["E-FILE-SIZE"]
    assert f"het maximum is {constants.MAX_FILE_BYTES}." in load_messages("nl")["E-FILE-SIZE"]


# --- E-HIDDEN-CHAR

HIDDEN = {
    "null": "\x00",
    "tab": "\t",
    "vertical tab": "\x0b",
    "form feed": "\x0c",
    "escape": "\x1b",
    "delete": "\x7f",
    "padding": "\x80",
    "next line": "\x85",
    "application program command": "\x9f",
    "no-break space": "\u00a0",
    "soft hyphen": "\u00ad",
    "combining grapheme joiner": "\u034f",
    "hangul choseong filler": "\u115f",
    "hangul jungseong filler": "\u1160",
    "mongolian vowel separator": "\u180e",
    "en quad": "\u2000",
    "em space": "\u2003",
    "zero width space": "\u200b",
    "zero width non-joiner": "\u200c",
    "zero width joiner": "\u200d",
    "left-to-right mark": "\u200e",
    "right-to-left mark": "\u200f",
    "line separator": "\u2028",
    "paragraph separator": "\u2029",
    "left-to-right embedding": "\u202a",
    "right-to-left override": "\u202e",
    "narrow no-break space": "\u202f",
    "word joiner": "\u2060",
    "left-to-right isolate": "\u2066",
    "pop directional isolate": "\u2069",
    "ideographic space": "\u3000",
    "hangul filler": "\u3164",
    "variation selector 1": "\ufe00",
    "variation selector 16": "\ufe0f",
    "byte-order mark inside the file": "\ufeff",
    "halfwidth hangul filler": "\uffa0",
    "tag 0": "\U000e0000",
    "language tag": "\U000e0001",
    "tag letter A": "\U000e0041",
    "cancel tag": "\U000e007f",
    "variation selector 17": "\U000e0100",
    "variation selector 256": "\U000e01ef",
}

VISIBLE = {
    "space": " ",
    "tilde": "~",
    "euro sign": "\u20ac",
    "e acute": "\u00e9",
    "inverted exclamation mark": "\u00a1",
    "en dash": "\u2013",
    "ellipsis": "\u2026",
    "emoji": "\U0001f600",
    "han character": "\u4e2d",
    "replacement character": "\ufffd",
    "combining mark before the grapheme joiner": "\u034e",
    "combining mark after the grapheme joiner": "\u0350",
    "hangul letter before the fillers": "\u115e",
    "hangul letter after the fillers": "\u1161",
    "hangul letter before the filler": "\u3163",
    "hangul letter after the filler": "\u3165",
    "halfwidth hangul letter": "\uffa1",
    "after variation selector 16": "\ufe10",
    "unassigned after the tags": "\U000e0080",
    "unassigned after the variation selectors": "\U000e01f0",
}


@pytest.mark.parametrize("char", HIDDEN.values(), ids=HIDDEN)
def test_a_hidden_character_is_reported_with_line_column_and_code_point(char):
    (finding,) = check(f"a{char}b\n")
    assert (finding.code, finding.line, finding.column) == ("E-HIDDEN-CHAR", 1, 2)
    assert finding.params == {"codepoint": f"U+{ord(char):04X}", "col": "2"}


@pytest.mark.parametrize("char", VISIBLE.values(), ids=VISIBLE)
def test_a_visible_character_is_not_hidden(char):
    assert check(f"a{char}b\n") == []


def test_the_code_point_has_at_least_four_uppercase_hex_digits():
    def codepoint(char: str) -> str:
        return check(f"a{char}\n")[0].params["codepoint"]

    assert codepoint("\t") == "U+0009"
    assert codepoint("\u200b") == "U+200B"
    assert codepoint("\U000e0041") == "U+E0041"


def test_the_message_names_the_code_point_and_the_column_in_both_languages():
    (finding,) = check("abc\u202e\n")
    assert message(finding, "en").startswith(
        "Invisible or direction-changing character U+202E at column 4."
    )
    assert "U+202E in kolom 4" in message(finding, "nl")


def test_every_occurrence_is_reported_at_its_own_position():
    text = "one\ntw\u200bo \u202e\nthree\n\ta\u00a0\n"
    assert places(check(text)) == [
        ("E-HIDDEN-CHAR", 2, 3),
        ("E-HIDDEN-CHAR", 2, 6),
        ("E-HIDDEN-CHAR", 4, 1),
        ("E-HIDDEN-CHAR", 4, 3),
    ]


def test_columns_count_code_points_not_bytes_or_utf16_units():
    assert places(check("\u20ac\U0001f600\u00e9\u200b\n")) == [("E-HIDDEN-CHAR", 1, 4)]


def test_lines_are_split_on_lf_only():
    # str.splitlines() would also break at \x0b, \x0c, \x1d, \x85, U+2028 and U+2029.
    findings = check("a\x0bb\x0cc\x1dd\x85e\u2028f\u2029g\nTODO\n")
    assert [f.line for f in findings if f.code == "E-PLACEHOLDER"] == [2]
    assert [f.line for f in findings if f.code == "E-HIDDEN-CHAR"] == [1] * 6


def test_lf_and_the_normal_space_are_not_hidden():
    assert check("a b\nc d\n") == []


def test_the_leading_byte_order_mark_is_not_hidden_but_a_second_one_is():
    assert places(check(codecs.BOM_UTF8 * 2 + b"a\n")) == [
        ("E-ENCODING", 1, None),
        ("E-HIDDEN-CHAR", 1, 1),
    ]


def test_the_hidden_characters_equal_the_spec():
    sentence = line_starting_with("Hidden characters are")
    assert set(re.findall(r"\b(C[cf]|Z[lps])\b", sentence)) == constants.HIDDEN_CATEGORIES
    listed = re.findall(r"U\+([0-9A-F]{4,6})(?:\u2013([0-9A-F]{4,6}))?", sentence)
    assert [(int(low, 16), int(high or low, 16)) for low, high in listed] == list(
        constants.HIDDEN_RANGES
    )


# --- E-PLACEHOLDER

PLACEHOLDERS = [
    "REPLACE_ME",
    "REPLACE_ME_X",
    "REPLACE_ME_AGENTS_PROJECT",
    "REPLACE_ME2",
    "TODO",
    "TBD",
    "FIXME",
]
NOT_PLACEHOLDERS = [
    "todo",
    "Todo",
    "tbd",
    "fixme",
    "FixMe",
    "TODOS",
    "TODO_LIST",
    "xTODO",
    "NOTBD",
    "FIXMEs",
    "replace_me",
    "xREPLACE_ME",
    "1aTBDz",
    "REPLACE-ME",
    "REPLACE_M",
    "TO DO",
]


@pytest.mark.parametrize(
    "template", ["{} here", "see {}", "x ({}) y", "{}: later", "a-{}-b", "# {}"]
)
@pytest.mark.parametrize("token", PLACEHOLDERS)
def test_a_placeholder_is_reported_with_its_token(token, template):
    text = template.format(token) + "\n"
    (finding,) = check(text)
    assert finding.code == "E-PLACEHOLDER"
    assert finding.params == {"token": token}
    assert (finding.line, finding.column) == (1, text.index(token) + 1)


@pytest.mark.parametrize("word", NOT_PLACEHOLDERS)
def test_other_words_are_not_placeholders(word):
    assert check(f"see {word} here\n") == []


def test_each_placeholder_is_reported_where_it_stands():
    text = "TODO and TBD\nFIXME\n  REPLACE_ME_X TODO\n"
    assert places(check(text)) == [
        ("E-PLACEHOLDER", 1, 1),
        ("E-PLACEHOLDER", 1, 10),
        ("E-PLACEHOLDER", 2, 1),
        ("E-PLACEHOLDER", 3, 3),
        ("E-PLACEHOLDER", 3, 16),
    ]


def test_the_message_names_the_token():
    (finding,) = check("fill REPLACE_ME_X in\n")
    assert message(finding, "en") == (
        "Placeholder REPLACE_ME_X is still there. Fill it in before signing."
    )
    assert "REPLACE_ME_X" in message(finding, "nl")


def test_the_template_placeholders_are_the_ones_in_spec_section_9():
    header, *rows = table_after("9. Template self-test")
    assert header == ["Severity", "Code", "Line", "About"]
    expected = [
        (int(line), code_spans(about)[0])
        for _, code, line, about in rows
        if code == "E-PLACEHOLDER"
    ]
    assert len(expected) == 4
    findings = check_file(Path("policy-template.md"), TEMPLATE_PATH.read_bytes())
    assert {f.code for f in findings} == {"E-PLACEHOLDER"}
    ordered = sorted(findings, key=lambda f: (f.line, f.column))
    assert [(f.line, f.params["token"]) for f in ordered] == expected
