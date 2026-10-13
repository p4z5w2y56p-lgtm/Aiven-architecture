"""Front matter (validator-spec section 3.2): splitting it off, and reading its YAML strictly.

`split` and `load` are tested on their own, with small texts. The field table (types, missing and
unknown fields) is tested in test_frontmatter_fields.py. The last section is about whole files: the
tests that the task names, and what `validate_file` skips when the front matter has no data. One
case per code, and the other tests of `validate_file`, are in test_codes.py.

Characters outside ASCII are written as \\N{...} escapes, so that this file stays plain ASCII.
"""

import dataclasses
import json
import random
import time
from pathlib import Path

import pytest

from aiven.policy.catalog import load_catalog
from aiven.policy.config import load_platform_config
from aiven.policy.findings import Finding, format_line, message
from aiven.policy.frontmatter import FIRST_LINE, MAX_DEPTH, check_filename, load, split
from aiven.policy.validate import validate_file
from tests.support import REPO_ROOT, gen
from tests.support.frontmatter import BASE_TEXT, DATA, FRONT, at, only, places, swap
from tests.support.policies import BASE_PATH, valid_base

CFG = load_platform_config(REPO_ROOT / "config" / "platform.example.yaml")
CATALOG = load_catalog(REPO_ROOT / "catalog" / "catalog-v1.yaml")

PATH = BASE_PATH
BASE = valid_base()
CYRILLIC_E = "\N{CYRILLIC SMALL LETTER IE}"
_, BODY, BODY_LINE = split(BASE_TEXT)


def features(result) -> list[tuple[str, int, int]]:
    """(feature, line, column) of every E-YAML-FEATURE finding, in file order."""
    found = [f for f in result.findings if f.code == "E-YAML-FEATURE"]
    return sorted((f.params["feature"], f.line, f.column) for f in found)


def paths_of(data: dict, prefix: str = "") -> list[str]:
    """The path of every field and list entry in `data`, as `load` keys them in `lines`."""
    paths = []
    for key, value in data.items():
        paths.append(prefix + key)
        if isinstance(value, dict):
            paths += paths_of(value, f"{prefix}{key}.")
        elif isinstance(value, list):
            paths += [f"{prefix}{key}.{number}" for number in range(len(value))]
    return paths


# --- split


def test_split_returns_the_front_matter_the_body_and_the_first_body_line():
    assert split("---\nschema: x\nagent: y\n---\n\n# y\n") == (
        "schema: x\nagent: y\n",
        "\n# y\n",
        5,
    )


def test_split_cuts_the_template_so_that_nothing_is_lost():
    assert "---\n" + FRONT + "---\n" + BODY == BASE_TEXT
    assert BODY_LINE == FRONT.count("\n") + 3
    assert BASE_TEXT.split("\n")[BODY_LINE - 1] == BODY.split("\n")[0]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n",
        "x\n---\n",
        "--- \n---\n",
        " ---\n---\n",
        "----\n---\n",
        "---x\n---\n",
        "\n---\n---\n",
    ],
)
def test_split_needs_exactly_three_hyphens_on_line_one(text):
    assert split(text) is None


@pytest.mark.parametrize(
    "text",
    ["---", "---\n", "---\na: 1\n", "---\na: 1\n--- \n", "---\na: 1\n----\n", "---\na: 1\n ---\n"],
)
def test_split_needs_a_closing_line_that_is_exactly_three_hyphens(text):
    assert split(text) is None


def test_split_treats_a_line_with_a_cr_as_a_different_line():
    # The CR is an error of its own (E-LINE-ENDINGS); the rule for the delimiter stays exact.
    assert split("---\r\na: 1\r\n---\r\n") is None


def test_split_closes_at_the_first_later_delimiter_line():
    assert split("---\na: 1\n---\nb\n---\nc\n") == ("a: 1\n", "b\n---\nc\n", 4)


def test_split_accepts_an_empty_front_matter():
    assert split("---\n---\n") == ("", "", 3)


def test_split_accepts_a_closing_line_without_a_newline():
    assert split("---\na: 1\n---") == ("a: 1\n", "", 4)


def test_split_cuts_lines_at_lf_only():
    odd = "a: 1\x85\N{LINE SEPARATOR} b\r"
    assert split(f"---\n{odd}\n---\n") == (f"{odd}\n", "", 4)


# --- load: a clean front matter


def test_load_reads_the_template_front_matter_into_python_values():
    result = load(FRONT, PATH)
    assert result.findings == []
    assert result.data == DATA
    assert type(result.data["version"]) is int
    assert type(result.data["limits"]["spend_eur_per_run"]) is int


def test_lines_hold_the_file_line_of_every_field_and_list_entry():
    result = load(FRONT, PATH)
    assert set(result.lines) == set(paths_of(DATA))
    file_lines = BASE_TEXT.split("\n")
    for path, number in result.lines.items():
        name = path.rsplit(".", 1)[-1]
        wanted = "- " if name.isdigit() else f"{name}:"
        assert file_lines[number - 1].strip().startswith(wanted), (path, number)
    assert result.lines["schema"] == FIRST_LINE + 1
    assert result.lines["limits.max_runtime_s"] == at("max_runtime_s: 300")
    assert result.lines["tools.1"] == at("- gmail.draft")
    assert result.lines["forbidden.3"] == at("- gmail.send_bulk")
    assert result.lines["scope.email_to.0"] == at('- "@aivenstudios.com"')


def test_load_names_the_file_in_its_findings():
    assert load("agent: [", Path("some/dir/x.md")).findings[0].path == "some/dir/x.md"
    assert load("agent: [").findings[0].path == ""


def test_a_result_shows_no_file_text_in_its_repr():
    iban = gen.valid_iban()
    result = load(f"agent: {iban}\n", PATH)
    assert result.data["agent"] == iban
    assert iban not in repr(result)


# --- E-YAML

# (front matter, line, column, what ruamel says is wrong)
SYNTAX_ERRORS = {
    "tab as indentation": (
        "a: 1\n\tb: 2\n",
        3,
        1,
        "found character '\\t' that cannot start any token",
    ),
    "indented key": ("a: 1\n  b: 2\n", 3, 4, "mapping values are not allowed here"),
    "unclosed flow list": ("a: [1, 2\nb: 3\n", 3, 2, "expected ',' or ']', but got ':'"),
    "unclosed quote": ('a: "unterminated\n', 3, 1, "found unexpected end of stream"),
    "character that starts no token": (
        "a: @foo\n",
        2,
        4,
        "found character '@' that cannot start any token",
    ),
    "control character": ("a: x\x01y\n", 2, 5, "special characters are not allowed"),
}


@pytest.mark.parametrize(
    ("front", "line", "column", "detail"), SYNTAX_ERRORS.values(), ids=SYNTAX_ERRORS
)
def test_a_syntax_error_is_e_yaml_at_its_file_line_and_column(front, line, column, detail):
    result = load(front, PATH)
    assert places(result) == [("E-YAML", line, column)]
    assert only(result).params == {"col": str(column), "detail": detail}
    assert (result.data, result.lines) == (None, {})


def test_e_yaml_gives_the_problem_and_never_a_line_of_the_file():
    finding = only(load("marker_one: [1, 2\nmarker_two: 3\n", PATH))
    shown = [format_line(finding), message(finding, "en"), message(finding, "nl"), repr(finding)]
    for text in shown:
        assert "marker_" not in text
        assert "<unicode string>" not in text
    assert "\n" not in finding.params["detail"]


def test_findings_before_a_syntax_error_are_still_reported():
    result = load("a: &x 1\nb: [\n", PATH)
    assert places(result) == [("E-YAML-FEATURE", 2, 4), ("E-YAML", 4, 1)]


def test_an_undefined_tag_handle_is_a_syntax_error():
    assert [f.code for f in load("a: !e!foo x\n", PATH).findings] == ["E-YAML"]


# --- E-YAML-FEATURE
#
# Each feature is found where it stands, as (feature, line, column).

FEATURES = {
    "anchor": ("agent: &a invoice\n", [("anchor", 2, 8)]),
    "alias": ("agent: *a\n", [("alias", 2, 8)]),
    "anchor and alias, each at its own line": (
        "a: &x 1\nb: *x\n",
        [("alias", 3, 4), ("anchor", 2, 4)],
    ),
    "merge key": ("<<: {}\n", [("merge key", 2, 1)]),
    "explicit tag": ("version: !!str 1\n", [("tag", 2, 10)]),
    "local tag": ("agent: !custom x\n", [("tag", 2, 8)]),
    "verbatim tag": ("agent: !<tag:example.com,2000:x> y\n", [("tag", 2, 8)]),
    "non-specific tag": ("agent: ! x\n", [("tag", 2, 8)]),
    "tag on a list": ("tools: !!seq\n  - a\n", [("tag", 2, 8)]),
    "tag on a key": ("!!str a: 1\n", [("tag", 2, 1)]),
    "tag without a value": ("agent: !!str\n", [("tag", 2, 8)]),
    "anchor and tag on one node": ("a: &x !!str 1\n", [("anchor", 2, 4), ("tag", 2, 4)]),
    "complex key in a block": ("? [a, b]\n: c\n", [("complex key", 2, 3)]),
    "complex key in flow style": ("[a, b]: c\n", [("complex key", 2, 1)]),
    "mapping as a key": ("{a: b}: c\n", [("complex key", 2, 1)]),
    "complex key deeper down": ("limits:\n  ? [a]\n  : b\n", [("complex key", 3, 5)]),
    "second document": ("a: 1\n--- # two\nb: 2\n", [("second document", 3, 1)]),
    "second document after a document end": ("a: 1\n...\nb: 2\n", [("second document", 4, 1)]),
    "document marker at the start": ("--- # c\na: 1\n", [("second document", 2, 1)]),
    "three documents": (
        "a: 1\n--- # 2\nb: 2\n--- # 3\nc: 3\n",
        [("second document", 3, 1), ("second document", 5, 1)],
    ),
    "yaml directive": (
        "%YAML 1.2\n--- # c\na: 1\n",
        [("directive", 2, 1), ("second document", 3, 1)],
    ),
    "tag directive": (
        "%TAG !e! tag:example.com,2000:\n--- # c\na: 1\n",
        [("directive", 2, 1), ("second document", 3, 1)],
    ),
    "unknown directive": (
        "%FOO bar\n--- # c\na: 1\n",
        [("directive", 2, 1), ("second document", 3, 1)],
    ),
    "directives with a comment and a blank line between": (
        "%YAML 1.2\n# c\n\n%FOO\n--- # c\na: 1\n",
        [("directive", 2, 1), ("directive", 5, 1), ("second document", 6, 1)],
    ),
    "directive of the second document": (
        "a: 1\n...\n%YAML 1.2\n--- b\n",
        [("directive", 4, 1), ("second document", 5, 1)],
    ),
}


@pytest.mark.parametrize(("front", "expected"), FEATURES.values(), ids=FEATURES)
def test_every_yaml_feature_is_reported_where_it_stands(front, expected):
    result = load(front, PATH)
    assert features(result) == sorted(expected)
    assert {f.code for f in result.findings} == {"E-YAML-FEATURE"}
    assert (result.data, result.lines) == (None, {})
    for finding in result.findings:
        for lang in ("en", "nl"):
            assert "{" not in message(finding, lang)


PLAIN_YAML = [
    "? a\n: b\n",
    '"<<": 1\n',
    "a: 1\n...\n",
    "a: [1, 2]\nb: {c: d}\n",
    "a: \"x\"\nb: 'y'\nc: |\n  z\n",
]


@pytest.mark.parametrize("front", PLAIN_YAML)
def test_plain_yaml_is_not_a_feature(front):
    assert features(load(front, PATH)) == []


def test_a_feature_stops_the_field_checks_and_drops_the_data():
    # Everything else in this front matter is missing, and still only the feature is reported.
    result = load("agent: &a x\n", PATH)
    assert [f.code for f in result.findings] == ["E-YAML-FEATURE"]
    assert result.data is None


def test_tags_never_build_python_objects(capsys):
    result = load("agent: !!python/object/apply:builtins.print [constructed]\n", PATH)
    assert features(result) == [("tag", 2, 8)]
    assert capsys.readouterr().out == ""


# --- E-YAML-DUPLICATE-KEY

DUPLICATES = {
    "top level": ("a: 1\nb: 2\na: 3\n", [("a", 4, 1)]),
    "inside a mapping": ("limits:\n  x: 1\n  x: 2\n", [("x", 4, 3)]),
    "quoted and plain": ('a: 1\n"a": 2\n', [("a", 3, 1)]),
    "single quoted": ("a: 1\n'a': 2\n", [("a", 3, 1)]),
    "written with an escape": ('a: 1\n"\\x61": 2\n', [("a", 3, 1)]),
    "flow style": ("{a: 1, a: 2}\n", [("a", 2, 8)]),
    "three times": ("a: 1\na: 2\na: 3\n", [("a", 3, 1), ("a", 4, 1)]),
    "empty value": ("a:\na:\n", [("a", 3, 1)]),
}


@pytest.mark.parametrize(("front", "expected"), DUPLICATES.values(), ids=DUPLICATES)
def test_a_repeated_key_is_reported_at_the_later_line(front, expected):
    result = load(front, PATH)
    found = [f for f in result.findings if f.code == "E-YAML-DUPLICATE-KEY"]
    assert [(f.params["key"], f.line, f.column) for f in found] == expected
    assert (result.data, result.lines) == (None, {})
    for finding in found:
        assert "appears twice" in message(finding, "en")


@pytest.mark.parametrize("front", ["a: 1\nA: 2\n", "a:\n  x: 1\nb:\n  x: 2\n", "a: [x, x]\n"])
def test_keys_in_different_places_or_with_different_case_are_not_duplicates(front):
    assert "E-YAML-DUPLICATE-KEY" not in {f.code for f in load(front, PATH).findings}


# --- E-FM-NON-ASCII


def test_a_non_ascii_character_is_reported_with_line_and_column_wherever_it_stands():
    front = (
        f"agent: invoice-r{CYRILLIC_E}minder\n"  # in a value
        f"{CYRILLIC_E}x: 1\n"  # in a key
        f"# r{CYRILLIC_E}quired\n"  # in a comment
    )
    found = [f for f in load(front, PATH).findings if f.code == "E-FM-NON-ASCII"]
    assert [(f.line, f.column, f.params) for f in found] == [
        (2, 17, {"col": "17"}),
        (3, 1, {"col": "1"}),
        (4, 4, {"col": "4"}),
    ]


def test_every_non_ascii_character_is_reported_once():
    front = f"# {CYRILLIC_E}{CYRILLIC_E} \N{LATIN SMALL LETTER E WITH ACUTE} \N{ROCKET}x\n"
    found = [f for f in load(front, PATH).findings if f.code == "E-FM-NON-ASCII"]
    assert [f.column for f in found] == [3, 4, 6, 8]  # an emoji is one column


def test_hidden_characters_are_left_to_e_hidden_char():
    hidden = "\N{ZERO WIDTH SPACE}\N{RIGHT-TO-LEFT OVERRIDE}\N{NO-BREAK SPACE}\N{SOFT HYPHEN}"
    assert "E-FM-NON-ASCII" not in {f.code for f in load(f"# {hidden}\n", PATH).findings}


def test_non_ascii_is_reported_for_a_front_matter_that_does_not_parse():
    result = load(f"a: [{CYRILLIC_E}\n", PATH)
    assert sorted(f.code for f in result.findings) == ["E-FM-NON-ASCII", "E-YAML"]


def test_ascii_text_has_no_non_ascii_findings():
    assert [f for f in load(FRONT, PATH).findings if f.code == "E-FM-NON-ASCII"] == []


def test_a_non_ascii_character_does_not_stop_the_field_checks():
    lookalike = f"drive.d{CYRILLIC_E}lete"
    front = FRONT.replace("drive.delete", lookalike)
    row = next(i for i, line in enumerate(front.split("\n")) if CYRILLIC_E in line)
    column = front.split("\n")[row].index(CYRILLIC_E) + 1
    result = load(front, PATH)
    assert FIRST_LINE + row == at("- drive.delete")
    assert places(result) == [("E-FM-NON-ASCII", FIRST_LINE + row, column)]
    assert result.data["forbidden"][1] == lookalike


# --- depth, size and safety

DEEP = {
    "flow lists": "[" * 10_000,
    "flow mappings": "{a: " * 10_000,
    "block lists on one line": "- " * 10_000,
    "explicit keys on one line": "? " * 10_000,
}


@pytest.mark.parametrize("text", DEEP.values(), ids=DEEP)
def test_deep_nesting_is_a_finding_and_not_a_crash(text):
    started = time.perf_counter()
    result = load(text + "\n", PATH)
    assert time.perf_counter() - started < 5  # reading all of it takes minutes
    assert result.data is None
    # Nested explicit keys are complex keys too, and each of them is reported on the way down.
    assert {f.code for f in result.findings} <= {"E-YAML", "E-YAML-FEATURE"}
    assert only(result, "E-YAML").params["detail"] == f"nesting is deeper than {MAX_DEPTH} levels"


def test_nesting_is_cut_off_where_the_depth_limit_is_passed():
    assert places(load("[" * 10_000, PATH)) == [("E-YAML", FIRST_LINE, MAX_DEPTH + 1)]


def test_the_depth_limit_counts_lists_and_mappings():
    inside = load("[" * MAX_DEPTH + "]" * MAX_DEPTH + "\n", PATH)
    assert [f.code for f in inside.findings] == ["E-FIELD-TYPE"]
    beyond = load("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1) + "\n", PATH)
    assert [f.code for f in beyond.findings] == ["E-YAML"]


def test_nesting_through_indentation_is_cut_off_too():
    text = "".join(f"{' ' * level}k:\n" for level in range(MAX_DEPTH + 2))
    assert places(load(text, PATH)) == [("E-YAML", MAX_DEPTH + 2, 1 + MAX_DEPTH)]


def test_load_returns_findings_and_never_raises_on_odd_text():
    rnd = random.Random(20261013)
    pieces = list("ab1:-[]{}&*!%#? \n\t\"'|>,.") + [
        "<<",
        "---",
        "...",
        "\\",
        "\x85",
        "\r",
        "@",
        "~",
    ]
    for _ in range(1500):
        text = "".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 60)))
        result = load(text, PATH)
        assert result.data is None or isinstance(result.data, dict)
        for finding in result.findings:
            assert finding.line is None or finding.line >= 1
            for lang in ("en", "nl"):
                message(finding, lang)  # raises KeyError if the finding lacks a parameter


# --- findings never show what the guard hides

SENSITIVE = gen.sensitive_samples()


@pytest.mark.parametrize(("value", "start"), SENSITIVE.values(), ids=SENSITIVE)
def test_no_finding_about_the_front_matter_shows_a_sensitive_value(value, start):
    texts = [
        f"{value}: 1\n",  # an unknown field
        f'version: "{value}"\n',  # a wrong type
        f"{value}: 1\n{value}: 2\n",  # a repeated key
        f"tools:\n  - {value}\n  - {value}\n",  # a repeated entry
        f"limits:\n  max_runtime_s: {value}\n",
    ]
    findings = [f for text in texts for f in load(text, PATH).findings]
    findings += check_filename(Path("policies/other.md"), {"agent": value})
    assert len(findings) > len(texts)
    for finding in findings:
        shown = [
            format_line(finding),
            message(finding, "en"),
            message(finding, "nl"),
            json.dumps(dataclasses.asdict(finding)),
        ]
        assert all(value[start:] not in text for text in shown), finding.code


# --- the tests that the task names, and how validate_file uses the front matter


def validate(data: bytes) -> list[Finding]:
    return validate_file(PATH, data, CFG, CATALOG)


def test_sexagesimal_is_not_an_integer():
    # YAML 1.1 reads 5:00 as 300. The loader keeps the text, and an integer is plain digits.
    result = load(swap("max_runtime_s: 300", "max_runtime_s: 5:00"), PATH)
    assert places(result) == [("E-FIELD-TYPE", at("max_runtime_s: 300"), None)]
    assert "max_runtime_s" not in result.data["limits"]


def test_lookalike_forbidden_entry_is_reported():
    data = BASE.replace(b"drive.delete", f"drive.d{CYRILLIC_E}lete".encode(), 1)
    assert ("E-FM-NON-ASCII", at("- drive.delete")) in {(f.code, f.line) for f in validate(data)}


def test_field_names_are_case_sensitive():
    data = BASE.replace(b"max_class: R2", b"Max_class: R2", 1)
    before = {(f.code, f.line) for f in validate(BASE)}
    assert {(f.code, f.line) for f in validate(data)} - before == {
        ("E-FIELD-UNKNOWN", at("max_class: R2")),
        ("E-FIELD-MISSING", 1),
    }


UNUSABLE = {
    "no front matter": (b"---\n# AIVEN", b"--- \n# AIVEN"),
    "syntax error": (b"max_class: R2", b"max_class: ["),
    "yaml feature": (b"agent: invoice-reminder", b"agent: &a invoice-reminder"),
    "repeated key": (b"version: 1", b"version: 1\nversion: 2"),
}


def test_checks_that_need_the_front_matter_are_skipped_when_it_has_no_data(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "aiven.policy.validate.check_filename", lambda path, data: calls.append(data) or []
    )
    for old, new in UNUSABLE.values():
        assert BASE.count(old) == 1
        validate(BASE.replace(old, new))
    assert calls == []  # no data, so nothing that needs the fields has run
    validate(BASE)
    assert calls == [DATA]
