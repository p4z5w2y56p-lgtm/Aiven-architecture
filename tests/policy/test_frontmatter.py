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
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aiven.policy.catalog import load_catalog
from aiven.policy.findings import Finding, format_line, message
from aiven.policy.frontmatter import FIRST_LINE, MAX_DEPTH, check_filename, load, split
from aiven.policy.validate import validate_file
from tests.support import REPO_ROOT, gen
from tests.support.frontmatter import BASE_TEXT, DATA, FRONT, at, only, places, swap, unexplained
from tests.support.policies import BASE_PATH, platform_config, valid_base

CFG = platform_config()
CATALOG = load_catalog(REPO_ROOT / "catalog" / "catalog-v1.yaml")

PATH = BASE_PATH
BASE = valid_base()
CYRILLIC_E = "\N{CYRILLIC SMALL LETTER IE}"
BS = "\\"  # a backslash; text with escapes is built from it, so that none is typed in this file
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


# --- E-YAML-FEATURE: escape sequences in double-quoted strings
#
# A backslash escape lets a value differ from what the signer reads: a look-alike letter, an
# invisible character, a disguised placeholder. No v1 field needs one, because every value is plain
# ASCII, so any backslash in a double-quoted string is a feature (ruling R39). It is found in the
# text as written, so none of those characters is ever in the text that the other checks read.

ESCAPES = {
    "look-alike letter": f'agent: "drive.d{BS}u0435lete"',
    "bidi override in a path": f'drive_folder_path: "AIVEN Sandbox{BS}u202e/ Invoices"',
    "zero width space in an id": f'agent: "invoice{BS}u200b-reminder"',
    "lone surrogate": f'agent: "{BS}uD800"',
    "hex escape": f'agent: "invoice{BS}x2dreminder"',
    "disguised placeholder": f'max_runtime_s: "T{BS}x4fDO"',
    "escaped line break": f'max_runtime_s: "TO{BS}\n    DO"',
    "escaped quote": f'agent: "a{BS}"b"',
    "escaped backslash": f'agent: "a{BS}{BS}b"',
    "newline escape": f'agent: "a{BS}nb"',
    "code point beyond the plane": f'agent: "{BS}U0001F600"',
}


@pytest.mark.parametrize("line", ESCAPES.values(), ids=ESCAPES)
def test_a_backslash_escape_in_a_double_quoted_string_is_a_feature(line):
    result = load(line + "\n", PATH)
    assert features(result) == [("escape sequence", FIRST_LINE, line.index('"') + 1)]
    assert {f.code for f in result.findings} == {"E-YAML-FEATURE"}  # no non-ASCII, no field check
    assert (result.data, result.lines) == (None, {})
    for lang in ("en", "nl"):
        assert "escape sequence" in message(result.findings[0], lang)


def test_an_escape_is_reported_once_per_string_at_the_line_where_the_string_starts():
    several = load(f'agent: "{BS}x41{BS}x42{BS}x43"\n', PATH)
    assert features(several) == [("escape sequence", FIRST_LINE, 8)]
    later_line = load(f'agent: "abc\n    d{BS}x4fe"\n', PATH)
    assert features(later_line) == [("escape sequence", FIRST_LINE, 8)]


def test_an_escape_is_found_in_keys_and_list_entries_too():
    assert features(load(f'"{BS}x61gent": x\n', PATH)) == [("escape sequence", 2, 1)]
    assert features(load(f'tools:\n  - "a{BS}x62"\n', PATH)) == [("escape sequence", 3, 5)]


NOT_ESCAPES = {
    "plain": f"agent: a{BS}b",
    "single quoted": f"agent: 'a{BS}b'",
    "block scalar": f"agent: |\n    a{BS}b",
    "folded scalar": f"agent: >\n    a{BS}b",
    "comment": f'agent: "ab" # {BS}x4f',
    "double quoted without one": 'agent: "ab"',
}


@pytest.mark.parametrize("line", NOT_ESCAPES.values(), ids=NOT_ESCAPES)
def test_a_backslash_is_only_an_escape_in_a_double_quoted_string(line):
    assert features(load(line + "\n", PATH)) == []


# --- E-YAML-DUPLICATE-KEY

DUPLICATES = {
    "top level": ("a: 1\nb: 2\na: 3\n", [("a", 4, 1)]),
    "inside a mapping": ("limits:\n  x: 1\n  x: 2\n", [("x", 4, 3)]),
    "quoted and plain": ('a: 1\n"a": 2\n', [("a", 3, 1)]),
    "single quoted": ("a: 1\n'a': 2\n", [("a", 3, 1)]),
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


# --- what ruamel rejects with an exception of its own (ruling R38)
#
# For some input ruamel does not raise a YAML error but a ValueError, an OverflowError (a code point
# in an escape that Python cannot make) or an AssertionError (a `%YAML` version it does not know).
# They are E-YAML too, at the place of the last event that was read. Python removes assert
# statements under `-O`, so the version is also judged here, and the result is the same either way.

REJECTED = {
    "yaml 1.0": ("%YAML 1.0\n--- # c\na: 1\n", "unsupported YAML version", (2, 1)),
    "yaml 1.3": ("%YAML 1.3\n--- # c\na: 1\n", "unsupported YAML version", (2, 1)),
    "yaml 1.10": ("%YAML 1.10\n--- # c\na: 1\n", "unsupported YAML version", (2, 1)),
    "yaml 1.0 after a document": (
        "a: 1\n...\n%YAML 1.0\n--- b\n",
        "unsupported YAML version",
        (3, 1),
    ),
    "code point beyond Unicode": (
        f'agent: "{BS}U00110000"\n',
        "invalid escape sequence",
        (2, 1),
    ),
    "code point beyond a C int": (
        f'agent: "{BS}UFFFFFFFF"\n',
        "invalid escape sequence",
        (2, 1),
    ),
    "after other keys": (f'a: 1\nb: "{BS}U00110000"\n', "invalid escape sequence", (3, 1)),
}


@pytest.mark.parametrize(("front", "detail", "place"), REJECTED.values(), ids=REJECTED)
def test_what_ruamel_rejects_with_an_exception_is_e_yaml(front, detail, place):
    result = load(front, PATH)
    assert [(f.code, f.params["detail"]) for f in result.findings] == [("E-YAML", detail)]
    assert (only(result).line, only(result).column) == place
    assert only(result).params["col"] == str(place[1])
    assert (result.data, result.lines) == (None, {})


@pytest.mark.parametrize("version", ["1.1", "1.2"])
def test_the_yaml_versions_ruamel_knows_are_a_directive_and_not_a_rejection(version):
    result = load(f"%YAML {version}\n--- # c\na: 1\n", PATH)
    assert features(result) == [("directive", 2, 1), ("second document", 3, 1)]


def test_features_found_before_a_rejection_are_kept():
    result = load(f'a: &x 1\nb: "{BS}U00110000"\n', PATH)
    assert places(result) == [("E-YAML-FEATURE", 2, 4), ("E-YAML", 3, 1)]


def test_an_exception_from_the_loader_itself_is_not_taken_for_a_yaml_error(monkeypatch):
    def broken(*args, **kwargs):
        raise ValueError("a bug in the loader")

    monkeypatch.setattr("aiven.policy.frontmatter.Finding", broken)
    with pytest.raises(ValueError, match="a bug in the loader"):
        load("a: &x 1\n", PATH)


@pytest.mark.parametrize("error", [KeyError, IndexError, TypeError, RuntimeError])
def test_any_other_exception_of_ruamel_is_a_bug_and_goes_up(monkeypatch, error):
    # Only what ruamel is known to raise for input it rejects is E-YAML. Anything else is a bug in
    # ruamel or here, and must not be passed off as a finding about the file.
    def failing(self, stream):
        yield from ()
        raise error("a bug in the parser")

    monkeypatch.setattr("aiven.policy.frontmatter.YAML.parse", failing)
    with pytest.raises(error, match="a bug in the parser"):
        load("a: 1\n", PATH)


SAME_UNDER_O = [
    *[front for front, _, _ in REJECTED.values()],
    *[front for front, _ in FEATURES.values()],
    *[front for front, *_ in SYNTAX_ERRORS.values()],
    *[f"{line}\n" for line in ESCAPES.values()],
    FRONT,
]

_DUMP = """
import json, sys
from aiven.policy.frontmatter import load
if __debug__:
    sys.exit("this must run under python -O")
out = []
for text in json.load(sys.stdin):
    result = load(text, "policies/x.md")
    out.append([[f.code, f.line, f.column, f.params] for f in result.findings] + [result.data])
json.dump(out, sys.stdout)
"""


def dump(texts: list[str]) -> list:
    """What `_DUMP` prints, computed here: findings as lists, and the data."""
    out = []
    for text in texts:
        result = load(text, "policies/x.md")
        out.append([[f.code, f.line, f.column, f.params] for f in result.findings] + [result.data])
    return json.loads(json.dumps(out))


def test_the_result_is_the_same_under_python_dash_o():
    # Under -O the assert in ruamel that rejects `%YAML 1.0` is gone. It must not change the result.
    done = subprocess.run(
        [sys.executable, "-O", "-c", _DUMP],
        input=json.dumps(SAME_UNDER_O),
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(done.stdout) == dump(SAME_UNDER_O)


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


# --- a fuzz corpus: random strings, and the template with random edits
#
# `load` must never raise, every finding must be one a message can be made of, and no field may
# drop out of `data` without a finding on its line (`unexplained`).

PIECES = [
    *"ab1:-[]{}&*!%#? \n\t\"'|>,.",
    *["<<", "---", "...", BS, "\x85", "\r", "@", "~"],
    *[f"{BS}x4f", f"{BS}n", f'{BS}"', f"{BS}u0435", f"{BS}uD800", f"{BS}U0001F600", f"{BS}\n"],
    *[f"{BS}U00110000", f"{BS}UFFFFFFFF", "%YAML 1.0\n", "%YAML 1.3\n", "%YAML 1.10\n"],
    *["%YAML 1.1\n", "%YAML 1.2\n", "%TAG ! tag:x,2000:\n"],
    *["TODO", "TBD", "FIXME", "REPLACE_ME_X"],
]
# What a field is set to now and then: placeholders in the ways that decide what is reported.
VALUES = [
    *["TODO", "TBD", "'FIXME'", '"REPLACE_ME_X"', "300\n    TBD", "\n    TBD", "|\n    TODO"],
    *[f'"T{BS}x4fDO"', f'"TO{BS}\n    DO"'],  # TODO, written so that E-PLACEHOLDER misses it
    *[f'"drive.d{BS}u0435lete"', f'"a{BS}u202eb"'],  # a look-alike letter, an override
    *[f'"{BS}U00110000"', f'"{BS}UFFFFFFFF"'],  # code points that ruamel cannot make
]
FIELD_LINE = re.compile(r"\s*[a-z_]+:")


def edit_at_random(rnd: random.Random, text: str) -> str:
    """One random edit of a front matter text: insert, delete, repeat a line, or set a value."""
    kind = rnd.random()
    position = rnd.randrange(len(text) + 1)
    if kind < 0.3:
        return text[:position] + rnd.choice(PIECES) + text[position:]
    if kind < 0.4:
        return text[:position] + text[position + rnd.randint(1, 12) :]
    lines = text.split("\n")
    if kind < 0.5:
        row = rnd.randrange(len(lines))
        lines.insert(row, lines[row])
    else:
        rows = [number for number, line in enumerate(lines) if FIELD_LINE.match(line)]
        if rows:
            row = rnd.choice(rows)
            key = lines[row].split(":")[0]
            value = rnd.choice(VALUES) if rnd.random() < 0.6 else rnd.choice(PIECES)
            lines[row] = f"{key}: {value}"
    return "\n".join(lines)


def fuzz_corpus() -> list[str]:
    rnd = random.Random(20261013)
    texts = ["".join(rnd.choice(PIECES) for _ in range(rnd.randint(0, 60))) for _ in range(1500)]
    for _ in range(600):
        text = FRONT
        for _ in range(rnd.randint(1, 3)):
            text = edit_at_random(rnd, text)
        texts.append(text)
    return texts


FUZZ = fuzz_corpus()


def test_load_returns_findings_and_never_raises_on_odd_text():
    for text in FUZZ:
        result = load(text, PATH)
        assert result.data is None or isinstance(result.data, dict)
        for finding in result.findings:
            assert finding.line is None or finding.line >= 1
            for lang in ("en", "nl"):
                message(finding, lang)  # raises KeyError if the finding lacks a parameter


def test_no_field_drops_out_of_the_data_unreported_on_the_fuzz_corpus():
    for text in FUZZ:
        assert unexplained(text, load(text, PATH)) == [], text


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
    findings += check_filename(Path("policies/other.md"), load(f'agent: "{value}"\n', PATH))
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
    lookalike = f"drive.d{CYRILLIC_E}lete"
    found = validate(BASE.replace(b"drive.delete", lookalike.encode(), 1))
    line = at("- drive.delete")
    assert ("E-FM-NON-ASCII", line) in {(f.code, f.line) for f in found}
    # It is no exact name, so it is E-FORBIDDEN-PATTERN (and not also unknown), and the real
    # drive.delete is then missing from the baseline.
    assert [(f.line, f.params) for f in found if f.code == "E-FORBIDDEN-PATTERN"] == [
        (line, {"entry": lookalike})
    ]
    assert [(f.line, f.params) for f in found if f.code == "E-FORBIDDEN-BASELINE"] == [
        (at("forbidden:"), {"missing": "drive.delete"})
    ]
    assert "E-FORBIDDEN-UNKNOWN" not in {f.code for f in found}


def test_field_names_are_case_sensitive():
    data = BASE.replace(b"max_class: R2", b"Max_class: R2", 1)
    before = {(f.code, f.line) for f in validate(BASE)}
    assert {(f.code, f.line) for f in validate(data)} - before == {
        ("E-FIELD-UNKNOWN", at("max_class: R2")),
        ("E-FIELD-MISSING", 1),
    }


FIELD_TEXT = {
    "agent": "invoice-reminder",
    "drive_folder_path": "AIVEN Architecture Sandbox / Invoices",
    "max_runtime_s": "300",
}


@pytest.mark.parametrize("line", ESCAPES.values(), ids=ESCAPES)
def test_an_escape_is_the_only_finding_of_a_whole_file(line):
    # The invisible and look-alike characters that an escape writes never stand in the file, so
    # E-HIDDEN-CHAR and E-FM-NON-ASCII have nothing to report, and the escape itself is reported.
    field = line.split(":")[0]
    old = f"{field}: {FIELD_TEXT[field]}".encode()
    assert BASE.count(old) == 1
    assert [(f.code, f.params) for f in validate(BASE.replace(old, line.encode()))] == [
        ("E-YAML-FEATURE", {"feature": "escape sequence"})
    ]


UNUSABLE = {
    "no front matter": (b"---\n# AIVEN", b"--- \n# AIVEN"),
    "syntax error": (b"max_class: R2", b"max_class: ["),
    "yaml feature": (b"agent: invoice-reminder", b"agent: &a invoice-reminder"),
    "repeated key": (b"version: 1", b"version: 1\nversion: 2"),
}


def test_checks_that_need_the_front_matter_are_skipped_when_it_has_no_data(monkeypatch):
    calls, rules = [], []
    monkeypatch.setattr(
        "aiven.policy.validate.check_filename", lambda path, front: calls.append(front) or []
    )
    monkeypatch.setattr(
        "aiven.policy.validate.build_policy",
        lambda front, *args, **kwargs: rules.append(front) or (None, []),
    )
    for old, new in UNUSABLE.values():
        assert BASE.count(old) == 1
        validate(BASE.replace(old, new))
    assert calls == [] and rules == []  # no data, so nothing that needs the fields has run
    validate(BASE)
    assert [front.data for front in calls] == [DATA]
    assert [front.data for front in rules] == [DATA]
