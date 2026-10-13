"""The field table of the front matter (validator-spec section 3.3), checked by `load`.

Types and values of scalars and lists, missing and unknown fields, and what a placeholder skips.
Reading the YAML itself is tested in test_frontmatter.py. Values and ranges are the next task's.
"""

import sys
from pathlib import Path

import pytest

from aiven.policy import constants
from aiven.policy.findings import Finding, message
from aiven.policy.frontmatter import (
    FIELDS,
    FIRST_LINE,
    OPTIONAL,
    FrontMatter,
    check_filename,
    load,
)
from tests.support.frontmatter import (
    DATA,
    FRONT,
    at,
    edited,
    front_without,
    lookup,
    only,
    places,
    swap,
    unexplained,
)
from tests.support.policies import BASE_PATH
from tests.support.spec_tables import code_spans, line_starting_with, table_after

PATH = BASE_PATH
SEND_LINE = at("- gmail.draft") + 1  # the line of the last tool, `gmail.send`
BS = "\\"  # a backslash; YAML text with escapes is built from it, so no escape is typed here


# --- scalars: integers

INTEGER_REJECTED = {
    "double quoted": ('"300"', '"300"'),
    "single quoted": ("'300'", '"300"'),
    "hexadecimal": ("0x12C", "0x12C"),
    "sexagesimal": ("5:00", "5:00"),
    "plus sign": ("+5", "+5"),
    "minus sign": ("-5", "-5"),
    "yaml 1.1 boolean": ("on", "on"),
    "leading zero": ("01", "01"),
    "underscore": ("1_000", "1_000"),
    "float": ("1.0", "1.0"),
    "exponent": ("1e3", "1e3"),
    "true": ("true", "true"),
    "null": ("null", "null"),
    "tilde": ("~", "~"),
    "no value": ("", "null"),
    "octal": ("0o14", "0o14"),
    "infinity": (".inf", ".inf"),
    "two numbers": ("1 2", "1 2"),
    "a word": ("fast", "fast"),
    "list": ("[300]", "list"),
    "mapping": ("{a: 1}", "mapping"),
}
INTEGER_ACCEPTED = {"zero": "0", "one": "1", "ten": "10", "300": "300", "huge": "9" * 40}


@pytest.mark.parametrize(("value", "found"), INTEGER_REJECTED.values(), ids=INTEGER_REJECTED)
def test_an_integer_field_takes_plain_digits_only(value, found):
    result = load(swap("max_runtime_s: 300", f"max_runtime_s: {value}".rstrip()), PATH)
    assert places(result) == [("E-FIELD-TYPE", at("max_runtime_s: 300"), None)]
    assert only(result).params == {
        "field": "limits.max_runtime_s",
        "expected": "integer",
        "found": found,
    }
    assert "max_runtime_s" not in result.data["limits"]
    assert result.lines["limits.max_runtime_s"] == at("max_runtime_s: 300")


@pytest.mark.parametrize("digits", INTEGER_ACCEPTED.values(), ids=INTEGER_ACCEPTED)
def test_an_integer_field_keeps_the_number_for_the_range_check_to_judge(digits):
    result = load(swap("max_runtime_s: 300", f"max_runtime_s: {digits}"), PATH)
    assert result.findings == []
    assert result.data["limits"]["max_runtime_s"] == int(digits)


def test_a_block_scalar_is_not_an_integer():
    result = load(swap("max_runtime_s: 300", "max_runtime_s: |\n    300"), PATH)
    assert only(result).params["expected"] == "integer"


def test_a_number_that_python_will_not_read_is_a_type_error_and_no_crash():
    limit = sys.get_int_max_str_digits()
    if not limit:
        pytest.skip("this interpreter reads integers of any length")
    result = load(swap("max_runtime_s: 300", "max_runtime_s: " + "9" * (limit + 1)), PATH)
    assert [f.code for f in result.findings] == ["E-FIELD-TYPE"]


# --- scalars: strings

STRING_REJECTED = {
    "digits": "123",
    "zero": "0",
    "float": "1.5",
    "leading dot": ".5",
    "exponent": "1e3",
    "hexadecimal": "0x1F",
    "octal": "0o7",
    "plus": "+1",
    "minus": "-1",
    "true": "true",
    "True": "True",
    "FALSE": "FALSE",
    "null": "null",
    "Null": "Null",
    "NULL": "NULL",
    "tilde": "~",
    "infinity": ".inf",
    "negative infinity": "-.INF",
    "not a number": ".NaN",
}
STRING_ACCEPTED = {
    "on is a word in yaml 1.2": "on",
    "off": "off",
    "yes": "yes",
    "no": "No",
    "y": "y",
    "a class": "R2",
    "underscores": "1_000",
    "binary": "0b101",
    "a date": "2024-01-01",
    "digit then letter": "1a",
    "only the prefix": "0x",
    "e then digits": "e5",
    "a word like null": "nul",
    "quoted digits": '"123"',
    "quoted null": "'null'",
    "quoted true": '"true"',
    "quoted empty": '""',
    "block scalar": "|\n    text",
}


@pytest.mark.parametrize("value", STRING_REJECTED.values(), ids=STRING_REJECTED)
def test_a_string_field_rejects_plain_text_that_yaml_reads_as_something_else(value):
    result = load(swap("agent: invoice-reminder", f"agent: {value}"), PATH)
    assert places(result) == [("E-FIELD-TYPE", at("agent: invoice-reminder"), None)]
    assert only(result).params == {"field": "agent", "expected": "string", "found": value}
    assert "agent" not in result.data


def test_a_string_field_without_a_value_is_null():
    result = load(swap("agent: invoice-reminder", "agent:"), PATH)
    assert only(result).params == {"field": "agent", "expected": "string", "found": "null"}


@pytest.mark.parametrize("value", STRING_ACCEPTED.values(), ids=STRING_ACCEPTED)
def test_a_string_field_accepts_text_and_anything_quoted(value):
    result = load(swap("agent: invoice-reminder", f"agent: {value}"), PATH)
    assert result.findings == []
    assert isinstance(result.data["agent"], str)


def test_a_quoted_string_keeps_its_text():
    result = load(swap("agent: invoice-reminder", "agent: '  a  b '"), PATH)
    assert result.data["agent"] == "  a  b "


def test_list_entries_follow_the_same_rule_as_string_fields():
    result = load(swap("- gmail.draft", "- 123"), PATH)
    assert only(result).params == {"field": "tools.1", "expected": "string", "found": "123"}
    assert load(swap("- gmail.draft", '- "123"'), PATH).findings == []


# --- lists

LIST_ENTRY_REJECTED = {
    "integer": ("- 5", "5"),
    "true": ("- true", "true"),
    "null": ("- null", "null"),
    "no value": ("-", "null"),
    "list": ("- [a]", "list"),
    "mapping": ("- {a: b}", "mapping"),
    "mapping in block style": ("- a: b", "mapping"),
}


@pytest.mark.parametrize(("entry", "found"), LIST_ENTRY_REJECTED.values(), ids=LIST_ENTRY_REJECTED)
def test_a_list_entry_must_be_a_string(entry, found):
    result = load(swap("- gmail.draft", entry), PATH)
    assert places(result) == [("E-FIELD-TYPE", at("- gmail.draft"), None)]
    assert only(result).params == {"field": "tools.1", "expected": "string", "found": found}
    assert "tools" not in result.data  # the list is not usable, and its numbering stays whole
    assert set(result.lines) >= {"tools", "tools.0", "tools.1", "tools.2"}


@pytest.mark.parametrize(
    ("text", "found"), [("sheets.read", "sheets.read"), ("", "null"), ("{a: b}", "mapping")]
)
def test_a_list_field_must_be_a_list(text, found):
    result = load(front_without("tools") + f"tools: {text}".rstrip() + "\n", PATH)
    assert [f.params for f in result.findings] == [
        {"field": "tools", "expected": "list", "found": found}
    ]
    assert "tools" not in result.data


def repeated(path: str, entry: str) -> str:
    """Front matter text of `DATA` with `entry` added once more to the list at `path`."""

    def change(data):
        *parents, name = path.split(".")
        lookup(data, parents)[name].append(entry)

    return edited(change)


REPEATED = {
    "tools": ("tools", "sheets.read"),
    "forbidden": ("forbidden", "drive.share"),
    "scope.email_to": ("scope.email_to", "@aivenstudios.com"),
}


@pytest.mark.parametrize(("path", "entry"), REPEATED.values(), ids=REPEATED)
def test_a_repeated_list_entry_is_reported_at_the_later_line(path, entry):
    result = load(repeated(path, entry), PATH)
    (finding,) = result.findings
    assert finding.code == "E-LIST-DUPLICATE"
    assert finding.params == {"list": path, "entry": entry}
    *parents, name = path.split(".")
    repeat_at = len(lookup(DATA, parents)[name])  # the number of the entry that was added
    assert finding.line == result.lines[f"{path}.{repeat_at}"]
    assert message(finding, "en") == f"{path} lists {entry} more than once."
    assert result.data is not None  # a repeat is not a syntax problem


def test_the_list_keeps_every_entry_so_that_its_numbering_matches_the_lines():
    result = load(swap("- gmail.send\n", "- gmail.send\n  - sheets.read\n"), PATH)
    assert places(result) == [("E-LIST-DUPLICATE", SEND_LINE + 1, None)]
    assert result.data["tools"] == ["sheets.read", "gmail.draft", "gmail.send", "sheets.read"]
    assert result.lines["tools.3"] == SEND_LINE + 1


def test_every_repeat_after_the_first_is_reported():
    result = load(swap("- gmail.send\n", "- gmail.send\n  - sheets.read\n  - sheets.read\n"), PATH)
    assert [f.line for f in result.findings] == [SEND_LINE + 1, SEND_LINE + 2]


def test_quoting_does_not_make_an_entry_different():
    result = load(swap("- gmail.send\n", '- gmail.send\n  - "sheets.read"\n'), PATH)
    assert [f.code for f in result.findings] == ["E-LIST-DUPLICATE"]


def test_entries_that_differ_in_case_are_different():
    assert load(swap("- gmail.send\n", "- gmail.send\n  - Sheets.read\n"), PATH).findings == []


# --- mappings, missing fields and unknown fields


@pytest.mark.parametrize(("text", "found"), [("5", "5"), ("[a]", "list"), ("", "null")])
def test_a_mapping_field_must_be_a_mapping_and_its_children_are_then_not_missing(text, found):
    result = load(front_without("shadow") + f"shadow: {text}".rstrip() + "\n", PATH)
    assert [f.params for f in result.findings] == [
        {"field": "shadow", "expected": "mapping", "found": found}
    ]


REQUIRED_TOP_LEVEL = [name for name in FIELDS if name not in OPTIONAL]


@pytest.mark.parametrize("name", REQUIRED_TOP_LEVEL)
def test_a_missing_top_level_field_is_reported_at_line_one(name):
    result = load(front_without(name), PATH)
    assert places(result) == [("E-FIELD-MISSING", 1, None)]
    assert only(result).params == {"field": name}
    assert name not in result.data


NESTED = [f"{parent}.{name}" for parent in ("limits", "shadow") for name in FIELDS[parent]]


@pytest.mark.parametrize("path", NESTED)
def test_a_missing_nested_field_is_reported_at_the_line_of_its_parent(path):
    result = load(front_without(path), PATH)
    parent = path.split(".")[0]
    assert places(result) == [("E-FIELD-MISSING", result.lines[parent], None)]
    assert only(result).params == {"field": path}


@pytest.mark.parametrize("parent", ["limits", "shadow"])
def test_a_missing_parent_is_reported_once_and_not_for_each_child(parent):
    result = load(front_without(parent), PATH)
    assert [(f.code, f.line, f.params) for f in result.findings] == [
        ("E-FIELD-MISSING", 1, {"field": parent})
    ]


def test_an_empty_parent_mapping_misses_each_child_at_the_line_of_the_parent():
    result = load(front_without("limits") + "limits: {}\n", PATH)
    assert [(f.line, f.params["field"]) for f in result.findings] == [
        (result.lines["limits"], f"limits.{name}") for name in FIELDS["limits"]
    ]


def test_scope_and_its_fields_are_optional_here():
    assert load(front_without("scope"), PATH).findings == []
    assert load(front_without("scope.email_to"), PATH).findings == []
    assert load(front_without("scope.drive_folder_path", "scope.email_to"), PATH).findings == []
    nothing = front_without("scope.drive_folder_id", "scope.drive_folder_path", "scope.email_to")
    assert "scope: {}" in nothing
    assert load(nothing, PATH).findings == []


def test_every_missing_field_is_reported_in_the_order_of_the_field_table():
    result = load("", PATH)
    assert result.data == {}
    assert [(f.code, f.line, f.params["field"]) for f in result.findings] == [
        ("E-FIELD-MISSING", 1, name) for name in REQUIRED_TOP_LEVEL
    ]
    assert places(load("# nothing but a comment\n", PATH)) == places(result)


def test_a_field_with_a_null_value_is_a_type_error_not_a_missing_field():
    result = load(swap("agent: invoice-reminder", "agent:"), PATH)
    assert [f.code for f in result.findings] == ["E-FIELD-TYPE"]


UNKNOWN = {
    "top level": ("foo", lambda data: data.update(foo=1)),
    "in limits": ("limits.foo", lambda data: data["limits"].update(foo=1)),
    "in scope": ("scope.bar", lambda data: data["scope"].update(bar=1)),
    "in shadow": ("shadow.baz", lambda data: data["shadow"].update(baz=1)),
}


@pytest.mark.parametrize(("field", "change"), UNKNOWN.values(), ids=UNKNOWN)
def test_an_unknown_field_is_reported_at_its_line_with_its_path(field, change):
    text = edited(change)
    result = load(text, PATH)
    name = field.rsplit(".", 1)[-1]
    row = next(i for i, line in enumerate(text.split("\n")) if line.strip().startswith(f"{name}:"))
    assert places(result) == [("E-FIELD-UNKNOWN", FIRST_LINE + row, None)]
    assert only(result).params == {"field": field}
    assert name not in str(result.data)  # an unknown field is neither in the data
    assert field not in result.lines  # nor in the lines


def test_a_key_that_is_not_a_word_is_still_an_unknown_field():
    assert only(load("1: x\n", PATH), "E-FIELD-UNKNOWN").params == {"field": "1"}
    assert only(load(": x\n", PATH), "E-FIELD-UNKNOWN").params == {"field": "null"}


# --- the front matter as a whole


NOT_A_MAPPING = {
    "list": ("- a\n- b\n", "list"),
    "text": ("just text\n", "just text"),
    "null": ("null\n", "null"),
    "tilde": ("~\n", "~"),
    "quoted text": ('"text"\n', '"text"'),
}


@pytest.mark.parametrize(("front", "found"), NOT_A_MAPPING.values(), ids=NOT_A_MAPPING)
def test_a_front_matter_that_is_not_a_mapping_is_a_type_error(front, found):
    result = load(front, PATH)
    assert places(result) == [("E-FIELD-TYPE", FIRST_LINE, None)]
    assert only(result).params == {"field": "front matter", "expected": "mapping", "found": found}
    assert result.data is None


def test_a_front_matter_in_flow_style_is_read_like_any_other():
    assert load("{shadow: {min_runs: 10}}\n", PATH).data == {"shadow": {"min_runs": 10}}


# --- a placeholder skips the other checks of its field (validator-spec 3.1)
#
# E-PLACEHOLDER reads the text of the file as it is written, so "holds a placeholder" is judged on
# the text as written too, and not on the value after YAML has decoded it (ruling R37).


@pytest.mark.parametrize("placeholder", ["TBD", "TODO", "FIXME", "REPLACE_ME_RUNTIME"])
def test_an_integer_field_that_holds_a_placeholder_gets_no_type_error(placeholder):
    result = load(swap("max_runtime_s: 300", f"max_runtime_s: {placeholder}"), PATH)
    assert result.findings == []
    assert "max_runtime_s" not in result.data["limits"]
    assert result.lines["limits.max_runtime_s"] == at("max_runtime_s: 300")
    assert result.placeholders == {"limits.max_runtime_s"}


@pytest.mark.parametrize(
    ("text", "name"), [("tools: TODO\n", "tools"), ("limits: TBD\n", "limits")]
)
def test_a_list_or_mapping_field_that_holds_a_placeholder_gets_no_type_error(text, name):
    result = load(text, PATH)
    assert {f.code for f in result.findings} == {"E-FIELD-MISSING"}
    assert name not in {f.params["field"] for f in result.findings}
    assert result.placeholders == {name}


def test_a_string_field_that_holds_a_placeholder_keeps_its_text():
    result = load(swap("agent: invoice-reminder", "agent: REPLACE_ME_AGENT"), PATH)
    assert result.findings == []
    assert result.data["agent"] == "REPLACE_ME_AGENT"
    assert result.placeholders == {"agent"}


def test_placeholder_entries_are_not_repeats_of_each_other():
    result = load(swap("- gmail.send\n", "- gmail.send\n  - TODO\n  - TODO\n"), PATH)
    assert result.findings == []
    assert result.placeholders == {"tools.3", "tools.4"}


def test_a_value_is_a_placeholder_when_it_is_written_with_one_in_quotes_or_on_a_later_line():
    assert load(swap("agent: invoice-reminder", 'agent: "TODO"'), PATH).placeholders == {"agent"}
    assert load(swap("agent: invoice-reminder", "agent: invoice\n  TODO"), PATH).placeholders == {
        "agent"
    }


def test_the_template_holds_no_placeholder():
    assert load(FRONT, PATH).placeholders == frozenset()


# The same four letters can be written so that YAML decodes them to a placeholder and
# E-PLACEHOLDER, which reads the text as written, does not see one.
TODO_HEX = f'"T{BS}x4fDO"'  # TODO, with a hex escape
TODO_FOLDED = f'"TO{BS}\n    DO"'  # TODO, with an escaped line break

DISGUISED = {
    "limits.max_runtime_s": lambda v: swap("max_runtime_s: 300", f"max_runtime_s: {v}"),
    "version": lambda v: swap("version: 1", f"version: {v}"),
    "limits": lambda v: front_without("limits") + f"limits: {v}\n",
    "shadow": lambda v: front_without("shadow") + f"shadow: {v}\n",
    "tools": lambda v: front_without("tools") + f"tools: {v}\n",
    "forbidden": lambda v: front_without("forbidden") + f"forbidden: {v}\n",
    "scope.email_to": lambda v: front_without("scope") + f"scope: {{email_to: {v}}}\n",
}


@pytest.mark.parametrize("spelling", [TODO_HEX, TODO_FOLDED], ids=["hex escape", "line break"])
@pytest.mark.parametrize("field", DISGUISED)
def test_a_disguised_placeholder_is_an_escape_sequence_and_no_field_vanishes(field, spelling):
    # The escape is a feature, so there is no data, and so no field that could leave it unreported.
    text = DISGUISED[field](spelling)
    result = load(text, PATH)
    assert [f.params.get("feature") for f in result.findings] == ["escape sequence"]
    assert (result.data, result.lines, result.placeholders) == (None, {}, frozenset())
    assert unexplained(text, result) == []


# A value on a later line than its key is reported on its own line by E-PLACEHOLDER, and the key
# line, which is the line of the field, would have nothing: the type error is then not skipped.
LATER_LINE = {
    "continued plain scalar": swap("max_runtime_s: 300", "max_runtime_s: 300\n    TBD"),
    "value on the next line": swap("max_runtime_s: 300", "max_runtime_s:\n    TBD"),
    "quoted on the next line": swap("max_runtime_s: 300", 'max_runtime_s:\n    "TBD"'),
    "continued quoted scalar": swap("max_runtime_s: 300", 'max_runtime_s: "300\n    TBD"'),
}


@pytest.mark.parametrize("text", LATER_LINE.values(), ids=LATER_LINE)
def test_a_placeholder_on_a_later_line_does_not_hide_the_type_error_of_the_key_line(text):
    result = load(text, PATH)
    assert places(result) == [("E-FIELD-TYPE", at("max_runtime_s: 300"), None)]
    assert unexplained(text, result) == []


# --- no field leaves `data` without a finding
#
# Later checks read "not in `data`" as "already reported". `unexplained` finds the fields that
# have a line but no value and no finding, and every case of this module is run through it.


def all_cases() -> dict[str, str]:
    """The front matter text of every case in the tables of this module, by a label."""
    cases = {"the template": FRONT}
    for label, (value, _) in INTEGER_REJECTED.items():
        cases[f"integer rejected: {label}"] = swap(
            "max_runtime_s: 300", f"max_runtime_s: {value}".rstrip()
        )
    for label, digits in INTEGER_ACCEPTED.items():
        cases[f"integer accepted: {label}"] = swap("max_runtime_s: 300", f"max_runtime_s: {digits}")
    for label, value in STRING_REJECTED.items():
        cases[f"string rejected: {label}"] = swap("agent: invoice-reminder", f"agent: {value}")
    for label, value in STRING_ACCEPTED.items():
        cases[f"string accepted: {label}"] = swap("agent: invoice-reminder", f"agent: {value}")
    for label, (entry, _) in LIST_ENTRY_REJECTED.items():
        cases[f"list entry rejected: {label}"] = swap("- gmail.draft", entry)
    for value in ("TODO", "5 TBD", "[TODO]"):
        cases[f"list entry: {value}"] = swap("- gmail.draft", f"- {value}")
    for value in ("TODO", "TBD", "FIXME", "REPLACE_ME_X", "'TODO'", '"TBD"', "|\n    TODO"):
        cases[f"limit: {value}"] = swap("max_runtime_s: 300", f"max_runtime_s: {value}")
    for label, (path, entry) in REPEATED.items():
        cases[f"repeated entry: {label}"] = repeated(path, entry)
    for path in [*REQUIRED_TOP_LEVEL, *NESTED]:
        cases[f"missing: {path}"] = front_without(path)
    for label, (_, change) in UNKNOWN.items():
        cases[f"unknown: {label}"] = edited(change)
    for label, (front, _) in NOT_A_MAPPING.items():
        cases[f"not a mapping: {label}"] = front
    for label, text in LATER_LINE.items():
        cases[f"later line: {label}"] = text
    for field, make in DISGUISED.items():
        for spelling in (TODO_HEX, TODO_FOLDED, "TODO"):
            cases[f"{field} written as {spelling}"] = make(spelling)
    return cases


ALL_CASES = all_cases()


@pytest.mark.parametrize("text", ALL_CASES.values(), ids=ALL_CASES)
def test_no_case_of_this_module_makes_a_field_vanish_without_a_finding(text):
    assert unexplained(text, load(text, PATH)) == []


# --- E-FILENAME


def test_the_file_name_must_be_the_agent_id_and_md():
    expected = Finding(
        "E-FILENAME",
        "error",
        "policies/other.md",
        params={"name": "other.md", "agent": "invoice-reminder"},
    )
    front = load(FRONT, PATH)
    assert check_filename(Path("policies/other.md"), front) == [expected]
    assert check_filename(Path("elsewhere/invoice-reminder.md"), front) == []


@pytest.mark.parametrize(
    "name",
    [
        "Invoice-Reminder.md",
        "invoice-reminder.markdown",
        "invoice-reminder",
        "invoice-reminder.md.md",
    ],
)
def test_the_file_name_is_compared_exactly(name):
    findings = check_filename(Path("policies") / name, load(FRONT, PATH))
    assert [f.code for f in findings] == ["E-FILENAME"]


FILENAME_SKIPPED = {
    "missing": None,
    "integer": "agent: 5",
    "null": "agent:",
    "placeholder": "agent: REPLACE_ME_AGENT",
    "TODO": "agent: TODO",
    "TBD in the id": "agent: x-TBD",
    "placeholder in quotes": 'agent: "TODO"',
    "placeholder on a later line": "agent: invoice\n  TODO",
}


@pytest.mark.parametrize("agent", FILENAME_SKIPPED.values(), ids=FILENAME_SKIPPED)
def test_the_file_name_check_skips_an_agent_it_cannot_compare(agent):
    text = front_without("agent") if agent is None else swap("agent: invoice-reminder", agent)
    assert check_filename(Path("policies/other.md"), load(text, PATH)) == []


def test_the_file_name_check_skips_when_there_is_no_data():
    assert check_filename(Path("policies/other.md"), load("agent: [", PATH)) == []


def test_an_agent_with_an_escape_has_no_data_and_is_not_compared():
    front = load(swap("agent: invoice-reminder", f"agent: {TODO_HEX}"), PATH)
    assert [f.code for f in front.findings] == ["E-YAML-FEATURE"]
    assert check_filename(Path("policies/other.md"), front) == []


def test_the_file_name_check_goes_by_the_placeholders_that_load_found_not_by_the_text():
    # What the loader did not list as a placeholder is compared, whatever the value looks like.
    front = FrontMatter({"agent": "TODO"}, {"agent": 4}, [], frozenset())
    (finding,) = check_filename(Path("policies/other.md"), front)
    assert finding.params == {"name": "other.md", "agent": "TODO"}
    listed = FrontMatter({"agent": "TODO"}, {"agent": 4}, [], frozenset({"agent"}))
    assert check_filename(Path("policies/other.md"), listed) == []


# --- the field table of the spec


def spec_fields() -> list[str]:
    header, *rows = table_after("3.3 Fields")
    assert header[0] == "Field"
    return [code_spans(row[0])[0] for row in rows]


def leaves(fields: dict, prefix: str = "") -> dict[str, str]:
    found = {}
    for name, kind in fields.items():
        if isinstance(kind, dict):
            found.update(leaves(kind, f"{prefix}{name}."))
        else:
            found[f"{prefix}{name}"] = kind
    return found


def test_the_fields_are_the_rows_of_the_spec_table():
    assert list(leaves(FIELDS)) == spec_fields()


def test_the_integer_fields_are_the_ones_with_a_ceiling():
    integers = {path for path, kind in leaves(FIELDS).items() if kind == "integer"}
    assert integers == set(constants.CEILINGS)


def test_the_list_fields_include_the_ones_with_a_size_limit():
    lists = {path for path, kind in leaves(FIELDS).items() if kind == "list"}
    assert lists == {"tools", "forbidden", "scope.email_to"}
    assert set(constants.LIST_SIZES) <= lists


def test_only_scope_is_optional():
    assert OPTIONAL == {"scope"}
    assert "except `scope.*`" in line_starting_with("Every front matter field is enforced")
