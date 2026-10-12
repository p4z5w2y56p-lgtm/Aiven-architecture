"""Findings and messages: the JSON files equal validator-spec appendix A, word for word."""

import json
import re
import string
from dataclasses import FrozenInstanceError, replace

import pytest

from aiven.policy.findings import Finding, format_line, load_messages, message
from tests.support import REPO_ROOT
from tests.support.spec_tables import table_after

MESSAGES_DIR = REPO_ROOT / "src" / "aiven" / "policy" / "messages"


def _appendix_rows() -> list[list[str]]:
    header, *rows = table_after("Appendix A. Messages")
    assert header == ["Code", "EN", "NL"]
    return rows


def _fields(template: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(template) if name is not None}


def test_messages_match_spec_appendix():
    rows = _appendix_rows()
    assert len(rows) == 65
    for lang, column in (("en", 1), ("nl", 2)):
        shipped = json.loads((MESSAGES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        expected = {row[0]: row[column] for row in rows}
        assert len(shipped) == 65
        assert shipped == expected
        assert list(shipped) == list(expected), "keep the spec's order, so the diffs line up"


@pytest.mark.parametrize("lang", ["en", "nl"])
def test_load_messages_reads_the_shipped_file(lang):
    shipped = json.loads((MESSAGES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
    assert dict(load_messages(lang)) == shipped


def test_english_and_dutch_have_the_same_codes_and_parameters():
    en, nl = load_messages("en"), load_messages("nl")
    assert list(en) == list(nl)
    for code in en:
        assert _fields(en[code]) == _fields(nl[code]), code


@pytest.mark.parametrize("lang", ["en", "nl"])
def test_templates_use_only_plain_named_fields(lang):
    # str.format_map would also honour {a.b}, {a[0]}, {a!r} and {a:>5}; a message must not.
    for code, template in load_messages(lang).items():
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is None:
                continue
            assert re.fullmatch(r"[a-z_]+", name), (code, name)
            assert spec == "" and conversion is None, (code, template)


@pytest.mark.parametrize("lang", ["en", "nl"])
def test_every_message_formats_with_exactly_its_own_parameters(lang):
    # Includes the keyword-named {class} field of E-TOOL-ABOVE-MAX-CLASS.
    for code, template in load_messages(lang).items():
        params = {name: f"<{name}>" for name in _fields(template)}
        text = message(Finding(code, "error", "a.md", params=params), lang)
        assert "{" not in text and "}" not in text, code
        for name in params:
            assert f"<{name}>" in text, (code, name)


def test_finding_defaults_describe_a_file_level_finding():
    a = Finding("E-FINAL-NEWLINE", "error", "policies/a.md")
    b = Finding("E-FINAL-NEWLINE", "error", "policies/a.md")
    assert (a.line, a.column, a.params) == (None, None, {})
    assert a.params is not b.params


def test_finding_is_frozen_comparable_and_hashable():
    f = Finding("E-RANGE", "error", "a.md", 3, 5, {"field": "version"})
    with pytest.raises(FrozenInstanceError):
        f.code = "E-OTHER"
    assert f == Finding("E-RANGE", "error", "a.md", 3, 5, {"field": "version"})
    assert f != replace(f, params={"field": "limits.runs_per_day"})
    assert len({f, Finding("E-RANGE", "error", "a.md", 3, 5, {"field": "version"})}) == 1


def test_message_fills_parameters_in_both_languages():
    f = Finding("E-FILE-SIZE", "error", "policies/a.md", params={"size": "70000"})
    assert message(f, "en") == "File is 70000 bytes; the maximum is 65536."
    assert message(f, "nl") == "Bestand is 70000 bytes; het maximum is 65536."


def test_message_without_parameters_is_the_template():
    f = Finding("E-FINAL-NEWLINE", "error", "a.md")
    assert message(f, "en") == "The file must end with exactly one newline."
    assert message(f, "nl") == "Het bestand moet eindigen op precies één regeleinde."


def test_message_does_not_reinterpret_braces_inside_values():
    f = Finding("E-INTERNAL", "error", "a.md", params={"detail": "{tool} {0} {__class__}"})
    assert message(f, "en") == (
        "The validator could not finish ({tool} {0} {__class__}). The file counts as invalid."
    )


def test_message_with_a_missing_parameter_fails_loudly():
    with pytest.raises(KeyError):
        message(Finding("E-FILE-SIZE", "error", "a.md"), "en")


def test_message_for_an_unknown_code_fails_loudly():
    with pytest.raises(KeyError):
        message(Finding("E-NO-SUCH-CODE", "error", "a.md"), "en")


def test_message_for_an_unknown_language_fails_loudly():
    with pytest.raises(ValueError, match="language"):
        message(Finding("E-FINAL-NEWLINE", "error", "a.md"), "de")


def test_format_line_with_a_line_number():
    f = Finding(
        "E-PLACEHOLDER",
        "error",
        "policy-template.md",
        6,
        38,
        {"token": "REPLACE_ME_AGENTS_PROJECT"},
    )
    assert format_line(f) == (
        "error E-PLACEHOLDER policy-template.md:6: "
        "Placeholder REPLACE_ME_AGENTS_PROJECT is still there. Fill it in before signing."
    )


def test_format_line_omits_the_line_for_a_file_level_finding():
    f = Finding(
        "E-FILENAME",
        "error",
        "policy-template.md",
        None,
        None,
        {"name": "policy-template.md", "agent": "invoice-reminder"},
    )
    assert format_line(f) == (
        "error E-FILENAME policy-template.md: File name policy-template.md must be "
        "invoice-reminder.md."
    )


def test_format_line_always_uses_the_english_text():
    f = Finding(
        "W-TOOL-NOT-LIVE",
        "warning",
        "policy-template.md",
        9,
        5,
        {"tool": "sheets.read", "wrapper": "Drive"},
    )
    assert format_line(f).startswith(
        "warning W-TOOL-NOT-LIVE policy-template.md:9: Tool sheets.read needs the Drive wrapper"
    )
