"""Findings and messages: the JSON files equal validator-spec appendix A, word for word."""

import json
import re
import string
from dataclasses import FrozenInstanceError, replace

import pytest

from aiven.policy.findings import Finding, format_line, load_messages, message
from tests.support import REPO_ROOT, gen
from tests.support.spec_tables import line_starting_with, table_after

MESSAGES_DIR = REPO_ROOT / "src" / "aiven" / "policy" / "messages"

WIDENS = {"changes": "tools: +drive.read; limits.runs_per_day: 1 -> 2"}


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
    # Includes the keyword-named {class} field of E-TOOL-ABOVE-MAX-CLASS. The {restart} of
    # W-WIDENS is not a param: `message` makes it from the param restart_runs (see below).
    for code, template in load_messages(lang).items():
        names = {"restart_runs" if name == "restart" else name for name in _fields(template)}
        params = {name: f"<{name}>" for name in names}
        text = message(Finding(code, "error", "a.md", params=params), lang)
        assert "{" not in text and "}" not in text, code
        for name in params:
            assert f"<{name}>" in text, (code, name)


# --- W-WIDENS: the {restart} of its message is a sentence of the language (rulings R55 and R75)


def _restart_sentences() -> dict[str, tuple[str, str]]:
    """The four sentences of the note under appendix A, with their leading space.

    For each language the sentence for `{n}` runs, and the one for a single run. The note gives
    them in the order EN and NL for `{n}` runs, then EN and NL for 1 run.
    """
    note = line_starting_with("For W-WIDENS, ")
    sentences = re.findall(r'"([^"]*)"', note)
    assert len(sentences) == 4, note
    assert "when {n} is 1," in note  # the rule that tells them apart
    en_many, nl_many, en_one, nl_one = sentences
    return {"en": (en_many, en_one), "nl": (nl_many, nl_one)}


@pytest.mark.parametrize("lang", ["en", "nl"])
def test_widens_restart_is_the_sentence_of_the_note_under_appendix_a(lang):
    # Drift: the code says what the note under appendix A says, word for word, in both languages,
    # for a number of runs and for one run.
    many, one = _restart_sentences()[lang]
    assert many.startswith(" ") and many.count("{n}") == 1
    assert one.startswith(" ") and "{n}" not in one and one.endswith(" 1 run.")
    template = load_messages(lang)["W-WIDENS"]
    for runs, sentence in [("12", many.replace("{n}", "12")), ("1", one)]:
        finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": runs})
        assert message(finding, lang) == template.format(**WIDENS, restart=sentence), runs


def test_widens_restart_in_full():
    finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": "10"})
    assert message(finding, "en") == (
        "This version gives the agent more room: tools: +drive.read; limits.runs_per_day: 1 -> 2."
        " Shadow mode starts again for 10 runs."
    )
    assert message(finding, "nl") == (
        "Deze versie geeft de agent meer ruimte: tools: +drive.read; limits.runs_per_day: 1 -> 2."
        " De schaduwmodus begint opnieuw voor 10 runs."
    )


@pytest.mark.parametrize(
    ("lang", "tail"),
    [
        ("en", " Shadow mode starts again for 1 run."),
        ("nl", " De schaduwmodus begint opnieuw voor 1 run."),
    ],
)
def test_widens_restart_for_one_run_is_in_the_singular(lang, tail):
    finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": "1"})
    text = message(finding, lang)
    assert text.endswith(f"limits.runs_per_day: 1 -> 2.{tail}")
    assert " 1 runs" not in text


@pytest.mark.parametrize("lang", ["en", "nl"])
@pytest.mark.parametrize("runs", ["0", "2", "10", "11", "100"])
def test_widens_restart_is_in_the_plural_for_every_number_but_one(lang, runs):
    # Only 1 is the singular: 10, 11 and 100 have a 1 in them and are not.
    finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": runs})
    many, _ = _restart_sentences()[lang]
    assert message(finding, lang).endswith(many.replace("{n}", runs))


@pytest.mark.parametrize("lang", ["en", "nl"])
def test_widens_without_restart_runs_ends_after_the_changes(lang):
    # Empty when the param is absent: the message ends in the full stop behind the changes.
    finding = Finding("W-WIDENS", "warning", "a.md", params=WIDENS)
    text = message(finding, lang)
    assert text.endswith("limits.runs_per_day: 1 -> 2.")
    assert text == load_messages(lang)["W-WIDENS"].format(**WIDENS, restart="")


def test_an_empty_number_of_runs_is_not_an_absent_one():
    # Only a missing param means that shadow mode does not start again. An empty number is a bug
    # of the check, and the message still says that it does, rather than saying nothing.
    finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": ""})
    assert message(finding, "en").endswith(" Shadow mode starts again for  runs.")


def test_widens_restart_is_in_the_one_line_form():
    finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": "3"})
    assert format_line(finding) == f"warning W-WIDENS a.md: {message(finding, 'en')}"
    assert format_line(finding).endswith(" Shadow mode starts again for 3 runs.")


@pytest.mark.parametrize("lang", ["en", "nl"])
def test_the_number_of_the_restart_sentence_is_cleaned_like_every_param(lang):
    # `message` cleans the params first and puts the sentence together after that, so the number
    # is cleaned (escaped, hidden, cut) and the sentence around it is the note's own.
    finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": "7"})
    sentence, _ = _restart_sentences()[lang]
    for dirty, shown in [
        ("7\nerror E-FORGED y.md: z", "7\\u000aerror E-FORGED y.md: z"),
        (gen.valid_bsn(), "[hidden]"),
        ("{changes} {0}", "{changes} {0}"),
    ]:
        finding.params["restart_runs"] = dirty  # the dict is not frozen: cleaned again at output
        text = message(finding, lang)
        assert text.endswith(sentence.replace("{n}", shown))
        assert text.splitlines() == [text]


def test_widens_with_an_unknown_language_still_fails_loudly():
    finding = Finding("W-WIDENS", "warning", "a.md", params={**WIDENS, "restart_runs": "10"})
    with pytest.raises(ValueError, match="language"):
        message(finding, "de")


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
