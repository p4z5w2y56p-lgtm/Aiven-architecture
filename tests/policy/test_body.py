"""The body checks (validator-spec 3.7) that are about the shape of the body: `check_body` is called
with a body and its policy, and the cases look at the codes and lines of what it finds.

The table of one new finding for each code is in test_codes.py. Here are the rules of the rulings
(R15, R27 to R29, R33, R46 to R48) that need more than one case each. The checks for HTML, links and
text that is hidden from the reader are in test_body_markup.py.
"""

from dataclasses import replace

import pytest

from aiven.policy.body import _bullets, _drift, _last_row, _Report, check_body
from aiven.policy.fileformat import decode_text
from aiven.policy.findings import Finding, format_line, message
from aiven.policy.frontmatter import split
from aiven.policy.markdown import headings, parse
from aiven.policy.validate import validate_file
from tests.support import gen
from tests.support.bodies import (
    BASE,
    BODY,
    ENFORCED,
    FIRST_LINE,
    POLICY,
    SECTION_NAMES,
    SIGNOFF,
    added_after,
    at,
    codes,
    edited,
    only,
    places,
    policy_of,
    run,
)
from tests.support.policies import BASE_PATH, TEMPLATE_PATH
from tests.support.rules import CATALOG, CFG

TEMPLATE = TEMPLATE_PATH.read_bytes()

WHY = "## Why each tool"
PURPOSE = "Once a day, this agent reads"
STOP = "Stop: the agent kill switch"
DRAFT_BULLET = "- `gmail.draft`: writes one internal reminder draft"


# --- the bodies of the base and of the template are fine


def test_the_body_of_the_base_has_no_finding():
    assert run() == []


def test_the_body_of_the_template_has_no_finding_either():
    # Its two placeholders stand in the front matter and in the generated sections alike.
    _, body, first_line = split(decode_text(TEMPLATE))
    assert check_body(body, first_line, policy_of(TEMPLATE), CATALOG, BASE_PATH) == []


def test_without_a_policy_the_base_has_no_finding_either():
    assert run(policy=None) == []


def test_the_findings_are_errors_on_the_path_that_was_given_and_the_lines_start_at_the_body():
    found = run(edited("no email goes to clients.", "no email goes to clients. <b>"))
    assert [(f.code, f.severity, f.path, f.column) for f in found] == [
        ("E-BODY-HTML", "error", str(BASE_PATH), None)
    ]
    shifted = run(
        edited("no email goes to clients.", "no email goes to clients. <b>"), first_line=100
    )
    assert shifted[0].line == found[0].line - FIRST_LINE + 100


# --- E-BODY-TITLE


TITLE_LINE = at("# invoice-reminder")


@pytest.mark.parametrize(
    "title",
    [
        "# Invoice Reminder",
        "# invoice-reminder ",
        "#invoice-reminder",
        "#  invoice-reminder",
        "  # invoice-reminder",
        "# invoice-reminder #",
        "## invoice-reminder",
        "invoice-reminder",
        "# invoice-reminder-2",
    ],
)
def test_a_first_line_that_is_not_exactly_the_title_is_reported_on_that_line(title):
    found = only(run(edited("\n# invoice-reminder\n", f"\n{title}\n")), "E-BODY-TITLE")
    assert [(f.line, f.params) for f in found] == [(TITLE_LINE, {"agent": "invoice-reminder"})]


def test_the_title_is_the_first_line_that_is_not_empty_so_blank_lines_before_it_are_fine():
    body = edited("\n# invoice-reminder\n", "\n \n\t\n# invoice-reminder\n")
    assert only(run(body), "E-BODY-TITLE") == []


def test_text_before_the_title_is_reported_on_its_line_and_the_title_is_then_a_second_heading():
    body = edited("\n# invoice-reminder\n", "\nSome text.\n\n# invoice-reminder\n")
    assert places(run(body)) == [("E-BODY-SECTIONS", TITLE_LINE + 2), ("E-BODY-TITLE", TITLE_LINE)]


@pytest.mark.parametrize("body", ["", "\n", "\n\n \n\t\n"])
def test_an_empty_body_is_reported_on_its_first_line(body):
    found = only(run(body), "E-BODY-TITLE")
    assert [(f.line, f.params) for f in found] == [(FIRST_LINE, {"agent": "invoice-reminder"})]


def test_the_title_is_that_of_the_agent_of_the_policy():
    found = only(run(policy=replace(POLICY, agent="other-agent")), "E-BODY-TITLE")
    assert [(f.line, f.params) for f in found] == [(TITLE_LINE, {"agent": "other-agent"})]


def test_the_title_is_not_checked_when_it_is_switched_off_or_there_is_no_policy():
    wrong = edited("# invoice-reminder", "# other")
    assert only(run(wrong), "E-BODY-TITLE") != []
    assert only(run(wrong, title=False), "E-BODY-TITLE") == []
    assert only(run(wrong, policy=None), "E-BODY-TITLE") == []


# --- E-BODY-SECTIONS


def body_of(*names: str, text: str = "Some text for the section that is long enough.") -> str:
    """A body with the title and one section for each name, whatever it is: 4 rows a section."""
    parts = ["", "# invoice-reminder", *[f"## {name}\n\n{text}" for name in names]]
    return "\n\n".join(parts) + "\n"


def heading_line(index: int) -> int:
    """The file line of the heading of the section with this index in a `body_of`."""
    return FIRST_LINE + 4 + 4 * index


def sections_of(body: str) -> list[Finding]:
    return only(run(body, policy=None), "E-BODY-SECTIONS")


def test_the_five_sections_in_order_are_fine():
    assert sections_of(body_of(*SECTION_NAMES)) == []


@pytest.mark.parametrize("missing", range(5), ids=SECTION_NAMES)
def test_a_section_that_is_missing_is_reported_on_the_first_line_of_the_body(missing):
    names = [name for number, name in enumerate(SECTION_NAMES) if number != missing]
    (found,) = sections_of(body_of(*names))
    assert found.line == FIRST_LINE
    assert found.params == {"found": ", ".join(names)}


def test_a_body_with_no_section_is_reported_on_its_first_line_with_nothing_found():
    (found,) = sections_of(body_of())
    assert (found.line, found.params) == (FIRST_LINE, {"found": ""})


def test_a_heading_that_is_not_one_of_the_sections_is_reported_on_its_own_line():
    names = [SECTION_NAMES[0], SECTION_NAMES[1], "Data and risk", *SECTION_NAMES[3:]]
    (found,) = sections_of(body_of(*names))  # a section is missing too, and this is the better line
    assert found.line == heading_line(2)
    assert found.params["found"] == ", ".join(names)


def test_an_unknown_heading_is_reported_before_a_missing_section():
    names = [SECTION_NAMES[0], "Notes", SECTION_NAMES[2], *SECTION_NAMES[3:]]  # no Why each tool
    (found,) = sections_of(body_of(*names))
    assert found.line == heading_line(1)


S = SECTION_NAMES
OUT_OF_PLACE = {
    "an extra one first": (["Notes", *S], 0),
    "an extra one after the first": ([S[0], "Notes", *S[1:]], 1),
    "an extra one in the middle": ([*S[:3], "Notes", *S[3:]], 3),
    "an extra one before the last": ([*S[:4], "Notes", S[4]], 4),
    "an extra one at the end": ([*S, "Notes"], 5),
    "the first one twice": (["Purpose", *S], 1),
    "a copy after the second": ([S[0], S[1], "Purpose", *S[2:]], 2),
    "a copy at the end": ([*S, "Why each tool"], 5),
    "the first two swapped": ([S[1], S[0], *S[2:]], 0),
    "the last two swapped": ([*S[:3], S[4], S[3]], 3),
    "all of them reversed": (S[::-1], 0),
    "a name in lower case": ([*S[:2], "data and risks", *S[3:]], 2),
}


@pytest.mark.parametrize(("names", "index"), OUT_OF_PLACE.values(), ids=OUT_OF_PLACE)
def test_a_heading_that_is_not_where_the_sections_have_it_is_reported_on_its_line(names, index):
    (found,) = sections_of(body_of(*names))
    assert found.line == heading_line(index)
    assert found.params == {"found": ", ".join(names)}


def test_only_the_names_as_written_are_the_sections():
    for name in ("**Purpose**", "`Purpose`", "Purpose:", "PURPOSE", "Purpose &amp; more"):
        assert len(sections_of(body_of(name, *SECTION_NAMES[1:]))) == 1, name


def test_a_heading_in_setext_style_is_a_heading_too():
    assert sections_of(edited("## Purpose\n", "Purpose\n-------\n")) == []
    assert len(sections_of(edited("## Purpose\n", "Notes\n-----\n"))) == 1


def test_a_second_title_is_reported_on_its_line_and_the_title_is_not():
    body = added_after(PURPOSE, "\n# Another title")
    assert [f.line for f in sections_of(body)] == [at("# Another title", body)]
    body = added_after(PURPOSE, "\nAnother title\n=============")
    assert [f.line for f in sections_of(body)] == [at("Another title", body)]


def test_every_wrong_heading_is_reported_on_its_own_line_and_a_missing_section_once():
    names = [*SECTION_NAMES[:2], *SECTION_NAMES[3:]]  # Data and risks is missing
    body = body_of(*names) + "\n# One\n\n### Three\n"
    assert sorted(f.line for f in sections_of(body)) == [
        FIRST_LINE,
        at("# One", body),
        at("### Three", body),
    ]


@pytest.mark.parametrize("level", [3, 4, 5, 6])
@pytest.mark.parametrize("inside", SECTION_NAMES[:3])
def test_a_heading_of_level_3_to_6_is_fine_inside_the_first_three_sections(level, inside):
    body = edited(
        f"## {inside}\n", f"## {inside}\n\n{'#' * level} Details\n", body_of(*SECTION_NAMES)
    )
    assert sections_of(body) == []


@pytest.mark.parametrize("level", [3, 6])
@pytest.mark.parametrize(
    "after",
    ["# invoice-reminder", ENFORCED, SIGNOFF],
    ids=["before the first section", "in the fourth", "in the fifth"],
)
def test_a_heading_of_level_3_to_6_anywhere_else_is_reported_on_its_line(level, after):
    heading = "#" * level + " Details"
    body = edited(f"{after}\n", f"{after}\n\n{heading}\n")
    assert [f.line for f in sections_of(body)] == [at(heading, body)]


def test_a_heading_of_level_3_is_reported_too_when_there_is_no_section_to_be_in():
    body = body_of() + "\n### Lonely\n"
    assert sorted(f.line for f in sections_of(body)) == [FIRST_LINE, at("### Lonely", body)]


def test_a_heading_of_level_3_after_the_last_section_is_reported_too():
    body = body_of(*SECTION_NAMES) + "\n### Late\n"
    assert [f.line for f in sections_of(body)] == [at("### Late", body)]


def test_a_heading_in_a_quote_or_a_list_is_a_heading_too():
    body = added_after(PURPOSE, "\n> ## Quoted section\n\n- ### Item heading")
    assert [f.line for f in sections_of(body)] == [
        at("> ## Quoted section", body)
    ]  # level 3 is fine


@pytest.mark.parametrize("mark", ["> ", "- ", "1. ", "> - "])
@pytest.mark.parametrize("name", SECTION_NAMES)
def test_a_section_heading_in_a_quote_or_a_list_is_no_section_so_it_is_reported(mark, name):
    # A section is a heading at the top level of the document (ruling R64). A copy in a quote does
    # not make up for the section that is not there, though the names then read right.
    body = edited(f"## {name}\n", f"{mark}## {name}\n")
    (found,) = sections_of(body)
    assert found.line == at(f"{mark}## {name}", body)


def test_a_heading_in_a_code_block_is_no_heading():
    body = added_after(PURPOSE, "\n```\n## Not a section\n# Not a title\n```\n\n    ## Nor this")
    assert sections_of(body) == []


def test_the_found_names_are_cleaned_like_every_text_of_the_file():
    key = gen.secret_values()["AWS access key"][0]
    (found,) = sections_of(body_of(*SECTION_NAMES[:3], key))
    assert key not in found.params["found"]
    assert key not in format_line(found) and key not in message(found, "nl")


def test_the_message_names_what_was_found_in_both_languages():
    (found,) = sections_of(body_of("Purpose"))
    assert message(found, "en").endswith("Found: Purpose.")
    assert message(found, "nl").endswith("Gevonden: Purpose.")


# --- E-BODY-EMPTY


def section_with(name: str, text: str) -> str:
    """The base body with the content of a section replaced by `text`, whatever its blocks were."""
    lines = BODY.split("\n")
    start = lines.index(f"## {name}") + 1
    end = lines.index(f"## {SECTION_NAMES[SECTION_NAMES.index(name) + 1]}")
    return "\n".join([*lines[:start], "", text, "", *lines[end:]])


def empty_of(body: str) -> list[tuple[str, int]]:
    return [(f.params["section"], f.line) for f in only(run(body), "E-BODY-EMPTY")]


@pytest.mark.parametrize("name", SECTION_NAMES[:3])
def test_a_section_with_fewer_than_20_characters_of_text_is_empty_on_the_line_of_its_heading(name):
    body = section_with(name, "x" * 19)
    assert empty_of(body) == [(name, at(f"## {name}", body))]
    assert empty_of(section_with(name, "x" * 20)) == []


def test_the_generated_sections_are_not_judged_by_their_length():
    body = BODY[: BODY.index(ENFORCED)] + f"{ENFORCED}\n\nshort\n\n{SIGNOFF}\n\nshort\n"
    assert empty_of(body) == []


def test_an_empty_section_is_one_finding_with_its_name_and_nothing_else_is_said_about_it():
    found = run(section_with("Purpose", ""))
    assert [(f.code, f.params) for f in found] == [("E-BODY-EMPTY", {"section": "Purpose"})]


@pytest.mark.parametrize(
    ("text", "length"),
    [
        ("a   b     c", 5),  # runs of whitespace count as one space
        ("a\tb", 2),  # a tab is a hidden character, and a hidden character is no text
        ("  padded  ", 6),  # and the ends are cut
        ("ab\ncd", 5),  # a line break in a paragraph counts as one space
        ("`code`", 4),  # a code span counts, without its backticks
        ("*em* and **strong**", 13),  # the markers do not
        ("first\n\nsecond", 12),  # two paragraphs are two texts with a space between them
        ("- one\n- two", 7),
        ("| a | b |\n|---|---|\n| c | d |", 7),
        ("one\\\ntwo", 6),  # a hard break is not counted: only text, code and soft breaks are
    ],
)
def test_what_counts_as_text_and_how(text, length):
    for total, is_empty in ((19, True), (20, False)):
        padding = "x" * (total - length - 1)  # the padding is a text of its own: one more space
        body = section_with("Purpose", f"{text}\n\n{padding}")
        assert (empty_of(body) != []) == is_empty


def test_a_heading_inside_the_section_counts_as_text_and_the_heading_of_the_section_does_not():
    assert empty_of(section_with("Purpose", "### " + "x" * 20)) == []
    assert empty_of(section_with("Purpose", "")) != []


@pytest.mark.parametrize(
    "block",
    [
        "```\n" + "x" * 30 + "\n```",
        "    " + "x" * 30,
        "<div>\n" + "x" * 30 + "\n</div>",
        "![" + "x" * 30 + "](b)",
    ],
    ids=["a fence", "indented code", "html", "an image"],
)
def test_code_blocks_html_and_images_are_not_text(block):
    assert [name for name, _ in empty_of(section_with("Purpose", block))] == ["Purpose"]


@pytest.mark.parametrize(
    "hidden",
    [
        "&#8203;",
        "&#x202E;",
        "&#xE0041;",
        "&nbsp;",
        "\N{ZERO WIDTH SPACE}",
        "\N{TAG LATIN SMALL LETTER A}",
    ],
    ids=[
        "zero width",
        "override",
        "tag letter",
        "no-break space",
        "written zero width",
        "written tag",
    ],
)
def test_characters_that_the_reader_cannot_see_are_not_text(hidden):
    # Twenty of them is nothing, and the written ones are E-HIDDEN-CHAR's as well (a file check).
    assert [name for name, _ in empty_of(section_with("Purpose", hidden * 20))] == ["Purpose"]
    # and they do not help a short text to reach 20 characters
    assert [name for name, _ in empty_of(section_with("Purpose", "Short. " + hidden * 20))] == [
        "Purpose"
    ]
    # while the same text without them, long enough, is fine
    assert empty_of(section_with("Purpose", "A sentence that is long." + hidden * 3)) == []


@pytest.mark.parametrize(
    "shown",
    [
        "\N{LATIN SMALL LETTER E WITH ACUTE}",
        "\N{CJK UNIFIED IDEOGRAPH-4E2D}",
        "\N{GREEK SMALL LETTER ALPHA}",
        "\N{EURO SIGN}",
    ],
)
def test_characters_that_show_are_text_also_when_they_are_not_ascii(shown):
    assert empty_of(section_with("Purpose", shown * 20)) == []
    assert [name for name, _ in empty_of(section_with("Purpose", shown * 19))] == ["Purpose"]
    assert tools_of(edited(BULLET, f"- `gmail.draft`: {shown}")) == []


def test_a_list_item_that_is_cut_off_is_left_alone_and_is_not_an_error():
    # A section does not end inside an item, but the check must not depend on that.
    tokens = parse("- `a`: reason\n")
    item = next(index for index, token in enumerate(tokens) if token.type == "list_item_open")
    assert [name for _, name, _ in _bullets(tokens)] == ["a"]
    assert list(_bullets(tokens[: item + 1])) == []  # nothing behind the item
    assert list(_bullets(tokens[: item + 2])) == []  # the paragraph is opened, and nothing more


def test_a_nested_heading_does_not_end_the_text_of_a_section_it_is_in():
    # A heading of level 2 in a quote is reported, and the text on both sides of it is Purpose's.
    body = section_with("Purpose", "Short.\n\n> ## Quoted\n\n" + "x" * 30)
    assert empty_of(body) == []
    assert [f.line for f in only(run(body), "E-BODY-SECTIONS")] == [at("> ## Quoted", body)]


@pytest.mark.parametrize("name", ["Purpose", "Why each tool"])
def test_a_copy_of_the_heading_of_a_free_section_in_a_quote_is_not_the_section_to_judge(name):
    # In front of the real one it must not stand in for it: its text would be empty, or it would
    # have no bullets. Only the copy is reported, for it is not one of the five sections.
    body = edited(f"## {name}\n", f"> ## {name}\n\n## {name}\n")
    assert codes(run(body)) == ["E-BODY-SECTIONS"]


def test_a_heading_of_level_2_in_a_quote_does_not_move_the_end_of_the_first_three_sections():
    # Behind it the fourth `##` heading would be Data and risks, and a heading of level 3 in it
    # would be reported. The quoted one is the only finding.
    body = added_after(PURPOSE, "\n> ## Quoted")
    body = added_after("- Reads: only the tracker", "\n### Details", body)
    assert [f.line for f in only(run(body), "E-BODY-SECTIONS")] == [at("> ## Quoted", body)]


def test_a_section_that_is_not_there_is_not_empty():
    assert only(run(body_of(*SECTION_NAMES[1:]), policy=None), "E-BODY-EMPTY") == []


# --- the tools: E-BODY-TOOL-UNEXPLAINED and E-BODY-TOOL-EXTRA


WHY_LINE = at(WHY)


def tools_of(body: str, **kw) -> list[tuple[str, int, str]]:
    """(code, line, tool) of the findings about tools, in the order they were made."""
    found = [f for f in run(body, **kw) if f.code.startswith("E-BODY-TOOL")]
    return [(f.code, f.line, f.params["tool"]) for f in found]


def without_bullets(body: str, *tools: str) -> str:
    """The body without the bullets of Why each tool for these tools."""
    lines = body.split("\n")
    start, end = lines.index(WHY), lines.index("## Data and risks")
    drop = {f"- `{tool}`:" for tool in tools}
    return "\n".join(
        line
        for row, line in enumerate(lines)
        if not (start < row < end and any(line.startswith(bullet) for bullet in drop))
    )


def test_a_tool_without_a_bullet_is_reported_on_the_line_of_why_each_tool_in_the_order_of_tools():
    body = without_bullets(BODY, "gmail.draft", "sheets.read")
    assert tools_of(body) == [
        ("E-BODY-TOOL-UNEXPLAINED", WHY_LINE, "sheets.read"),
        ("E-BODY-TOOL-UNEXPLAINED", WHY_LINE, "gmail.draft"),
    ]


BULLET = next(line for line in BODY.split("\n") if line.startswith(DRAFT_BULLET))


@pytest.mark.parametrize(
    "bullet",
    [
        "- `gmail.draft`:",
        "- `gmail.draft`:   ",
        "- `gmail.draft` writes drafts",
        "- `gmail.draft` : writes drafts",
        "- `gmail.draft`; writes drafts",
        "- gmail.draft: writes drafts",
        "- The tool `gmail.draft`: writes drafts",
        "- **`gmail.draft`**: writes drafts",
        "- `gmail.drafts`: writes drafts",
        "- `Gmail.draft`: writes drafts",
        "- `gmail.draft `: writes drafts",
        "- `gmail.draft` and `gmail.send`: write drafts",
        "- Writes drafts: `gmail.draft`",
        "- `gmail.draft`: ` `",
        "`gmail.draft`: writes drafts",
        "- \\`gmail.draft`: writes drafts",
    ],
)
def test_a_bullet_that_does_not_have_the_form_does_not_explain_the_tool(bullet):
    found = tools_of(edited(BULLET, bullet))
    assert ("E-BODY-TOOL-UNEXPLAINED", WHY_LINE, "gmail.draft") in found


@pytest.mark.parametrize(
    "bullet",
    [
        "- `gmail.draft`: writes drafts",
        "- `gmail.draft`:writes drafts",
        "- `gmail.draft`: .",
        "- `gmail.draft`: *writes* drafts",
        "- `gmail.draft`: `x`",
        "- `gmail.draft`: a\n  second line",
        "- `gmail.draft`:\n  writes drafts",
        "* `gmail.draft`: writes drafts",
        "+ `gmail.draft`: writes drafts",
        "1. `gmail.draft`: writes drafts",
        "- `gmail.draft`: writes drafts\n  - `gmail.draft`: and more",
    ],
)
def test_a_bullet_with_a_code_span_a_colon_and_a_reason_explains_the_tool(bullet):
    assert tools_of(edited(BULLET, bullet)) == []


@pytest.mark.parametrize(
    "hidden",
    ["&#8203;", "&#x202E;", "&nbsp;", "\N{ZERO WIDTH SPACE}", "\N{TAG LATIN SMALL LETTER A}"],
)
def test_a_reason_that_is_only_characters_that_the_reader_cannot_see_is_no_reason(hidden):
    found = tools_of(edited(BULLET, f"- `gmail.draft`: {hidden}"))
    assert ("E-BODY-TOOL-UNEXPLAINED", WHY_LINE, "gmail.draft") in found
    found = tools_of(edited(BULLET, f"- `gmail.draft`:{hidden}{hidden}"))
    assert ("E-BODY-TOOL-UNEXPLAINED", WHY_LINE, "gmail.draft") in found
    assert tools_of(edited(BULLET, f"- `gmail.draft`: {hidden}writes drafts")) == []


def test_a_sub_bullet_explains_a_tool():
    body = edited("- `gmail.send`: sends", "- `gmail.send`: sends\n  - `sheets.read`: reads again")
    assert tools_of(without_bullets(body, "sheets.read")) == []


def test_a_bullet_in_another_section_does_not_explain_a_tool_and_is_not_looked_at():
    moved = added_after(
        PURPOSE,
        "\n- `gmail.send`: sends, in the wrong section",
        without_bullets(BODY, "gmail.send"),
    )
    assert tools_of(moved) == [("E-BODY-TOOL-UNEXPLAINED", at(WHY, moved), "gmail.send")]


def test_a_bullet_for_a_tool_that_is_not_in_tools_is_reported_on_its_own_line():
    body = added_after(
        "- `gmail.send`: sends", "- `drive.read`: reads files\n- `drive.list`: lists them"
    )
    assert tools_of(body) == [
        ("E-BODY-TOOL-EXTRA", at("`drive.read`", body), "drive.read"),
        ("E-BODY-TOOL-EXTRA", at("`drive.list`", body), "drive.list"),
    ]


def test_a_bullet_that_names_a_tool_is_extra_also_without_a_colon_or_a_reason():
    body = added_after("- `gmail.send`: sends", "- `drive.read`\n- `drive.list`:")
    assert [code for code, _, _ in tools_of(body)] == ["E-BODY-TOOL-EXTRA"] * 2


def test_a_bullet_that_does_not_start_with_a_code_span_names_no_tool():
    body = added_after("- `gmail.send`: sends", "- Reads with `drive.read`: yes\n- A plain bullet")
    assert tools_of(body) == []


def test_a_tool_that_is_swapped_for_another_is_both_unexplained_and_extra():
    body = edited("- `gmail.draft`: writes", "- `drive.read`: writes")
    assert sorted(tools_of(body)) == sorted(
        [
            ("E-BODY-TOOL-UNEXPLAINED", WHY_LINE, "gmail.draft"),
            ("E-BODY-TOOL-EXTRA", at("`drive.read`", body), "drive.read"),
        ]
    )


@pytest.mark.parametrize(
    "tool", ["drive.reed", "drive.*", "payments.pay", "drive.move", "TODO", "REPLACE_ME_TOOL", ""]
)
def test_a_tool_entry_that_failed_its_own_rules_is_never_unexplained(tool):
    # Ruling R33: the rules of the tools have said what is wrong with it (or E-PLACEHOLDER has).
    assert tools_of(BODY, policy=replace(POLICY, tools=(*POLICY.tools, tool))) == []


def test_a_list_item_that_starts_with_a_heading_is_no_bullet():
    body = added_after("- `gmail.send`: sends", "- ### `drive.read`: a heading, not a bullet")
    assert tools_of(body) == []


def test_a_bullet_for_a_tool_entry_that_failed_its_rules_is_not_extra_because_it_is_in_tools():
    policy = replace(POLICY, tools=(*POLICY.tools, "drive.reed"))
    body = added_after("- `gmail.send`: sends", "- `drive.reed`: a typo")
    assert tools_of(body, policy=policy) == []


@pytest.mark.parametrize("marks", ["- ", "1. ", "> - ", "- - ", "* "])
def test_a_heading_in_a_list_item_is_an_extra_section_and_the_item_names_no_tool(marks):
    # The item starts with a heading, and has no paragraph to look at.
    body = added_after("- `gmail.send`: sends", f"{marks}## Nested")
    found = run(body)
    assert [f.line for f in only(found, "E-BODY-SECTIONS")] == [at("## Nested", body)]
    assert tools_of(body) == []


def test_the_tools_are_not_judged_without_why_each_tool_or_without_a_policy():
    assert tools_of(body_of("Purpose", "Data and risks", *SECTION_NAMES[3:])) == []
    assert tools_of(without_bullets(BODY, "gmail.send"), policy=None) == []


# --- E-BODY-DRIFT


STOP_LINE = at(STOP)
ENFORCED_LINE = at(ENFORCED)
SIGNOFF_LINE = at(SIGNOFF)
SIGNED_LINE = at("must enforce.")


def drift_of(body: str, **kw) -> list[tuple[str, str, int]]:
    """(section, diff_line, line) for each finding of drift."""
    found = only(run(body, **kw), "E-BODY-DRIFT")
    return [(f.params["section"], f.params["diff_line"], f.line) for f in found]


def drift(section: str, line: int) -> tuple[str, str, int]:
    return (section, str(line), line)


def test_a_difference_in_a_generated_section_is_reported_on_the_first_line_that_differs():
    assert drift_of(edited(STOP, "Stop: nothing")) == [
        drift("Enforced rules (generated)", STOP_LINE)
    ]
    body = edited("Signing means: I have", "Signing means: I may have")
    assert drift_of(body) == [drift("Sign-off (generated)", at("Signing means"))]


def test_the_first_difference_is_the_one_reported_and_each_section_has_its_own():
    body = edited(STOP, "Stop: nothing").replace("| R0 read |", "| R9 read |")
    body = edited("Signing means: I have", "Signing means: I may have", body)
    body = edited(
        "Agent `invoice-reminder`, version 1.", "Agent `invoice-reminder`, version 2.", body
    )
    assert drift_of(body) == [
        drift("Enforced rules (generated)", at("| `sheets.read` |", body)),
        drift("Sign-off (generated)", at("version 2.", body)),
    ]


def test_the_policy_decides_what_a_section_must_say_so_a_new_value_is_a_difference():
    assert drift_of(BODY, policy=replace(POLICY, version=2)) == [
        drift("Sign-off (generated)", at("version 1."))
    ]
    assert drift_of(BODY, policy=replace(POLICY, untrusted_input="taint")) == [
        drift("Enforced rules (generated)", at("Untrusted input ("))
    ]


def test_a_paragraph_that_is_missing_is_a_difference_where_it_should_be():
    stop = f"{STOP} stops this agent; the global kill switch stops every agent. Neither needs this agent's cooperation.\n\n"
    assert drift_of(BODY.replace(stop, "")) == [drift("Enforced rules (generated)", STOP_LINE)]


def test_an_extra_blank_line_is_a_difference_on_the_line_where_the_text_should_go_on():
    assert drift_of(added_after(STOP, "")) == [drift("Enforced rules (generated)", STOP_LINE + 2)]


def test_the_blank_line_before_the_next_heading_is_part_of_the_section():
    body = BODY.replace("kept 1 year.\n\n" + SIGNOFF, "kept 1 year.\n" + SIGNOFF)
    assert drift_of(body) == [drift("Enforced rules (generated)", SIGNOFF_LINE - 1)]


def test_the_last_section_is_compared_without_the_newlines_at_the_end_of_the_file():
    # They are E-FINAL-NEWLINE's (ruling R15).
    assert drift_of(BODY.rstrip("\n")) == []
    assert drift_of(BODY.rstrip("\n") + "\n\n\n") == []
    assert drift_of(BODY.rstrip("\n") + "\nExtra.\n") == [
        drift("Sign-off (generated)", SIGNED_LINE + 1)
    ]


def test_a_last_section_that_is_cut_short_differs_on_the_line_behind_its_last_line():
    last = at("The signature is the separate file")
    cut = BODY[: BODY.rindex("Signing means")]  # a blank line is the last line of the file
    assert drift_of(cut) == [drift("Sign-off (generated)", last + 1)]
    # With nothing behind the last line (one LF at the end, or none) the difference is on that line.
    assert drift_of(cut.rstrip("\n") + "\n") == [drift("Sign-off (generated)", last)]
    assert drift_of(cut.rstrip("\n")) == [drift("Sign-off (generated)", last)]


def lines_of(body: str) -> int:
    """The number of lines of the file: those of the front matter, and those of the body."""
    return FIRST_LINE - 1 + len(body.split("\n")) - (1 if body.endswith("\n") else 0)


@pytest.mark.parametrize("ending", ["", "\n", "\n\n", "\n\n\n"], ids=["no LF", "1", "2", "3"])
def test_drift_never_points_behind_the_last_line_of_the_file(ending):
    # Minor 3: a file of 103 lines had its difference on line 104. Every cut of the last section.
    head = BODY[: BODY.index(SIGNOFF)]
    signoff = BODY[BODY.index(SIGNOFF) :].rstrip("\n").split("\n")
    for keep in range(1, len(signoff)):  # the heading, and then more of the section, but not all
        body = head + "\n".join(signoff[:keep]) + ending
        found = drift_of(body)
        assert found, (keep, ending)
        assert all(line <= lines_of(body) for _, _, line in found), (keep, ending)


def test_a_section_that_is_not_there_is_not_compared():
    without_signoff = BODY[: BODY.index(SIGNOFF)]
    assert drift_of(without_signoff) == []
    assert drift_of(without_signoff[: without_signoff.index(ENFORCED)]) == []
    assert codes(run(without_signoff)) == ["E-BODY-SECTIONS"]


# --- E-BODY-DRIFT is judged only when the sections are right (ruling R58)


STALE = edited(STOP, "Stop: nothing")  # a body with a difference in a generated section
SECTION_DEFECTS = {
    "an extra section after the sign-off": lambda body: body + "\n## Notes\n\nSome more text.\n",
    "a second copy of the sign-off": lambda body: body + f"\n{SIGNOFF}\n\nA second one.\n",
    "a section that is missing": lambda body: edited("## Data and risks\n", "", body),
    "a section that is renamed": lambda body: edited("## Data and risks", "## Data and risk", body),
    "two sections swapped": lambda body: (
        body.replace("## Purpose\n", "##\n")
        .replace("## Why each tool\n", "## Purpose\n")
        .replace("##\n", "## Why each tool\n")
    ),
    "a second title": lambda body: added_after(PURPOSE, "\n# Another title", body),
    "a heading of level 3 in a generated section": lambda body: added_after(
        "Stop: nothing", "\n### Details", body
    ),
    "a generated heading in a quote": lambda body: added_after(
        PURPOSE, f"\n> {ENFORCED}\n\nNot the section.", body
    ),
}


def test_an_extra_section_after_the_signoff_is_a_finding_of_sections_and_not_of_drift():
    assert codes(run(BODY + "\n## Notes\n\nSome more text.\n")) == ["E-BODY-SECTIONS"]


def test_the_file_of_the_defects_has_a_difference_in_a_generated_section():
    assert drift_of(STALE) == [drift("Enforced rules (generated)", at("Stop: nothing", STALE))]


@pytest.mark.parametrize("defect", SECTION_DEFECTS.values(), ids=SECTION_DEFECTS)
def test_the_boundaries_of_the_sections_are_not_trusted_so_drift_waits_until_they_are_right(defect):
    body = defect(STALE)
    assert "E-BODY-SECTIONS" in codes(run(body))
    assert "E-BODY-DRIFT" not in codes(run(body))


def test_a_heading_in_setext_style_differs_on_its_own_line():
    body = edited(ENFORCED, "Enforced rules (generated)\n--------------------------")
    assert drift_of(body) == [drift("Enforced rules (generated)", ENFORCED_LINE)]


@pytest.mark.parametrize(
    ("lines", "last"),
    [([""], 0), (["a"], 0), (["a", ""], 0), (["a", "", ""], 1), (["a", "b", "c"], 2)],
)
def test_the_last_line_of_a_file_is_the_one_before_the_final_lf_and_never_before_the_first(
    lines, last
):
    assert _last_row(lines) == last


def test_drift_goes_by_the_headings_at_the_top_level_where_it_is_made():
    # `check_body` judges drift only when the sections are right (ruling R58), and then no copy of
    # a heading is in a quote. So the rule that a quoted copy is not the section, which `rewrite`
    # has too, cannot be seen through `check_body`: it is pinned here, on drift itself.
    body = added_after(PURPOSE, f"\n> {ENFORCED}\n\nNot the section.\n\n> {SIGNOFF}")
    assert body.count(ENFORCED) == 2 and body.count(SIGNOFF) == 2
    report = _Report(str(BASE_PATH), FIRST_LINE)
    assert _drift(report, body.split("\n"), headings(parse(body)), POLICY, CATALOG) == []
    stale = body.replace(STOP, "Stop: nothing")
    found = _drift(report, stale.split("\n"), headings(parse(stale)), POLICY, CATALOG)
    assert [(f.params["section"], f.line) for f in found] == [
        ("Enforced rules (generated)", at("Stop: nothing", stale))
    ]


def test_drift_is_not_checked_without_a_policy_or_when_it_is_switched_off():
    body = edited(STOP, "Stop: nothing")
    assert drift_of(body, drift=False) == []
    assert drift_of(body, policy=None) == []


@pytest.mark.parametrize("tool", ["drive.reed", "drive.*", "payments.pay", "drive.move", "TODO"])
def test_a_policy_that_cannot_be_rendered_has_no_drift_and_does_not_raise(tool):
    assert drift_of(BODY, policy=replace(POLICY, tools=(*POLICY.tools, tool))) == []
    assert drift_of(BODY, policy=replace(POLICY, untrusted_input="zz-mode")) == []


# --- validate_file: when the checks of the body run (rulings R27, R28, R29, R33)


def validate(data: bytes, path=BASE_PATH) -> list[Finding]:
    return validate_file(path, data, CFG, CATALOG)


def body_codes(findings: list[Finding]) -> list[str]:
    return sorted(f.code for f in findings if f.code.startswith("E-BODY"))


HTML = b"no email goes to clients. <b>"
WRONG_TITLE = b"# something-else\n"


def with_body_problems(data: bytes) -> bytes:
    data = data.replace(b"no email goes to clients.", HTML, 1)
    data = data.replace(b"# invoice-reminder\n", WRONG_TITLE, 1)
    data = data.replace(b"- `gmail.send`: sends", b"- `gmail.send`; sends", 1)
    return data.replace(b"Stop: the agent", b"Stop: an agent", 1)


def test_the_file_of_the_tests_has_all_four_problems_and_nothing_else_in_the_body():
    assert body_codes(validate(with_body_problems(BASE))) == [
        "E-BODY-DRIFT",
        "E-BODY-HTML",
        "E-BODY-TITLE",
        "E-BODY-TOOL-UNEXPLAINED",
    ]


def test_no_check_of_the_body_runs_when_there_is_no_front_matter_or_it_cannot_be_trusted():
    # Ruling R27: spec section 1 lists the file, hidden-character, placeholder and content checks.
    no_front_matter = with_body_problems(BASE).replace(b"---\n", b"--- \n", 1)
    broken_yaml = with_body_problems(BASE).replace(b"# AIVEN policy, schema v1", b"@", 1)
    twice = with_body_problems(BASE).replace(b"version: 1 ", b"version: 1\nversion: 2 ", 1)
    for data in (no_front_matter, broken_yaml, twice):
        assert body_codes(validate(data)) == []
        assert validate(data) != []


def test_without_a_policy_the_checks_that_need_none_still_run_and_the_others_do_not():
    # Ruling R33: a missing field gives no policy. Title, tools and drift need it.
    data = with_body_problems(BASE).replace(b"version: 1 ", b"# version: 1 ", 1)
    found = validate(data)
    assert "E-FIELD-MISSING" in codes(found)
    assert body_codes(found) == ["E-BODY-HTML"]
    data = data.replace(b"## Why each tool", b"## Why each tools", 1)
    assert body_codes(validate(data)) == ["E-BODY-HTML", "E-BODY-SECTIONS"]


@pytest.mark.parametrize("agent", [b"ab", b"admin", b"Invoice-reminder", b"TODO"])
def test_an_agent_that_is_not_a_usable_id_is_not_compared_with_the_title(agent):
    # Ruling R28: one defect, one code. The title still says invoice-reminder.
    data = BASE.replace(b"agent: invoice-reminder", b"agent: " + agent, 1)
    assert "E-BODY-TITLE" not in codes(validate(data))


def test_a_warning_does_not_stop_drift_so_a_value_that_is_not_rendered_again_is_a_difference():
    data = BASE.replace(b"min_runs: 10", b"min_runs: 5", 1)
    found = validate(data)
    assert "W-SHADOW-LOW" in codes(found)
    assert body_codes(found) == ["E-BODY-DRIFT"]


def test_an_error_that_load_found_stops_drift_too():
    # An unknown field is no obstacle to a policy, and it is an error of the front matter all the same.
    data = BASE.replace(b"min_runs: 10", b"min_runs: 5\nunknown: 1", 1)
    found = validate(data)
    assert {"E-FIELD-UNKNOWN", "W-SHADOW-LOW"} <= set(codes(found))
    assert body_codes(found) == []


def test_an_error_in_the_front_matter_stops_drift():
    # Ruling R29: rendering an invalid front matter is noise. The file cannot be signed anyway.
    data = BASE.replace(b"min_runs: 10", b"min_runs: 0", 1)
    found = validate(data)
    assert "E-RANGE" in codes(found)
    assert body_codes(found) == []
    data = BASE.replace(b"max_class: R2", b"max_class: R3", 1)  # an error of the rules
    assert body_codes(validate(data)) == []


def test_a_placeholder_does_not_stop_drift_and_the_template_has_none():
    # E-PLACEHOLDER comes from the checks of the file. The template renders with its placeholders.
    assert body_codes(validate(TEMPLATE)) == []
    data = BASE.replace(
        b"agent-invoice-reminder@aiven-agents-test", b"agent-invoice-reminder@REPLACE_ME", 1
    )
    found = validate(data)
    assert "E-PLACEHOLDER" in codes(found)
    assert body_codes(found) == ["E-BODY-DRIFT"]  # the Identity line says the old project


def test_a_file_name_that_is_wrong_does_not_stop_drift():
    data = BASE.replace(b"min_runs: 10", b"min_runs: 5", 1)
    found = validate(data, path=BASE_PATH.with_name("other-name.md"))
    assert {"E-FILENAME", "E-BODY-DRIFT"} <= set(codes(found))


def test_a_tool_entry_that_is_a_placeholder_is_a_placeholder_and_no_crash_and_no_other_finding():
    data = BASE.replace(b"  - gmail.send\nforbidden:", b"  - gmail.send\n  - TODO\nforbidden:", 1)
    found = validate(data)
    assert body_codes(found) == []
    assert "E-PLACEHOLDER" in codes(found)


def test_the_findings_of_the_body_are_in_the_one_sorted_list_with_the_others():
    found = validate(with_body_problems(BASE))
    lines = [f.line for f in found if f.line is not None]
    assert lines == sorted(lines)
    assert {"E-BODY-HTML", "W-TOOL-NOT-LIVE"} <= set(codes(found))
