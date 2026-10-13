"""The renderer (validator-spec section 7): the two generated sections, and `rewrite`.

`templates/policy-template.md` is the reference output (V-3): rendering its own front matter,
placeholders and all (ruling R4), gives its two sections byte for byte. The other tests change one
value of the policy at a time and look at the one place where it shows. The sentences that section 7
spells out are read from the spec, so a change of the spec without a change of the renderer (or the
reverse) fails here.

A section is the text of a file from its heading to the next heading, or to the end of the file. So
the first one ends with the blank line before the next heading, and the second with one LF.
"""

import random
import re
from copy import deepcopy
from dataclasses import replace

import pytest

from aiven.policy.body import check_body
from aiven.policy.catalog import Action
from aiven.policy.constants import POLICY_CLASSES
from aiven.policy.fileformat import decode_text
from aiven.policy.frontmatter import split
from aiven.policy.markdown import parse
from aiven.policy.model import Limits, Scope
from aiven.policy.render import render_generated, rewrite
from aiven.policy.validate import validate_file
from tests.support.bodies import ENFORCED, SIGNOFF, generated_of, only, policy_of, rerendered
from tests.support.frontmatter import DATA, emit
from tests.support.policies import AGENTS_PROJECT, BASE_PATH, FOLDER_ID, TEMPLATE_PATH, valid_base
from tests.support.rules import CATALOG, CFG
from tests.support.spec_tables import code_spans, line_starting_with

TEMPLATE = TEMPLATE_PATH.read_bytes()
TEMPLATE_TEXT = TEMPLATE.decode("utf-8")
BASE = valid_base()
BASE_TEXT = BASE.decode("utf-8")
POLICY = policy_of(BASE)
SECTIONS = "".join(render_generated(POLICY, CATALOG))  # the two sections, as they stand in a file
PATH = "AIVEN Architecture Sandbox / Invoices"

# What section 7 spells out.
CLASS_AND_GATE = {cls: code_spans(line_starting_with(f"  - {cls}:")) for cls in POLICY_CLASSES}
FIXED_SENTENCE = code_spans(line_starting_with("  - Fixed:"))[0]
MODE_RULES = {
    mode: code_spans(line_starting_with(f"  - `{mode}` adds:"))[1] for mode in ("strict", "taint")
}
NO_SCOPE = code_spans(line_starting_with("- Scope:"))[-1]
SPEND_AND_SHADOW = line_starting_with("- Spend renders as")


def enforced_of(policy=POLICY) -> str:
    return render_generated(policy, CATALOG)[0]


def signoff_of(policy=POLICY) -> str:
    return render_generated(policy, CATALOG)[1]


def paragraph(section: str, start: str) -> str:
    """The one paragraph of a section (text between blank lines) that starts with `start`."""
    found = [text for text in section.split("\n\n") if text.startswith(start)]
    assert len(found) == 1, f"{start!r} must start exactly one paragraph, found {len(found)}"
    return found[0]


def scope_of(policy) -> str:
    """The bullets under `Scope:`, which is a paragraph of its own."""
    blocks = enforced_of(policy).split("\n\n")
    return blocks[blocks.index("Scope:") + 1]


# --- the template is the reference output (V-3)


def test_render_template_golden():
    policy = policy_of(TEMPLATE)
    # The front matter of the template still holds its two placeholders. The policy keeps them, and
    # so do the sections (ruling R4).
    assert "REPLACE_ME_AGENTS_PROJECT" in policy.principal
    assert policy.scope.drive_folder_id == "REPLACE_ME_FOLDER_ID"
    assert render_generated(policy, CATALOG) == generated_of(TEMPLATE_TEXT)


def test_valid_base_matches_render():
    # Ruling R1: the base is the template with two values filled in. Its generated sections are what
    # the renderer makes of that front matter, so the plain substitution was a re-render.
    assert render_generated(POLICY, CATALOG) == generated_of(BASE_TEXT)
    assert rewrite(BASE, POLICY, CATALOG) == BASE


def test_filling_in_the_two_values_of_the_template_and_rendering_gives_a_policy_with_three_warnings():
    # Spec section 9: "fill in the two values in the front matter, run render. After that only the
    # three warnings remain." The sections still hold the placeholders until they are rendered.
    end = TEMPLATE_TEXT.index("\n---\n", 4) + len("\n---\n")
    front = TEMPLATE_TEXT[:end]
    front = front.replace("REPLACE_ME_AGENTS_PROJECT", AGENTS_PROJECT)
    front = front.replace("REPLACE_ME_FOLDER_ID", FOLDER_ID)
    data = (front + TEMPLATE_TEXT[end:]).encode("utf-8")
    assert b"REPLACE_ME" in data
    filled = rewrite(data, policy_of(data), CATALOG)
    assert filled == BASE
    assert [f.code for f in validate_file(BASE_PATH, filled, CFG, CATALOG)] == [
        "W-TOOL-NOT-LIVE"
    ] * 3


def test_the_two_sections_are_the_text_from_each_heading_to_the_next():
    enforced, signoff = render_generated(POLICY, CATALOG)
    assert enforced.startswith(ENFORCED + "\n\n")
    assert enforced.endswith("kept 1 year.\n\n")  # with the blank line before the next heading
    assert signoff.startswith(SIGNOFF + "\n\n")
    assert signoff.endswith("must enforce.\n")  # one LF, and nothing behind it
    assert enforced + signoff == BASE_TEXT[BASE_TEXT.index(ENFORCED) :]


# --- untrusted input: the fixed sentence and the part of the mode (section 7)


def test_the_sentences_that_the_tests_read_from_the_spec_are_the_ones_expected():
    # The tests below are only as good as what they read.
    assert FIXED_SENTENCE.startswith("Untrusted input ({mode}): a run is tainted once")
    assert MODE_RULES["strict"].startswith(" In a tainted run, R1 actions also wait")
    assert MODE_RULES["taint"].startswith(" In a tainted run, each R2 action is reviewed")
    assert NO_SCOPE == "- None: this agent has no Drive or email tools."
    assert re.findall(r'"([^"]+)"', SPEND_AND_SHADOW) == [
        "the first run only proposes",
        "after 1 run",
    ]
    assert CLASS_AND_GATE == {
        "R0": ["R0 read", "Runs at once, logged"],
        "R1": ["R1 reversible", "Snapshot first, then runs at once, logged"],
        "R2": ["R2 costly to undo", "Waits for Matthijs to confirm a plain-language preview"],
    }


@pytest.mark.parametrize("mode", ["strict", "taint"])
def test_render_strict_and_taint_text(mode):
    wanted = FIXED_SENTENCE.replace("{mode}", mode) + MODE_RULES[mode]
    enforced = enforced_of(replace(POLICY, untrusted_input=mode))
    assert paragraph(enforced, "Untrusted input (") == wanted


def test_the_mode_changes_no_paragraph_but_its_own():
    strict = enforced_of()
    taint = enforced_of(replace(POLICY, untrusted_input="taint"))
    assert strict != taint
    own = paragraph(strict, "Untrusted input ("), paragraph(taint, "Untrusted input (")
    assert strict.replace(*own) == taint


# --- the tools: classes, gates, undo texts


GRANTABLE = [action for action in CATALOG.actions.values() if action.cls in POLICY_CLASSES]


@pytest.mark.parametrize("action", GRANTABLE, ids=lambda action: action.id)
def test_every_action_has_a_row_with_its_class_and_a_bullet_with_its_undo_text(action):
    lines = enforced_of(replace(POLICY, tools=(action.id,))).split("\n")
    label, gate = CLASS_AND_GATE[action.cls]
    assert f"| `{action.id}` | {label} | {gate} |" in lines
    assert f"- `{action.id}`: {action.undo}" in lines


def test_the_table_and_the_undo_list_have_one_entry_per_tool_in_the_order_of_the_file():
    tools = ("gmail.send", "sheets.read", "gmail.draft", "drive.list")
    lines = enforced_of(replace(POLICY, tools=tools)).split("\n")
    rows = [line for line in lines if line.startswith("| `")]
    undo = [line for line in lines if line.startswith("- `") and "`: " in line]
    assert [row.split("`")[1] for row in rows] == list(tools)
    assert [line.split("`")[1] for line in undo] == list(tools)


def test_the_undo_text_is_the_one_of_the_catalog_in_use():
    action = CATALOG.actions["gmail.draft"]
    catalog = replace(
        CATALOG,
        actions={**CATALOG.actions, action.id: replace(action, undo="throw the draft away.")},
    )
    enforced = render_generated(POLICY, catalog)[0]
    assert "- `gmail.draft`: throw the draft away." in enforced.split("\n")
    assert "restore or remove the draft" not in enforced


def test_the_highest_class_is_max_class_because_that_is_what_the_gateway_enforces():
    # The only tool is R0 and max_class is R2: the sentence says R2, as the gateway refuses above it.
    sentence = "Highest class: {}. A call that is classed higher at runtime is refused."
    assert sentence.format("R2") in enforced_of(replace(POLICY, tools=("sheets.read",)))
    assert sentence.format("R1") in enforced_of(replace(POLICY, max_class="R1"))


def test_forbidden_items_are_in_backticks_in_the_order_of_the_file():
    forbidden = ("gmail.send_bulk", "drive.share", "drive.delete", "payments.*")
    wanted = "Forbidden (refused, logged, alert to Matthijs): " + ", ".join(
        f"`{item}`" for item in forbidden
    )
    assert paragraph(enforced_of(replace(POLICY, forbidden=forbidden)), "Forbidden (") == (
        wanted + "."
    )


# --- a value with a backtick in it stays in its code span (ruling R67)


def code_spans_in(section: str) -> list[str]:
    """The content of every code span of a text, as the parser of the body reads it."""
    return [
        child.content
        for token in parse(section)
        if token.type == "inline"
        for child in token.children or []
        if child.type == "code_inline"
    ]


TRICKY = ["a`b", "`start", "end`", "a``b", "``", "`", "a ` b", "```x```", "` `", "x ` y ``` z"]


@pytest.mark.parametrize("value", TRICKY)
def test_a_value_with_backticks_is_one_code_span_that_holds_all_of_it(value):
    policy = replace(
        POLICY,
        principal=value,
        agent=value,
        forbidden=(value,),
        scope=Scope(value, value, (value,)),
    )
    enforced, signoff = render_generated(policy, CATALOG)
    # the principal, the item of forbidden, the folder (path and ID) and the address
    assert code_spans_in(enforced).count(value) == 5
    assert code_spans_in(signoff) == [value, f"{value}.md.sig", "aiven-policy-v1"]


def test_a_path_that_closes_a_code_span_and_opens_another_stays_a_path():
    path = "AIVEN Architecture Sandbox / Invoices` (read only). Nothing is ever written to `Drive"
    policy = replace(POLICY, scope=replace(POLICY.scope, drive_folder_path=path, email_to=()))
    bullet = scope_of(policy)
    (token,) = [t for t in parse(bullet) if t.type == "inline"]
    assert [child.type for child in token.children] == [
        "text",
        "code_inline",
        "text",
        "code_inline",
        "text",
    ]
    assert [child.content for child in token.children if child.type == "code_inline"] == [
        path,
        FOLDER_ID,
    ]
    assert token.children[-1].content == ") and its subfolders."


def test_a_value_without_a_backtick_is_in_a_code_span_of_one_backtick_with_no_padding():
    assert "`@aivenstudios.com`" in enforced_of()
    assert "Agent `invoice-reminder`," in signoff_of()


@pytest.mark.parametrize(
    ("value", "span"),
    [
        ("a", "`a`"),
        ("a`b", "``a`b``"),
        ("a`b`c", "``a`b`c``"),
        ("`a", "`` `a ``"),
        ("a`", "`` a` ``"),
        ("`", "`` ` ``"),
        ("``", "``` `` ```"),
        ("a``b`c", "```a``b`c```"),
    ],
)
def test_the_fence_is_one_backtick_longer_than_the_longest_run_in_the_value(value, span):
    # CommonMark: a space on each side where the value starts or ends with a backtick.
    assert f"Identity: runs as {span}. Calls" in enforced_of(replace(POLICY, principal=value))


def test_a_tool_of_a_catalog_that_is_made_by_hand_with_a_backtick_in_it_stays_in_its_span():
    tool = "ops.run`x"
    catalog = replace(CATALOG, actions={**CATALOG.actions, tool: Action(tool, "R1", "drive", "u.")})
    enforced = render_generated(replace(POLICY, tools=("sheets.read", tool)), catalog)[0]
    assert code_spans_in(enforced).count(tool) == 2  # in the table, and in the list of undo


@pytest.mark.parametrize("value", TRICKY)
def test_a_folder_id_without_a_path_is_in_one_code_span_too(value):
    scope = Scope(value, None, ())
    assert code_spans_in(scope_of(replace(POLICY, scope=scope))) == [value]


# --- limits, scope, shadow mode


def test_the_limits_table_has_one_row_for_each_limit():
    limits = Limits(
        emails_per_day=3, records_per_run=4, spend_eur_per_run=0, max_runtime_s=90, runs_per_day=2
    )
    lines = enforced_of(replace(POLICY, limits=limits)).split("\n")
    start = lines.index("| Limit | Value |")
    assert lines[start : start + 7] == [
        "| Limit | Value |",
        "|---|---|",
        "| Email recipients per day (Europe/Amsterdam) | 3 |",
        "| Records changed per run | 4 |",
        "| Spend per run | \u20ac0 |",
        "| Runtime per run | 90 s |",
        "| Runs per day | 2 |",
    ]


def test_the_spend_is_what_the_front_matter_says_so_that_the_text_cannot_be_untrue():
    # The spend must be 0 in v1 (E-LIMIT-SPEND), and the renderer does not hide a value that is not.
    limits = replace(POLICY.limits, spend_eur_per_run=5)
    assert "| Spend per run | \u20ac5 |" in enforced_of(replace(POLICY, limits=limits)).split("\n")


def test_render_scope_none():
    policy = replace(POLICY, scope=Scope(None, None, ()))
    assert scope_of(policy) == "- None: this agent has no Drive or email tools."
    assert "- Drive:" not in enforced_of(policy) and "- Email:" not in enforced_of(policy)


def test_a_drive_folder_alone_and_an_email_list_alone_each_have_their_bullet_only():
    drive = replace(POLICY.scope, email_to=())
    email = replace(POLICY.scope, drive_folder_id=None, drive_folder_path=None)
    assert scope_of(replace(POLICY, scope=drive)) == (
        f"- Drive: only `{PATH}` (ID `{FOLDER_ID}`) and its subfolders."
    )
    assert scope_of(replace(POLICY, scope=email)) == "- Email: only to `@aivenstudios.com`."


def test_email_entries_are_in_backticks_separated_by_commas_in_the_order_of_the_file():
    addresses = ("b@aivenstudios.com", "@aivenstudios.com", "a@aivenstudios.com")
    scope = replace(POLICY.scope, email_to=addresses)
    wanted = "- Email: only to `b@aivenstudios.com`, `@aivenstudios.com`, `a@aivenstudios.com`."
    assert scope_of(replace(POLICY, scope=replace(scope, drive_folder_id=None))) == wanted


def test_a_folder_id_without_a_path_is_the_folder_with_that_id():
    # A warning only (W-SCOPE-UNUSED), so a policy that has it is rendered, and it must say it.
    scope = replace(POLICY.scope, drive_folder_path=None, email_to=())
    assert scope_of(replace(POLICY, scope=scope)) == (
        f"- Drive: only the folder with ID `{FOLDER_ID}` and its subfolders."
    )


def test_render_min_runs_singular():
    one = enforced_of(replace(POLICY, shadow_min_runs=1))
    assert "Shadow mode: the first run only proposes. R0 reads run;" in one
    assert "After 1 run the agent stays in shadow until Matthijs signs it off." in one
    for words in re.findall(r'"([^"]+)"', SPEND_AND_SHADOW):  # the two phrases of the spec
        assert words.lower() in one.lower()


@pytest.mark.parametrize("runs", [2, 10, 100])
def test_render_min_runs_plural(runs):
    enforced = enforced_of(replace(POLICY, shadow_min_runs=runs))
    assert f"Shadow mode: the first {runs} runs only propose. R0 reads run;" in enforced
    assert f"After {runs} runs the agent stays in shadow until Matthijs signs it off." in enforced


# --- the identity and the sign-off


def test_the_identity_line_has_the_principal_of_the_file_as_it_is():
    policy = replace(POLICY, principal="agent-x@elsewhere.iam.gserviceaccount.com")
    wanted = "Identity: runs as `agent-x@elsewhere.iam.gserviceaccount.com`. Calls from any other"
    assert wanted in enforced_of(policy)


def test_the_sign_off_names_the_agent_and_the_version():
    signoff = signoff_of(replace(POLICY, agent="other-agent", version=7))
    signature = (
        "the separate file `other-agent.md.sig` (SSH signature, namespace `aiven-policy-v1`)"
    )
    assert "Agent `other-agent`, version 7. Signer: Matthijs van Hoorn, the only signer" in signoff
    assert signature in signoff


# --- what cannot be rendered


@pytest.mark.parametrize(
    "tool", ["drive.reed", "payments.pay", "drive.*", "drive.move", "agentbuilder.permissions"]
)
def test_a_tool_that_is_not_an_action_to_grant_raises_value_error_without_its_name(tool):
    # Not in the catalog, a reserved name, a wildcard, and an R3 action (which has no undo text).
    policy = replace(POLICY, tools=("sheets.read", tool))
    with pytest.raises(ValueError) as raised:
        render_generated(policy, CATALOG)
    assert tool not in str(raised.value)
    with pytest.raises(ValueError):
        rewrite(BASE, policy, CATALOG)


def test_an_action_without_an_undo_text_or_of_a_class_that_is_not_granted_raises_value_error():
    # The loader of the catalog makes no such action, but a catalog that is made by hand can.
    actions = {
        "ops.run": Action("ops.run", "R1", "drive"),
        "ops.wipe": Action("ops.wipe", "R4", "drive", "undo it."),
    }
    catalog = replace(CATALOG, actions={**CATALOG.actions, **actions})
    for tool in actions:
        with pytest.raises(ValueError):
            render_generated(replace(POLICY, tools=("sheets.read", tool)), catalog)


def test_a_mode_that_is_neither_strict_nor_taint_raises_value_error_without_its_value():
    with pytest.raises(ValueError) as raised:
        render_generated(replace(POLICY, untrusted_input="zz-mode"), CATALOG)
    assert "zz-mode" not in str(raised.value)


# --- rewrite


def with_other_values(data: bytes) -> bytes:
    """The base with a new version and two other values, which show in the generated sections."""
    text = data.decode("utf-8")
    for old, new in [
        ("version: 1 ", "version: 2 "),
        ("min_runs: 10", "min_runs: 3"),
        ("runs_per_day: 1", "runs_per_day: 4"),
    ]:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text.encode("utf-8")


def test_rewrite_changes_only_generated_sections():
    data = with_other_values(BASE).replace(b"Once a day,", b"Twice a week,")
    policy = policy_of(data)
    result = rewrite(data, policy, CATALOG)
    cut = data.index(ENFORCED.encode())
    assert result[:cut] == data[:cut]  # nothing before the heading changes, byte for byte
    assert result[cut:] == "".join(render_generated(policy, CATALOG)).encode()
    text = result.decode("utf-8")
    assert "Agent `invoice-reminder`, version 2." in text
    assert "the first 3 runs only propose" in text and "| Runs per day | 4 |" in text
    assert "Twice a week," in text


def test_rewrite_puts_back_what_was_changed_in_the_generated_sections():
    text = BASE_TEXT
    for old, new in [
        ("Stop: the agent kill switch", "Stop: nothing"),
        ("| `gmail.send` | R2 costly to undo |", "| `gmail.send` | R0 read |"),
        ("Signing means: I have read", "Signing means: I may have read"),
    ]:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    text = text.replace(SIGNOFF, f"Something between.\n\n{SIGNOFF}") + "\nExtra text at the end.\n"
    assert rewrite(text.encode(), POLICY, CATALOG) == BASE


@pytest.mark.parametrize("tail", [b"", b"\n\n", b"\n\n\n\n"], ids=["no LF", "2 LF", "4 LF"])
def test_rewrite_ends_with_exactly_one_lf(tail):
    result = rewrite(BASE.rstrip(b"\n") + tail, POLICY, CATALOG)
    assert result.endswith(b"must enforce.\n")
    assert result == BASE


def test_rewrite_is_idempotent():
    data = with_other_values(BASE)
    once = rewrite(data, policy_of(data), CATALOG)
    assert rerendered(once) == once


PREFIX = BASE[: BASE.index(ENFORCED.encode())].rstrip(b"\n")


@pytest.mark.parametrize(
    ("tail", "gap"),
    [(b"\n", b"\n"), (b"", b"\n\n"), (b"\n\n", b""), (b"\n\n\n", b"")],
    ids=["one LF", "no LF", "a blank line", "two blank lines"],
)
def test_without_the_heading_both_sections_are_appended_after_one_blank_line(tail, gap):
    data = PREFIX + tail
    assert rewrite(data, POLICY, CATALOG) == data + gap + SECTIONS.encode()


def test_the_bytes_before_the_heading_are_kept_whatever_they_are():
    # A byte-order mark, a byte that is not UTF-8, and a CR: the validator reports them, and the
    # renderer does not repair them behind the author's back.
    data = b"\xef\xbb\xbf" + BASE.replace(b"Once a day,", b"Once\xff a day,\r")
    cut = data.index(ENFORCED.encode())
    assert rewrite(data, POLICY, CATALOG) == data[:cut] + SECTIONS.encode()


def test_a_heading_in_a_code_fence_or_a_quote_is_not_the_section():
    decoys = f"```\n{ENFORCED}\n\nnot the section\n```\n\n> {ENFORCED}\n\n"
    cut = BASE_TEXT.index("## Data and risks")
    text = BASE_TEXT[:cut] + decoys + BASE_TEXT[cut:]
    wanted = text[: text.rindex(ENFORCED)] + SECTIONS  # the real heading is the last one
    assert wanted.count(ENFORCED) == 3  # the fence, the quote, and the section
    assert rewrite(text.encode(), POLICY, CATALOG).decode("utf-8") == wanted


def test_a_heading_in_setext_style_is_the_section_too():
    text = BASE_TEXT.replace(ENFORCED, "Enforced rules (generated)\n--------------------------")
    assert rewrite(text.encode(), POLICY, CATALOG) == BASE


def test_a_file_without_front_matter_is_searched_whole():
    data = b"Some text.\n"
    assert rewrite(data, POLICY, CATALOG) == data + b"\n" + SECTIONS.encode()
    broken = BASE.replace(b"---\n", b"--- \n", 1)  # the first line is not the delimiter
    cut = broken.index(ENFORCED.encode())
    assert rewrite(broken, POLICY, CATALOG) == broken[:cut] + SECTIONS.encode()


def test_a_file_without_anything_is_just_the_sections():
    assert rewrite(b"", POLICY, CATALOG) == SECTIONS.encode()


def test_a_heading_in_the_front_matter_is_a_comment_and_not_the_section():
    # In YAML it is a comment, and in Markdown it is the heading: only the body is searched.
    comment = (
        b"# AIVEN policy, schema v1. The gateway enforces this block; the body below explains it."
    )
    data = BASE.replace(comment, ENFORCED.encode(), 1)
    cut = data.rindex(ENFORCED.encode())
    assert data.index(ENFORCED.encode()) < cut
    assert rewrite(data, POLICY, CATALOG) == data[:cut] + SECTIONS.encode()


# --- rewrite never deletes text that is not a generated section (ruling R64)

AUTHOR = "Text that the author wrote and that no rewrite may take away."
PURPOSE_HEADING = "## Purpose\n"


def sections_first(text: str) -> str:
    """The base with its three free sections behind the two generated ones."""
    start = text.index(PURPOSE_HEADING)
    middle = text.index(ENFORCED)
    return text[:start] + text[middle:] + "\n" + text[start:middle].rstrip("\n") + "\n"


MISORDERED = {
    "the free sections behind the generated ones": sections_first(
        BASE_TEXT.replace("Once a day,", f"{AUTHOR} Once a day,")
    ),
    "a section behind the sign-off": BASE_TEXT + f"\n## Notes\n\n{AUTHOR}\n",
    "a section in setext style behind the sign-off": BASE_TEXT + f"\nNotes\n-----\n\n{AUTHOR}\n",
    "a section between the two": BASE_TEXT.replace(SIGNOFF, f"## Notes\n\n{AUTHOR}\n\n{SIGNOFF}"),
    "the first heading twice": BASE_TEXT.replace(SIGNOFF, f"{ENFORCED}\n\n{AUTHOR}\n\n{SIGNOFF}"),
    "the sign-off twice": BASE_TEXT + f"\n{SIGNOFF}\n\n{AUTHOR}\n",
    "a free section behind the first": BASE_TEXT.replace(
        SIGNOFF, f"## Data and risks\n\n{AUTHOR}\n\n{SIGNOFF}"
    ),
    # Ruling R69: a heading of level 1 closes the section above it, so what follows is the author's.
    "a heading of level 1 behind the sign-off": BASE_TEXT + f"\n# Appendix\n\n{AUTHOR}\n",
    "a heading of level 1 in setext style behind the sign-off": (
        BASE_TEXT + f"\nAppendix\n========\n\n{AUTHOR}\n"
    ),
    "a heading of level 1 between the two": BASE_TEXT.replace(
        SIGNOFF, f"# Note\n\n{AUTHOR}\n\n{SIGNOFF}"
    ),
    "a heading of level 1 behind the first section alone": (
        BASE_TEXT[: BASE_TEXT.index(SIGNOFF)] + f"# Note\n\n{AUTHOR}\n"
    ),
}


@pytest.mark.parametrize("text", MISORDERED.values(), ids=MISORDERED)
def test_sections_that_are_not_the_last_two_are_not_rewritten_and_nothing_of_the_file_is_said(text):
    assert AUTHOR in text
    with pytest.raises(ValueError) as raised:
        rewrite(text.encode(), POLICY, CATALOG)
    assert AUTHOR not in str(raised.value) and AUTHOR not in repr(raised.value)
    assert "Purpose" not in str(raised.value) and "Notes" not in str(raised.value)


@pytest.mark.parametrize(
    "tail",
    [
        f"{AUTHOR}\n",
        f"### Notes\n\n{AUTHOR}\n",
        f"> ## Notes\n\n{AUTHOR}\n",
        f"- ## Notes\n\n{AUTHOR}\n",
        f"> # Note\n\n{AUTHOR}\n",
        f"- # Note\n\n{AUTHOR}\n",
        f"```\n{AUTHOR}\n",
        f"<!--\n{AUTHOR}\n",
    ],
    ids=[
        "text",
        "a heading of level 3",
        "a heading of level 2 in a quote",
        "one in a list",
        "a heading of level 1 in a quote",
        "one in a list",
        "a fence",
        "a tag",
    ],
)
def test_what_follows_the_signoff_without_a_heading_of_level_1_or_2_is_part_of_it_and_is_replaced(
    tail,
):
    text = BASE_TEXT + "\n" + tail
    assert rewrite(text.encode(), POLICY, CATALOG) == BASE


def test_the_first_generated_section_alone_is_completed_and_a_signoff_in_front_is_kept():
    only_first = BASE_TEXT[: BASE_TEXT.index(SIGNOFF)]
    assert rewrite(only_first.encode(), POLICY, CATALOG) == BASE
    swapped = BASE_TEXT[: BASE_TEXT.index(ENFORCED)] + f"{SIGNOFF}\n\n{AUTHOR}\n\n" + SECTIONS
    cut = swapped.index(ENFORCED)
    assert rewrite(swapped.encode(), POLICY, CATALOG) == swapped[:cut].encode() + SECTIONS.encode()
    assert AUTHOR in swapped[:cut]


LINES_THAT_ARE_NO_HEADING = {
    "in a fence that is not closed": f"```\n{ENFORCED}\n\n{AUTHOR}\n",
    "in a fence of tildes that is not closed": f"~~~~\n{ENFORCED}\n{AUTHOR}\n",
    "in a fence that is closed": f"```\n{ENFORCED}\n```\n\n{AUTHOR}\n",
    "in a block of HTML": f"<div>\n{ENFORCED}\n</div>\n\n{AUTHOR}\n",
    "behind spaces in an indented code block": f"{AUTHOR}\n\n    {ENFORCED}\n",
}


@pytest.mark.parametrize("tail", LINES_THAT_ARE_NO_HEADING.values(), ids=LINES_THAT_ARE_NO_HEADING)
def test_a_line_that_looks_like_the_heading_but_is_none_raises_instead_of_adding_the_sections(tail):
    # Added at the end, the sections would be in the fence too, and each rewrite would add more.
    text = BASE_TEXT[: BASE_TEXT.index(ENFORCED)] + tail
    with pytest.raises(ValueError) as raised:
        rewrite(text.encode(), POLICY, CATALOG)
    assert AUTHOR not in str(raised.value) and ENFORCED not in str(raised.value)


@pytest.mark.parametrize("tail", ["```\nsome code\n", "<!--\nsome comment\n", "~~~\ncode"])
def test_sections_that_would_end_up_in_a_block_that_is_not_closed_raise_instead_of_being_added(
    tail,
):
    # The same without a line like the heading in it: the sections must be headings where they go.
    data = PREFIX + b"\n\n" + tail.encode()
    with pytest.raises(ValueError):
        rewrite(data, POLICY, CATALOG)


@pytest.mark.parametrize("mark", ["> ", "- ", "1. ", "> - "])
def test_a_generated_heading_in_a_quote_or_a_list_is_not_the_section_so_the_sections_are_added(
    mark,
):
    decoy = f"{mark}{ENFORCED}\n\n{AUTHOR}\n"
    data = PREFIX + b"\n\n" + decoy.encode()
    result = rewrite(data, POLICY, CATALOG)
    assert result == data + b"\n" + SECTIONS.encode()
    assert rewrite(result, POLICY, CATALOG) == result  # and now the real heading is the section


@pytest.mark.parametrize("mark", ["> ", "- ", "1. "])
def test_rewrite_and_drift_agree_that_a_generated_heading_in_a_quote_or_a_list_is_content(mark):
    # In front of the real section: it is not the section for rewrite, and not for the check.
    decoy = f"{mark}{ENFORCED}\n\n{AUTHOR}\n\n"
    cut = BASE_TEXT.index("## Data and risks")
    text = BASE_TEXT[:cut] + decoy + BASE_TEXT[cut:]
    stale = text.replace("Stop: the agent kill switch", "Stop: nothing")
    assert rewrite(text.encode(), POLICY, CATALOG).decode("utf-8") == text
    assert rewrite(stale.encode(), POLICY, CATALOG).decode("utf-8") == text
    _, body, first_line = split(stale)
    found = check_body(body, first_line, POLICY, CATALOG, BASE_PATH)
    assert [f.line for f in only(found, "E-BODY-SECTIONS")] == [
        first_line + body[: body.index(decoy)].count("\n")
    ]
    assert only(found, "E-BODY-DRIFT") == []


@pytest.mark.parametrize("mark", ["> ", "- "])
def test_a_generated_heading_in_a_quote_inside_the_section_goes_with_the_section(mark):
    # Inside the text that is replaced, it is replaced: the check names it, and render repairs it.
    inside = BASE_TEXT.replace("Stop: the agent", f"{mark}{ENFORCED}\n\nStop: the agent")
    _, body, first_line = split(inside)
    assert only(check_body(body, first_line, POLICY, CATALOG), "E-BODY-SECTIONS") != []
    assert rewrite(inside.encode(), POLICY, CATALOG) == BASE


# --- the renderer and the check of drift say the same, for any policy


ACTIONS = [action.id for action in CATALOG.actions.values() if action.cls in POLICY_CLASSES]


def random_front_matter(rng: random.Random) -> str:
    """The front matter of a policy with other tools, limits, scope, mode and runs."""
    data = deepcopy(DATA)
    data["agent"] = rng.choice(["invoice-reminder", "a1b", "x-y-z"])
    data["version"] = rng.choice([1, 2, 9999])
    data["tools"] = rng.sample(ACTIONS, k=rng.randint(1, 6))
    data["max_class"] = rng.choice(POLICY_CLASSES)
    data["untrusted_input"] = rng.choice(["strict", "taint"])
    data["forbidden"] = rng.sample(data["forbidden"], k=4) + rng.sample(
        ACTIONS, k=rng.randint(0, 2)
    )
    data["limits"] = {name: rng.choice([0, 1, 7, 50]) for name in data["limits"]}
    data["shadow"]["min_runs"] = rng.choice([1, 2, 10, 100])
    scope = rng.choice(["both", "drive", "email", "none"])
    if scope in ("drive", "none"):
        del data["scope"]["email_to"]
    if scope in ("email", "none"):
        del data["scope"]["drive_folder_id"], data["scope"]["drive_folder_path"]
    if scope == "none":
        del data["scope"]
    elif "email_to" in data["scope"]:
        data["scope"]["email_to"] = [f"a{n}@aivenstudios.com" for n in range(rng.randint(1, 3))]
    return "\n".join(emit(data)) + "\n"


def test_what_is_rendered_is_not_a_difference_and_rendering_again_changes_nothing():
    rng = random.Random(20261015)
    for number in range(150):
        front = random_front_matter(rng)
        file = f"---\n{front}---\n\n# some-agent\n\n## Purpose\n\nSome text.\n".encode()
        policy = policy_of(file)
        rendered = rewrite(file, policy, CATALOG)  # the sections are added, as there are none yet
        _, body, first_line = split(decode_text(rendered))
        found = check_body(body, first_line, policy, CATALOG)
        assert only(found, "E-BODY-DRIFT") == [], number
        assert rewrite(rendered, policy, CATALOG) == rendered, number
        assert generated_of(rendered.decode("utf-8")) == render_generated(policy, CATALOG), number


def test_the_euro_sign_is_written_as_utf8():
    assert b"\xe2\x82\xac0" in rewrite(BASE, POLICY, CATALOG)
