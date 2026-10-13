"""The renderer (validator-spec section 7): the two generated sections, and `rewrite`.

`templates/policy-template.md` is the reference output (V-3): rendering its own front matter,
placeholders and all (ruling R4), gives its two sections byte for byte. The other tests change one
value of the policy at a time and look at the one place where it shows. The sentences that section 7
spells out are read from the spec, so a change of the spec without a change of the renderer (or the
reverse) fails here.

A section is the text of a file from its heading to the next heading, or to the end of the file. So
the first one ends with the blank line before the next heading, and the second with one LF.
"""

import re
from dataclasses import replace

import pytest

from aiven.policy.constants import POLICY_CLASSES
from aiven.policy.model import Limits, Scope
from aiven.policy.render import render_generated, rewrite
from tests.support.bodies import ENFORCED, SIGNOFF, generated_of, policy_of, rerendered
from tests.support.policies import FOLDER_ID, TEMPLATE_PATH, valid_base
from tests.support.rules import CATALOG
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


def test_the_euro_sign_is_written_as_utf8():
    assert b"\xe2\x82\xac0" in rewrite(BASE, POLICY, CATALOG)
