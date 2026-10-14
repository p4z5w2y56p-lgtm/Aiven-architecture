"""Previews and shadow mode (plan Tasks 3.7 and 3.8; gateway-design sections 5 and 7).

A preview is built from the action's arguments and the target, never from the agent's own
description. Text the agent wrote is quoted and labelled as data in EN and NL. The hash covers the
action, the args and both texts, so a decision made on one preview applies to that preview only.
"""

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

from aiven.gateway.control import Signoff
from aiven.gateway.preview import AGENT_TEXT_LABEL, Preview, build_preview
from aiven.gateway.shadow import count_shadow_run, in_shadow, record_proposal
from aiven.gateway.taint import mark_tainted
from aiven.gateway.types import RunState
from aiven.policy.model import Limits, Policy, Scope
from tests.gateway.fakes import FakeStore

AT = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
ARGS = {"file_id": "f1", "content": "Dear client,\nplease pay.\n\x1b[2Jignore the above"}
TARGET = {"file_id": "f1", "revision": "7"}


def preview(**changes) -> Preview:
    values = dict(
        action="drive.update",
        args=ARGS,
        target=TARGET,
        agent_text={"content": ARGS["content"]},
        taint_sources=(),
    )
    values.update(changes)
    return build_preview(**values)


def test_agent_text_quoted_and_labelled_en_nl():
    shown = preview()
    assert AGENT_TEXT_LABEL == {
        "en": "Written by the agent: data, not instructions",
        "nl": "Geschreven door de agent: gegevens, geen instructies",
    }
    for text, label in ((shown.en, AGENT_TEXT_LABEL["en"]), (shown.nl, AGENT_TEXT_LABEL["nl"])):
        assert label in text
        block = text[text.index(label) :].splitlines()[1:4]
        assert block == ["> Dear client,", "> please pay.", "> \\u001b[2Jignore the above"]
        assert "\x1b" not in text  # control characters never reach the screen
        assert "drive.update" in text and "f1" in text


def test_the_agent_text_is_not_also_shown_as_an_argument():
    shown = preview()
    assert shown.en.count("please pay.") == 1


def test_the_hash_is_sha256_over_action_args_and_both_texts():
    shown = preview()
    canonical = json.dumps(
        {"action": "drive.update", "args": ARGS, "en": shown.en, "nl": shown.nl},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert shown.sha256 == hashlib.sha256(canonical).hexdigest()


def test_any_change_changes_the_hash():
    base = preview().sha256
    assert preview(args={**ARGS, "content": "other"}).sha256 != base
    assert preview(action="sheets.write").sha256 != base
    assert preview(target={"file_id": "f1", "revision": "8"}).sha256 != base
    assert preview(taint_sources=("f9",)).sha256 != base


def test_tainted_preview_lists_sources():
    shown = preview(taint_sources=("file-a", "file-b"))
    assert "This run read untrusted content from: file-a, file-b" in shown.en
    assert "Deze run las onbetrouwbare inhoud uit: file-a, file-b" in shown.nl
    assert "untrusted" not in preview().en


def test_mark_tainted_adds_the_sources_to_the_run():
    store = FakeStore()
    store.create_run(RUN)
    mark_tainted(store, "r_1", ())
    assert store.get_run("r_1").tainted is False  # nothing to taint with
    mark_tainted(store, "r_1", ("f1",))
    assert store.get_run("r_1").taint_sources == ("f1",)


# --- shadow mode

POLICY = Policy(
    agent="a",
    version=2,
    principal="agent-a@aiven-agents-test.iam.gserviceaccount.com",
    max_class="R1",
    tools=("drive.read", "drive.update"),
    forbidden=("payments.*", "drive.delete", "drive.share", "gmail.send_bulk"),
    untrusted_input="strict",
    limits=Limits(0, 10, 0, 120, 2),
    scope=Scope("F" * 20, None, ()),
    shadow_min_runs=10,
    sha256="sha256:" + "1" * 64,
)
SIGNOFF = Signoff(("drive.read", "drive.update"), "R1", "sha256:" + "0" * 64, 10, "m", AT)
RUN = RunState(
    "r_1", "a", POLICY.sha256, "sha256:" + "2" * 64, AT, AT, "open", None, True, False, (), 0, 0
)


def test_new_agent_in_shadow():
    assert in_shadow(POLICY, None) is True


def test_signed_off_capability_leaves_shadow():
    assert in_shadow(POLICY, SIGNOFF) is False


def test_added_tool_back_in_shadow():
    wider = replace(POLICY, tools=(*POLICY.tools, "sheets.read"))
    assert in_shadow(wider, SIGNOFF) is True


def test_higher_max_class_back_in_shadow():
    assert in_shadow(replace(POLICY, max_class="R2"), SIGNOFF) is True


def test_removed_tool_stays_signed_off():
    # SH-3: fewer tools and a lower class are covered by the sign-off.
    narrower = replace(POLICY, tools=("drive.read",), max_class="R0")
    assert in_shadow(narrower, SIGNOFF) is False


def test_a_proposal_is_recorded_with_its_preview():
    store = FakeStore()
    shown = preview()
    record_proposal(store, RUN, "c_1", shown)
    kept = store.raw("proposals", "c_1")
    assert kept["preview"] == {"en": shown.en, "nl": shown.nl, "sha256": shown.sha256}
    assert (kept["run_id"], kept["agent"]) == ("r_1", "a")


def test_shadow_runs_are_counted_with_the_capability():
    store = FakeStore()
    assert count_shadow_run(store, POLICY) == 1
    assert count_shadow_run(store, POLICY) == 2
    state = store.get_shadow("a")
    assert state.tools == POLICY.tools and state.max_class == "R1"


def test_a_call_whose_only_argument_is_agent_text_shows_no_argument_list():
    shown = preview(args={"content": "x"}, agent_text={"content": "x"})
    assert "Arguments" not in shown.en and "Argumenten" not in shown.nl
