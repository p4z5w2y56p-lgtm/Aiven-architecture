"""The checks across all policies (validator-spec 3.6 and 3.9): `check_duplicates`, `check_history`.

`check_duplicates(items)` looks at the files of a set together: `items` are (path, policy) pairs. It
reports E-AGENT-DUPLICATE and E-PRINCIPAL-DUPLICATE. `check_history(path, policy, previous)` looks
at one file against the previous signed policy of its agent, or against `None` for a new agent. It
reports E-VERSION-ORDER (the rule of CI) and W-WIDENS. They are findings about a whole file, because
a policy carries no line map. They are two functions so that a caller that has the whole set and no
history can ask for the first alone (ruling R91).

The policies are made as files from the valid base (tests/support/variants.py): `V1` is the base,
which is version 1 of `invoice-reminder`.
"""

from pathlib import Path

import pytest

from aiven.policy.content import _SHOWN as SHOWN
from aiven.policy.findings import format_line, message
from aiven.policy.model import Policy
from aiven.policy.policyset import check_duplicates, check_history
from tests.support import gen
from tests.support.bodies import policy_of
from tests.support.frontmatter import DATA
from tests.support.policies import valid_base
from tests.support.rules import setting, with_tools
from tests.support.variants import another, principal_of, variant

AGENT = DATA["agent"]
PRINCIPAL = DATA["principal"]
TOOLS = tuple(DATA["tools"])
PATH = "policies/invoice-reminder.md"
FILE = Path(PATH)
V1 = variant()

CODES_OF_DUPLICATES = {"E-AGENT-DUPLICATE", "E-PRINCIPAL-DUPLICATE"}
CODES_OF_HISTORY = {"E-VERSION-ORDER", "W-WIDENS"}


def shape(findings):
    return [(f.code, f.path, f.params) for f in findings]


def files(*named: tuple[str, Policy]) -> list[tuple[Path, Policy]]:
    """(path, policy) pairs from (file name, policy) pairs: the files stand in `policies/`."""
    return [(Path("policies") / name, policy) for name, policy in named]


# --- E-AGENT-DUPLICATE


def test_two_files_with_the_same_agent_both_get_e_agent_duplicate():
    copy = variant(setting("principal", principal_of("invoice-copy")))
    found = check_duplicates(files(("invoice-reminder.md", V1), ("invoice-copy.md", copy)))
    params = {"agent": AGENT, "files": "invoice-copy.md, invoice-reminder.md"}
    assert shape(found) == [
        ("E-AGENT-DUPLICATE", "policies/invoice-reminder.md", params),
        ("E-AGENT-DUPLICATE", "policies/invoice-copy.md", params),
    ]


def test_a_group_names_all_its_files_sorted_whatever_the_order_of_the_set():
    named = [
        (name, variant(setting("principal", principal_of(name[0]))))
        for name in ("c.md", "a.md", "b.md")
    ]
    found = check_duplicates(files(*named))
    assert [(f.path, f.params["files"]) for f in found] == [
        ("policies/c.md", "a.md, b.md, c.md"),
        ("policies/a.md", "a.md, b.md, c.md"),
        ("policies/b.md", "a.md, b.md, c.md"),
    ]


def test_only_the_files_that_share_an_agent_get_the_finding():
    copy = variant(setting("principal", principal_of("invoice-copy")))
    nudge = another("payment-nudge")
    items = files(
        ("invoice-reminder.md", V1), ("payment-nudge.md", nudge), ("invoice-copy.md", copy)
    )
    assert [f.path for f in check_duplicates(items)] == [
        "policies/invoice-reminder.md",
        "policies/invoice-copy.md",
    ]


# --- E-PRINCIPAL-DUPLICATE


def test_two_agents_with_one_principal_both_get_e_principal_duplicate():
    nudge = variant(setting("agent", "payment-nudge"))  # the principal of invoice-reminder
    found = check_duplicates(files(("invoice-reminder.md", V1), ("payment-nudge.md", nudge)))
    assert shape(found) == [
        (
            "E-PRINCIPAL-DUPLICATE",
            "policies/invoice-reminder.md",
            {"principal": PRINCIPAL, "other": "payment-nudge.md"},
        ),
        (
            "E-PRINCIPAL-DUPLICATE",
            "policies/payment-nudge.md",
            {"principal": PRINCIPAL, "other": "invoice-reminder.md"},
        ),
    ]


def test_a_principal_lists_the_other_files_and_not_its_own_sorted():
    named = [(f"{name}.md", variant(setting("agent", name))) for name in ("zed", "mid", "abc")]
    found = check_duplicates(files(*named))
    assert [(f.path, f.params["other"]) for f in found] == [
        ("policies/zed.md", "abc.md, mid.md"),
        ("policies/mid.md", "abc.md, zed.md"),
        ("policies/abc.md", "mid.md, zed.md"),
    ]


def test_the_file_itself_is_left_out_by_place_and_not_by_name():
    # Two files of one name in two folders: each names the other, which has the same name.
    second = variant(setting("agent", "payment-nudge"))
    items = [(Path("a/x.md"), V1), (Path("b/x.md"), second)]
    assert [(f.path, f.params["other"]) for f in check_duplicates(items)] == [
        ("a/x.md", "x.md"),
        ("b/x.md", "x.md"),
    ]


def test_a_copy_of_a_file_is_a_duplicate_agent_and_a_duplicate_principal():
    found = check_duplicates(files(("invoice-reminder.md", V1), ("invoice-copy.md", V1)))
    assert [(f.code, f.path) for f in found] == [
        ("E-AGENT-DUPLICATE", "policies/invoice-reminder.md"),
        ("E-PRINCIPAL-DUPLICATE", "policies/invoice-reminder.md"),
        ("E-AGENT-DUPLICATE", "policies/invoice-copy.md"),
        ("E-PRINCIPAL-DUPLICATE", "policies/invoice-copy.md"),
    ]


def test_files_that_share_nothing_have_no_finding():
    items = files(("invoice-reminder.md", V1), ("payment-nudge.md", another("payment-nudge")))
    assert check_duplicates(items) == []
    assert check_duplicates([]) == []
    assert check_duplicates(files(("invoice-reminder.md", V1))) == []


# --- E-VERSION-ORDER


@pytest.mark.parametrize(
    ("old", "new", "required"),
    [
        (1, 2, None),
        (5, 6, None),
        (9998, 9999, None),
        (1, 3, 2),  # skips a version
        (1, 9999, 2),
        (1, 1, 2),  # the same version, with other content
        (5, 4, 6),  # an older version cannot come back
    ],
)
def test_the_version_of_a_changed_file_is_the_previous_version_plus_one(old, new, required):
    previous = variant(setting("version", old))
    changed = variant(
        setting("version", new), setting("shadow.min_runs", 20)
    )  # narrowing: no W-WIDENS
    found = check_history(FILE, changed, previous)
    expected = [] if required is None else [{"value": str(new), "next": str(required)}]
    assert [(f.code, f.path, f.params) for f in found] == [
        ("E-VERSION-ORDER", PATH, params) for params in expected
    ]


@pytest.mark.parametrize(("version", "required"), [(1, None), (2, 1), (9999, 1)])
def test_a_new_agent_starts_at_version_one(version, required):
    # No previous policy: the agent is new. (A caller that does not know the history of the file
    # does not ask: see the module of the command line.)
    found = check_history(FILE, variant(setting("version", version)), previous=None)
    expected = (
        []
        if required is None
        else [("E-VERSION-ORDER", PATH, {"value": str(version), "next": "1"})]
    )
    assert shape(found) == expected


def test_a_file_that_did_not_change_keeps_its_version():
    same = variant(setting("version", 4))
    assert check_history(FILE, same, same) == []
    assert check_history(FILE, variant(setting("version", 4)), same) == []


def test_a_file_with_other_bytes_has_changed_though_its_fields_are_the_same():
    # The hash decides. The same fields in a file that differs (a body that was edited, say) are
    # a new signed file, and its version is the next one.
    before = policy_of(valid_base())
    assert before.sha256 != V1.sha256
    found = check_history(FILE, V1, before)
    assert shape(found) == [("E-VERSION-ORDER", PATH, {"value": "1", "next": "2"})]


def test_an_unchanged_file_is_still_checked_against_the_other_files():
    # It is that version, so it has no finding of the history. It is still a copy of itself.
    same = variant(setting("version", 4))
    assert check_history(FILE, same, same) == []
    found = check_duplicates(files(("invoice-reminder.md", same), ("invoice-copy.md", same)))
    assert {f.code for f in found} == {"E-AGENT-DUPLICATE", "E-PRINCIPAL-DUPLICATE"}


# --- W-WIDENS


def test_a_widened_file_gets_w_widens_with_the_changes_joined():
    new = variant(
        setting("version", 2), setting("limits.runs_per_day", 2), setting("shadow.min_runs", 5)
    )
    (found,) = check_history(FILE, new, V1)
    assert (found.code, found.severity, found.path) == ("W-WIDENS", "warning", PATH)
    assert found.params == {"changes": "limits.runs_per_day: 1 -> 2; shadow.min_runs: 10 -> 5"}


def test_a_new_tool_restarts_shadow_for_the_runs_of_the_new_version():
    new = variant(
        setting("version", 2), with_tools(*TOOLS, "drive.read"), setting("shadow.min_runs", 7)
    )
    (found,) = check_history(FILE, new, V1)
    assert found.params == {
        "changes": "tools: +drive.read; shadow.min_runs: 10 -> 7",
        "restart_runs": "7",
    }


def test_a_restart_for_one_run_says_1_run():
    new = variant(
        setting("version", 2), with_tools(*TOOLS, "drive.read"), setting("shadow.min_runs", 1)
    )
    (found,) = check_history(FILE, new, V1)
    assert found.params["restart_runs"] == "1"
    assert format_line(found).endswith(" Shadow mode starts again for 1 run.")
    assert message(found, "nl").endswith(" De schaduwmodus begint opnieuw voor 1 run.")


def test_a_raised_class_restarts_shadow_too():
    reads = with_tools("sheets.read")
    previous = variant(reads, setting("max_class", "R1"))
    new = variant(reads, setting("max_class", "R2"), setting("version", 2))
    (found,) = check_history(FILE, new, previous)
    assert found.params == {"changes": "max_class: R1 -> R2", "restart_runs": "10"}


def test_a_widening_without_a_restart_has_no_number_of_runs():
    new = variant(setting("version", 2), setting("untrusted_input", "taint"))
    (found,) = check_history(FILE, new, V1)
    assert found.params == {"changes": "untrusted_input: strict -> taint"}


def test_a_file_that_narrows_has_no_w_widens():
    new = variant(setting("version", 2), with_tools("sheets.read", "gmail.draft"))
    assert check_history(FILE, new, V1) == []


def test_a_new_agent_has_nothing_to_widen_from():
    new = variant(with_tools(*TOOLS, "drive.read"), setting("limits.runs_per_day", 9))
    assert check_history(FILE, new, None) == []


def test_a_wrong_version_does_not_hide_a_widening():
    new = variant(setting("version", 3), setting("limits.runs_per_day", 2))
    found = check_history(FILE, new, V1)
    assert [f.code for f in found] == ["E-VERSION-ORDER", "W-WIDENS"]


# --- the whole list of changes is shown (ruling R73)

ELLIPSIS = "\N{HORIZONTAL ELLIPSIS}"


def test_a_widening_of_every_kind_is_shown_whole_in_the_line_and_in_both_languages():
    # 20 tools and 10 addresses are added, and every other field is widened: the list is about
    # 1,000 characters, which the cut at 200 used to shorten. The strings are written out here, not
    # made by `widening`, so that the test is about what is shown.
    tools = [f"agentbuilder.tool{number:02d}" for number in range(20)]
    addresses = [f"person{number}@aivenstudios.com" for number in range(10)]
    before = variant(
        with_tools("sheets.read", max_class="R0"),
        setting("limits.emails_per_day", 0),
        setting("limits.records_per_run", 0),
        setting("limits.max_runtime_s", 60),
        setting("scope.email_to", ["z@aivenstudios.com"]),
    )
    new = variant(
        setting("version", 2),
        with_tools(*tools, max_class="R2"),
        setting("untrusted_input", "taint"),
        setting("limits.emails_per_day", 50),
        setting("limits.records_per_run", 200),
        setting("limits.max_runtime_s", 900),
        setting("limits.runs_per_day", 10),
        setting("scope.drive_folder_id", "0AnotherFolderId1234"),
        setting("scope.drive_folder_path", "AIVEN Architecture Sandbox"),
        setting("scope.email_to", ["z@aivenstudios.com", *addresses]),
        setting("shadow.min_runs", 5),
    )
    changes = "; ".join(
        [
            "tools: " + " ".join(f"+{tool}" for tool in tools),
            "max_class: R0 -> R2",
            "limits.emails_per_day: 0 -> 50",
            "limits.records_per_run: 0 -> 200",
            "limits.max_runtime_s: 60 -> 900",
            "limits.runs_per_day: 1 -> 10",
            "scope.drive_folder_id: changed",
            "scope.drive_folder_path: changed",
            "scope.email_to: " + " ".join(f"+{address}" for address in addresses),
            "untrusted_input: strict -> taint",
            "shadow.min_runs: 10 -> 5",
        ]
    )
    assert 900 < len(changes) < SHOWN  # well beyond the old cut of 200, and within the cut
    (found,) = check_history(FILE, new, before)
    assert found.params == {"changes": changes, "restart_runs": "5"}
    for text in (format_line(found), message(found, "en"), message(found, "nl")):
        assert changes in text
        assert ELLIPSIS not in text
    assert format_line(found).endswith(f"{changes}. Shadow mode starts again for 5 runs.")


def test_an_address_that_looks_like_a_bsn_hides_only_itself_in_the_message():
    # Ruling R77. The message used to be "more room: [hidden]." and lost the tool and the limit.
    bsn = gen.valid_bsn()
    before = variant(setting("scope.email_to", ["z@aivenstudios.com"]))
    new = variant(
        setting("version", 2),
        with_tools(*TOOLS, "drive.read"),
        setting("limits.runs_per_day", 2),
        setting("scope.email_to", ["z@aivenstudios.com", f"{bsn}@aivenstudios.com"]),
    )
    (found,) = check_history(FILE, new, before)
    changes = "tools: +drive.read; limits.runs_per_day: 1 -> 2; scope.email_to: +[hidden]"
    assert found.params == {"changes": changes, "restart_runs": "10"}
    for text in (format_line(found), message(found, "en"), message(found, "nl")):
        assert changes in text
        assert bsn not in text


# --- the two functions apart (ruling R91)
#
# The gateway loads all its policies at once and finds the duplicates over all of them, but it keeps
# the history of an agent in its durable state, per file. A set that is asked about its duplicates
# has no history, and must not be told that a policy above version 1 is a new agent that starts
# in the wrong place.


def test_the_duplicates_of_a_set_say_nothing_of_the_versions_in_it():
    later = variant(setting("version", 4))
    nudge = another("payment-nudge", setting("version", 7))
    assert (
        check_duplicates(files(("invoice-reminder.md", later), ("payment-nudge.md", nudge))) == []
    )


def test_each_function_gives_the_codes_of_its_own_and_no_others():
    new = variant(setting("version", 3), with_tools(*TOOLS, "drive.read"))
    copy = variant(setting("version", 3))  # the agent and the principal of the first
    duplicates = check_duplicates(files(("invoice-reminder.md", new), ("invoice-copy.md", copy)))
    history = check_history(FILE, new, V1)
    assert {f.code for f in duplicates} == CODES_OF_DUPLICATES
    assert {f.code for f in history} == CODES_OF_HISTORY


def test_every_finding_is_about_a_whole_file():
    new = variant(setting("version", 3), setting("limits.runs_per_day", 2))
    copy = variant(setting("principal", principal_of("invoice-copy")))
    found = [
        *check_duplicates(files(("invoice-reminder.md", new), ("invoice-copy.md", copy))),
        *check_history(FILE, new, V1),
    ]
    assert {f.code for f in found} == {"E-AGENT-DUPLICATE", "E-VERSION-ORDER", "W-WIDENS"}
    assert all(f.line is None and f.column is None for f in found)
    assert all(f.severity == ("error" if f.code.startswith("E-") else "warning") for f in found)


def test_the_duplicates_follow_the_order_of_the_set():
    wrong = variant(setting("version", 3), setting("limits.runs_per_day", 2))
    fine = variant(setting("version", 2), setting("principal", principal_of("invoice-copy")))
    first = check_duplicates(files(("x.md", wrong), ("y.md", fine)))
    assert [(f.code, f.path) for f in first] == [
        ("E-AGENT-DUPLICATE", "policies/x.md"),
        ("E-AGENT-DUPLICATE", "policies/y.md"),
    ]
    second = check_duplicates(files(("y.md", fine), ("x.md", wrong)))
    assert [(f.code, f.path) for f in second] == [
        ("E-AGENT-DUPLICATE", "policies/y.md"),
        ("E-AGENT-DUPLICATE", "policies/x.md"),
    ]


def test_the_history_is_about_the_file_it_is_given():
    # The path of the finding is the path of the file, whatever the folder, and the same for a
    # name that has to be escaped.
    new = variant(setting("version", 3))
    for path in (Path("x.md"), Path("a/b/c.md"), Path("policies/odd\nname.md")):
        (found,) = check_history(path, new, V1)
        assert (found.code, found.path) == ("E-VERSION-ORDER", str(path).replace("\n", "\\u000a"))


def test_the_findings_read_in_both_languages():
    new = variant(setting("version", 3), with_tools(*TOOLS, "drive.read"))
    nudge = variant(setting("agent", "payment-nudge"))  # the principal of invoice-reminder
    duplicates = check_duplicates(files(("invoice-reminder.md", new), ("payment-nudge.md", nudge)))
    order, widens = check_history(FILE, new, V1)
    assert [format_line(f) for f in duplicates] == [
        "error E-PRINCIPAL-DUPLICATE policies/invoice-reminder.md: "
        f"principal {PRINCIPAL} is also used by payment-nudge.md. Each agent needs its own "
        "identity, or one could act with the other's rights.",
        "error E-PRINCIPAL-DUPLICATE policies/payment-nudge.md: "
        f"principal {PRINCIPAL} is also used by invoice-reminder.md. Each agent needs its own "
        "identity, or one could act with the other's rights.",
    ]
    assert format_line(order) == (
        "error E-VERSION-ORDER policies/invoice-reminder.md: version is 3, but the next version "
        "must be 2. Older versions can never come back."
    )
    assert format_line(widens) == (
        "warning W-WIDENS policies/invoice-reminder.md: This version gives the agent more room: "
        "tools: +drive.read. Shadow mode starts again for 10 runs."
    )
    assert message(widens, "nl") == (
        "Deze versie geeft de agent meer ruimte: tools: +drive.read. "
        "De schaduwmodus begint opnieuw voor 10 runs."
    )
    assert message(order, "nl") == (
        "version is 3, maar de volgende versie moet 2 zijn. Oudere versies kunnen nooit terugkomen."
    )
