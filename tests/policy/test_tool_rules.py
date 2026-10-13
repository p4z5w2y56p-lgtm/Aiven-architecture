"""The tool rules (validator-spec 3.4): `tools`, `forbidden`, and what follows from them.

Each case runs `build_policy` on a small front matter (tests/support/rules.py). The base lists
sheets.read (R0), gmail.draft (R1) and gmail.send (R2), and forbids the four baseline items. A case
adds an entry to a list, and then that entry is the only thing the rules have to say about.
"""

from dataclasses import replace

import pytest

from aiven.policy import constants
from aiven.policy.catalog import Action
from aiven.policy.tools import tool_problem
from tests.support.frontmatter import front_without
from tests.support.rules import (
    CATALOG,
    UNSETTLED_TOOLS,
    catalog_with,
    check,
    run_front,
    setting,
    with_tools,
)

ALL_BUILT = {"drive": "built", "email": "built", "agentbuilder": "built"}
WRAPPER_WARNINGS_OF_THE_BASE = 3


def add_tool(entry: str):
    return lambda data: data["tools"].append(entry)


def add_forbidden(entry: str):
    return lambda data: data["forbidden"].append(entry)


def only_forbidden(entry: str):
    return setting("forbidden", [entry])


def tool_line(run, tool: str) -> int:
    return run.entry("tools", tool)


def forbidden_line(run, entry: str) -> int:
    return run.entry("forbidden", entry)


def numbered(count: int) -> list[str]:
    """Names that are no tool, one for each number."""
    return [f"agentbuilder.tool{n}" for n in range(count)]


# --- one tool entry: the first rule it fails decides (ruling R32)

BAD_TOOLS = {
    # a wildcard comes first, whatever else the entry is
    "star": ("*", "E-TOOL-WILDCARD"),
    "namespace star": ("drive.*", "E-TOOL-WILDCARD"),
    "star inside": ("drive.re*d", "E-TOOL-WILDCARD"),
    "reserved namespace star": ("payments.*", "E-TOOL-WILDCARD"),
    "star behind a space": ("drive.read *", "E-TOOL-WILDCARD"),
    # a reserved namespace is R4, and never also unknown
    "payments": ("payments.pay", "E-TOOL-R4"),
    "payments, deeper": ("payments.refunds.create", "E-TOOL-R4"),
    "policy": ("policy.sign", "E-TOOL-R4"),
    "audit": ("audit.read", "E-TOOL-R4"),
    "killswitch": ("killswitch.stop", "E-TOOL-R4"),
    "iam": ("iam.grant", "E-TOOL-R4"),
    "secrets": ("secrets.get", "E-TOOL-R4"),
    "the one reserved name": ("agentbuilder.permissions", "E-TOOL-R4"),
    # not in the catalog
    "a typo": ("drive.reed", "E-TOOL-UNKNOWN"),
    "capital": ("Drive.read", "E-TOOL-UNKNOWN"),
    "space behind it": ("drive.read ", "E-TOOL-UNKNOWN"),
    "space in front": (" drive.read", "E-TOOL-UNKNOWN"),
    "no dot": ("drive", "E-TOOL-UNKNOWN"),
    "a reserved name without its dot": ("payments", "E-TOOL-UNKNOWN"),
    "a namespace that only starts like a reserved one": ("paymentsx.pay", "E-TOOL-UNKNOWN"),
    "almost the reserved name": ("agentbuilder.permission", "E-TOOL-UNKNOWN"),
    "the reserved name and more": ("agentbuilder.permissionsx", "E-TOOL-UNKNOWN"),
    "empty": ("", "E-TOOL-UNKNOWN"),
    # R3: in the catalog, and not grantable. The baseline forbids three of them as well.
    "move": ("drive.move", "E-TOOL-R3"),
    "share": ("drive.share", "E-TOOL-R3"),
    "delete": ("drive.delete", "E-TOOL-R3"),
    "bulk": ("gmail.send_bulk", "E-TOOL-R3"),
}


@pytest.mark.parametrize(("tool", "code"), BAD_TOOLS.values(), ids=BAD_TOOLS)
def test_a_tool_that_fails_a_rule_gets_that_code_and_no_other(tool, code):
    run = check(add_tool(tool))
    assert run.places() == [(code, tool_line(run, tool))]
    assert run.params(code) == {"tool": tool}
    # and no warning that it needs a wrapper: only the three tools of the base have one
    assert run.codes(wrappers=True).count("W-TOOL-NOT-LIVE") == WRAPPER_WARNINGS_OF_THE_BASE


@pytest.mark.parametrize(("tool", "code"), BAD_TOOLS.values(), ids=BAD_TOOLS)
def test_tool_problem_is_the_code_of_the_first_rule_that_the_tool_fails(tool, code):
    # The body checks ask it too (ruling R33), so that they never judge a tool by another rule.
    assert tool_problem(tool, CATALOG) == code


def test_the_bad_tools_cover_every_code_every_r3_action_and_every_reserved_namespace():
    assert {code for _, code in BAD_TOOLS.values()} == {
        "E-TOOL-WILDCARD",
        "E-TOOL-R4",
        "E-TOOL-UNKNOWN",
        "E-TOOL-R3",
    }
    r3 = {action.id for action in CATALOG.actions.values() if action.cls == "R3"}
    assert r3 <= {tool for tool, code in BAD_TOOLS.values() if code == "E-TOOL-R3"}
    for pattern in CATALOG.reserved:
        namespace = pattern.split(".")[0] + "."
        assert any(
            tool.startswith(namespace) and code == "E-TOOL-R4" for tool, code in BAD_TOOLS.values()
        ), pattern


def test_a_tool_whose_class_in_the_catalog_is_r4_is_r4():
    catalog = catalog_with(Action("ops.wipe", "R4", "drive"))
    run = check(add_tool("ops.wipe"), catalog=catalog)
    assert run.places() == [("E-TOOL-R4", tool_line(run, "ops.wipe"))]


def test_the_reserved_namespaces_are_the_ones_of_the_catalog_in_use():
    catalog = replace(CATALOG, reserved=(*CATALOG.reserved, "ops.*"))
    run = check(add_tool("ops.wipe"), catalog=catalog)
    assert run.places() == [("E-TOOL-R4", tool_line(run, "ops.wipe"))]
    assert check(add_tool("ops.wipe")).codes() == ["E-TOOL-UNKNOWN"]


GRANTABLE = [action.id for action in CATALOG.actions.values() if action.cls in ("R0", "R1", "R2")]


def test_the_grantable_actions_are_the_r0_r1_and_r2_rows_of_the_catalog():
    assert sorted(GRANTABLE) == [
        "agentbuilder.create",
        "agentbuilder.publish",
        "agentbuilder.read",
        "drive.create",
        "drive.list",
        "drive.read",
        "drive.update",
        "gmail.draft",
        "gmail.read",
        "gmail.send",
        "sheets.read",
        "sheets.write",
    ]


@pytest.mark.parametrize("tool", GRANTABLE)
def test_every_r0_r1_and_r2_action_of_the_catalog_can_be_granted(tool):
    run = check(with_tools(tool))
    assert [code for code in run.codes() if code.startswith("E-TOOL")] == []
    assert tool_problem(tool, CATALOG) is None


def test_a_policy_without_a_usable_tools_list_has_no_tool_findings():
    # Missing or a placeholder: load() has reported it, and there is no list to judge.
    assert run_front(front_without("tools")).codes(wrappers=True) == []
    assert check(setting("tools", "TODO")).codes(wrappers=True) == []


def test_the_findings_of_a_list_in_flow_style_stand_on_the_line_of_each_entry():
    # `load` gives every entry of a list the line where it is written: here all on one line.
    front = check(add_tool("gmail.sned")).front.replace(
        'tools:\n  - "sheets.read"\n  - "gmail.draft"\n  - "gmail.send"\n  - "gmail.sned"\n',
        'tools: ["sheets.read", "gmail.draft", "gmail.send", "gmail.sned", "drive.move"]\n',
    )
    run = run_front(front)
    assert run.places() == [
        ("E-TOOL-R3", run.line("tools:")),
        ("E-TOOL-UNKNOWN", run.line("tools:")),
    ]
    assert [f.params["tool"] for f in run.findings if f.code.startswith("E-TOOL")] == [
        "gmail.sned",
        "drive.move",
    ]


# --- W-TOOL-NOT-LIVE: the wrapper is planned (section 3.4)


@pytest.mark.parametrize(
    ("tool", "wrapper"),
    [
        ("sheets.read", "Drive"),
        ("drive.create", "Drive"),
        ("gmail.read", "Email"),
        ("gmail.send", "Email"),
        ("agentbuilder.read", "Agent Builder"),
        ("agentbuilder.publish", "Agent Builder"),
    ],
)
def test_a_tool_of_a_planned_wrapper_is_a_warning_with_the_display_name_of_the_wrapper(
    tool, wrapper
):
    run = check(with_tools(tool))
    assert run.places(wrappers=True).count(("W-TOOL-NOT-LIVE", tool_line(run, tool))) == 1
    assert run.params("W-TOOL-NOT-LIVE") == {"tool": tool, "wrapper": wrapper}


def test_the_base_has_a_warning_for_each_of_its_three_tools():
    run = check()
    assert run.places(wrappers=True) == [
        ("W-TOOL-NOT-LIVE", tool_line(run, tool))
        for tool in ("sheets.read", "gmail.draft", "gmail.send")
    ]
    assert [f.params["wrapper"] for f in run.findings] == ["Drive", "Email", "Email"]


def test_a_wrapper_that_is_built_gives_no_warning():
    # Whether a built wrapper is switched on for this agent is only known at load (Task 1.7).
    assert check(catalog=catalog_with(**ALL_BUILT)).codes(wrappers=True) == []


def test_only_the_wrappers_that_are_planned_give_a_warning():
    run = check(catalog=catalog_with(drive="built"))
    assert [f.params["tool"] for f in run.findings] == ["gmail.draft", "gmail.send"]


def test_a_tool_that_fails_its_own_rules_has_no_warning_about_its_wrapper():
    run = check(with_tools("drive.move", "drive.reed", "drive.*", "payments.pay"))
    assert run.codes(wrappers=True).count("W-TOOL-NOT-LIVE") == 0


# --- E-TOOL-ABOVE-MAX-CLASS


@pytest.mark.parametrize(
    ("max_class", "above"),
    [("R0", ["gmail.draft", "gmail.send"]), ("R1", ["gmail.send"]), ("R2", [])],
)
def test_a_tool_above_max_class_is_an_error_with_both_classes(max_class, above):
    run = check(setting("max_class", max_class))
    assert run.places() == [("E-TOOL-ABOVE-MAX-CLASS", tool_line(run, tool)) for tool in above]
    assert [f.params for f in run.findings if f.code == "E-TOOL-ABOVE-MAX-CLASS"] == [
        {"tool": tool, "class": CATALOG.actions[tool].cls, "max": max_class} for tool in above
    ]


@pytest.mark.parametrize("max_class", ["R3", "R4", "high", "TODO"])
def test_a_max_class_that_is_not_valid_is_not_compared_with_the_tools(max_class):
    # When max_class is invalid or a placeholder, ABOVE-MAX-CLASS and the slack warning are
    # skipped. One defect, one code.
    codes = check(setting("max_class", max_class)).codes()
    assert "E-TOOL-ABOVE-MAX-CLASS" not in codes
    assert "W-MAX-CLASS-SLACK" not in codes


def test_a_tool_that_is_not_grantable_is_not_also_above_max_class():
    def change(data):
        data["tools"].append("drive.move")
        data["max_class"] = "R0"

    run = check(change)
    assert run.places() == [
        ("E-TOOL-ABOVE-MAX-CLASS", tool_line(run, "gmail.draft")),
        ("E-TOOL-ABOVE-MAX-CLASS", tool_line(run, "gmail.send")),
        ("E-TOOL-R3", tool_line(run, "drive.move")),
    ]


# --- E-TOOL-FORBIDDEN


@pytest.mark.parametrize(
    ("entry", "tools"),
    [
        ("sheets.read", ["sheets.read"]),
        ("gmail.send", ["gmail.send"]),
        ("sheets.*", ["sheets.read"]),
        ("gmail.*", ["gmail.draft", "gmail.send"]),
    ],
)
def test_a_tool_that_a_forbidden_entry_matches_is_an_error_on_the_line_of_the_tool(entry, tools):
    run = check(add_forbidden(entry))
    assert run.places() == [("E-TOOL-FORBIDDEN", tool_line(run, tool)) for tool in tools]
    assert [f.params for f in run.findings if f.code == "E-TOOL-FORBIDDEN"] == [
        {"tool": tool, "pattern": entry} for tool in tools
    ]


def test_a_tool_that_two_entries_match_gets_one_finding_with_the_first_of_them():
    def patterns(run):
        return [
            (f.params["tool"], f.params["pattern"])
            for f in run.findings
            if f.code == "E-TOOL-FORBIDDEN"
        ]

    first = check(lambda d: d["forbidden"].extend(["gmail.*", "gmail.send"]))
    assert patterns(first) == [("gmail.draft", "gmail.*"), ("gmail.send", "gmail.*")]
    second = check(lambda d: d["forbidden"].extend(["gmail.send", "gmail.*"]))
    assert patterns(second) == [("gmail.draft", "gmail.*"), ("gmail.send", "gmail.send")]


def test_a_tool_that_is_above_max_class_and_forbidden_gets_both_codes():
    # R0 to R2 tools get ABOVE-MAX-CLASS and FORBIDDEN independently (ruling R32).
    def change(data):
        data["max_class"] = "R1"
        data["forbidden"].append("gmail.send")

    run = check(change)
    line = tool_line(run, "gmail.send")
    assert run.places() == [("E-TOOL-ABOVE-MAX-CLASS", line), ("E-TOOL-FORBIDDEN", line)]


@pytest.mark.parametrize("entry", ["gmail.send ", "gmail.sen*", "Gmail.send", "TODO"], ids=repr)
def test_an_entry_that_is_not_valid_forbids_nothing(entry):
    assert "E-TOOL-FORBIDDEN" not in check(add_forbidden(entry)).codes()


@pytest.mark.parametrize("entry", ["gmailx.*", "gmail.sen", "gmail.sendx", "gmail.send_bulk"])
def test_an_entry_that_only_starts_like_a_tool_does_not_forbid_it(entry):
    assert "E-TOOL-FORBIDDEN" not in check(add_forbidden(entry)).codes()


# --- forbidden entries

BAD_PATTERNS = {
    "no dot": "drive",
    "a star": "*",
    "nothing behind the dot": "drive.",
    "nothing in front of the dot": ".delete",
    "a star after a name": "drive.*.x",
    "capital in the namespace": "Drive.delete",
    "capital in the name": "drive.Delete",
    "a star inside the name": "drive.dele*",
    "a star in front of the name": "*.delete",
    "a star behind a star": "drive.*x",
    "a space behind it": "drive.delete ",
    "two dots": "drive..delete",
    "namespace starts with a digit": "1drive.read",
    "name starts with a digit": "drive.1read",
    "a hyphen": "drive.de-lete",
    "a look-alike letter": "drive.d\N{CYRILLIC SMALL LETTER IE}lete",
    "empty": "",
}


@pytest.mark.parametrize("entry", BAD_PATTERNS.values(), ids=BAD_PATTERNS)
def test_an_entry_that_is_neither_a_name_nor_a_namespace_star_is_e_forbidden_pattern_only(entry):
    run = check(add_forbidden(entry))
    assert run.places() == [("E-FORBIDDEN-PATTERN", forbidden_line(run, entry))]
    assert run.params("E-FORBIDDEN-PATTERN") == {"entry": entry}


UNKNOWN_ENTRIES = {
    "the typo of the brief": "paymnets.*",
    "a typo in the namespace of a name": "paymnets.pay",
    "a name that is not in the catalog": "drive.reed",
    "a namespace that is not in it": "driv.*",
    "a typo in a name": "gmail.sendbulk",
    "almost the reserved name": "agentbuilder.permission",
    "no namespace like it": "sheet.read",
}


@pytest.mark.parametrize("entry", UNKNOWN_ENTRIES.values(), ids=UNKNOWN_ENTRIES)
def test_an_entry_that_matches_nothing_is_e_forbidden_unknown(entry):
    run = check(add_forbidden(entry))
    assert run.places() == [("E-FORBIDDEN-UNKNOWN", forbidden_line(run, entry))]
    assert run.params("E-FORBIDDEN-UNKNOWN") == {"entry": entry}


# A name inside a reserved namespace is covered by the reserved entry (ruling R50), also when no
# action of the catalog has that name: the entry matches the reserved list, so it is no typo.
RESERVED_NAMES = {
    "payments": "payments.pay",
    "policy": "policy.sign",
    "audit": "audit.read",
    "killswitch": "killswitch.stop",
    "iam": "iam.grant",
    "secrets": "secrets.get",
    "the one reserved name": "agentbuilder.permissions",
}

KNOWN_ENTRIES = [
    "sheets.read",
    "sheets.*",
    "gmail.*",
    "drive.*",
    "drive.move",
    "agentbuilder.*",
    "agentbuilder.publish",
    *RESERVED_NAMES.values(),
    *constants.RESERVED_NAMESPACES,
]


@pytest.mark.parametrize("entry", KNOWN_ENTRIES)
def test_an_entry_that_matches_a_catalog_action_or_a_reserved_entry_is_known(entry):
    codes = check(only_forbidden(entry)).codes()
    assert "E-FORBIDDEN-UNKNOWN" not in codes and "E-FORBIDDEN-PATTERN" not in codes


def test_the_reserved_names_cover_every_reserved_namespace():
    for pattern in constants.RESERVED_NAMESPACES:
        namespace = pattern.split(".")[0] + "."
        assert any(name.startswith(namespace) for name in RESERVED_NAMES.values()), pattern


@pytest.mark.parametrize("name", RESERVED_NAMES.values(), ids=RESERVED_NAMES)
def test_forbidding_a_name_inside_a_reserved_namespace_is_fine(name):
    # It forbids nothing that the reserved list does not, and it protects: a typo would not.
    assert check(add_forbidden(name)).places() == []


def test_a_namespace_item_matches_when_only_a_reserved_name_lies_in_it():
    # "A namespace.* matches when any catalog id or reserved entry lies in that namespace": here
    # the only thing in the namespace is the reserved name, and no action of the catalog.
    catalog = replace(CATALOG, reserved=(*CATALOG.reserved, "ops.wipe"))
    assert check(add_forbidden("ops.*")).codes() == ["E-FORBIDDEN-UNKNOWN"]
    assert check(add_forbidden("ops.*"), catalog=catalog).codes() == []


def test_the_catalog_in_use_decides_what_is_known():
    catalog = catalog_with(Action("sheets.share", "R3", "drive"))
    assert check(add_forbidden("sheets.share")).codes() == ["E-FORBIDDEN-UNKNOWN"]
    assert check(add_forbidden("sheets.share"), catalog=catalog).codes() == []


def test_a_repeated_entry_that_is_wrong_is_reported_once():
    run = check(lambda d: d["forbidden"].extend(["paymnets.*", "paymnets.*"]))
    assert run.codes() == ["E-FORBIDDEN-UNKNOWN"]


def test_a_forbidden_list_that_is_missing_or_a_placeholder_has_no_findings_of_its_own():
    assert run_front(front_without("forbidden")).codes() == []
    assert check(setting("forbidden", "TODO")).codes() == []


# --- the baseline: each of the four items, literally


@pytest.mark.parametrize("item", constants.FORBIDDEN_BASELINE)
def test_a_missing_baseline_item_is_one_e_forbidden_baseline_on_the_line_of_forbidden(item):
    run = check(lambda d: d["forbidden"].remove(item))
    assert run.places() == [("E-FORBIDDEN-BASELINE", run.line("forbidden:"))]
    assert run.params("E-FORBIDDEN-BASELINE") == {"missing": item}


def test_each_missing_item_is_reported_once_in_the_order_of_the_baseline():
    run = check(setting("forbidden", ["drive.share", "payments.*"]))
    assert [f.params["missing"] for f in run.findings if f.code == "E-FORBIDDEN-BASELINE"] == [
        "drive.delete",
        "gmail.send_bulk",
    ]
    assert run.lines_of("E-FORBIDDEN-BASELINE") == [run.line("forbidden:")] * 2


def test_an_empty_forbidden_list_misses_all_four():
    run = check(setting("forbidden", []))
    assert run.places() == [("E-FORBIDDEN-BASELINE", run.line("forbidden:"))] * 4
    assert [f.params["missing"] for f in run.findings if f.code == "E-FORBIDDEN-BASELINE"] == list(
        constants.FORBIDDEN_BASELINE
    )


@pytest.mark.parametrize(
    ("instead", "missing"),
    [
        (["drive.*"], ["drive.delete", "drive.share"]),
        (["payments.pay"], ["payments.*"]),
        (["gmail.*"], ["gmail.send_bulk"]),
    ],
)
def test_the_baseline_must_be_there_literally_so_a_wider_entry_does_not_count(instead, missing):
    kept = [item for item in constants.FORBIDDEN_BASELINE if item not in missing]
    run = check(setting("forbidden", kept + instead))
    assert [
        f.params["missing"] for f in run.findings if f.code == "E-FORBIDDEN-BASELINE"
    ] == missing


def test_an_entry_that_is_a_placeholder_is_not_checked_and_is_no_item_of_the_baseline():
    run = check(lambda d: d["forbidden"].__setitem__(1, "TODO"))
    assert run.places() == [("E-FORBIDDEN-BASELINE", run.line("forbidden:"))]
    assert run.params("E-FORBIDDEN-BASELINE") == {"missing": "drive.delete"}


# --- how many tools (E-RANGE)


def test_no_tool_at_all_is_e_range():
    run = check(setting("tools", []))
    assert run.lines_of("E-RANGE") == [run.line("tools:")]
    assert run.params("E-RANGE") == {"field": "tools", "value": "0", "min": "1", "max": "20"}
    assert run.policy.tools == ()


def test_twenty_tools_are_fine_and_twenty_one_are_e_range_on_the_line_of_the_list():
    assert "E-RANGE" not in check(setting("tools", numbered(20))).codes()
    run = check(setting("tools", numbered(21)))
    assert run.lines_of("E-RANGE") == [run.line("tools:")]
    assert run.params("E-RANGE") == {"field": "tools", "value": "21", "min": "1", "max": "20"}


def test_the_size_counts_the_entries_that_are_wrong_or_placeholders_but_not_the_repeats():
    wrong = check(setting("tools", numbered(20) + ["TODO"]))
    assert wrong.params("E-RANGE")["value"] == "21"
    assert wrong.codes().count("E-TOOL-UNKNOWN") == 20
    repeated = check(setting("tools", numbered(20) + numbered(1)))
    assert "E-RANGE" not in repeated.codes()


# --- W-MAX-CLASS-SLACK


@pytest.mark.parametrize(
    ("tools", "max_class", "highest"),
    [
        (["sheets.read"], "R1", "R0"),
        (["sheets.read"], "R2", "R0"),
        (["sheets.read", "gmail.draft"], "R2", "R1"),
        (["drive.update"], "R2", "R1"),  # it can become R2 on a shared file, and then it waits
    ],
)
def test_a_max_class_above_the_highest_tool_is_a_warning_with_both_classes(
    tools, max_class, highest
):
    run = check(with_tools(*tools, max_class=max_class))
    assert run.lines_of("W-MAX-CLASS-SLACK") == [run.line("max_class:")]
    assert run.params("W-MAX-CLASS-SLACK") == {"max": max_class, "highest": highest}


@pytest.mark.parametrize(
    ("tools", "max_class"),
    [
        (["sheets.read"], "R0"),
        (["gmail.draft"], "R1"),
        (["gmail.send"], "R2"),
        (["gmail.read", "gmail.send"], "R2"),
    ],
)
def test_a_max_class_that_the_highest_tool_reaches_is_not_slack(tools, max_class):
    assert "W-MAX-CLASS-SLACK" not in check(with_tools(*tools, max_class=max_class)).codes()


@pytest.mark.parametrize("tools", UNSETTLED_TOOLS.values(), ids=UNSETTLED_TOOLS)
def test_there_is_no_slack_while_the_tool_list_is_unsettled(tools):
    # Which tools there will be is not known yet, so a max_class above the highest of them would be
    # a guess (rulings R49 and R53). The error of the odd entry is the one to fix first.
    assert "W-MAX-CLASS-SLACK" not in check(with_tools(*tools, max_class="R2")).codes()


def test_what_is_said_about_the_tools_that_passed_does_not_wait_for_the_rest_of_the_list():
    # Only the guesses wait (ruling R53): the errors and the warning about the wrapper are about
    # a tool that is there, whatever the placeholder turns out to be.
    def change(data):
        data["tools"] = ["gmail.send", "TODO"]
        data["max_class"] = "R1"
        data["forbidden"].append("gmail.send")

    run = check(change)
    line = run.entry("tools", "gmail.send")
    assert run.places(wrappers=True) == [
        ("E-TOOL-ABOVE-MAX-CLASS", line),
        ("E-TOOL-FORBIDDEN", line),
        ("W-TOOL-NOT-LIVE", line),
    ]


def test_a_list_that_is_too_long_is_unsettled_though_every_entry_passes():
    # Only the size is wrong here, so it is not an entry that unsettles the list. The catalog has
    # too few actions to make 21 distinct tools, so it gets 21 more (ruling R53).
    extra = [Action(f"drive.extra{n}", "R0", "drive") for n in range(21)]
    catalog = catalog_with(*extra)
    names = [action.id for action in extra]
    guesses = {"W-LIMIT-UNUSED", "W-SCOPE-UNUSED", "W-MAX-CLASS-SLACK"}
    assert guesses <= set(check(with_tools(*names[:20]), catalog=catalog).codes())
    too_long = check(with_tools(*names), catalog=catalog)
    assert too_long.codes() == ["E-RANGE"]
