"""The typed policy and `build_policy` (validator-spec 3.3 to 3.5; rulings R4, R7 and R26).

What each rule reports is tested in test_field_rules.py, test_tool_rules.py and
test_limit_scope_rules.py. This module is about the object: its shape, when there is one, and what
it holds when the file has errors.
"""

import hashlib
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from aiven.policy.frontmatter import FIELDS, FrontMatter, load, split
from aiven.policy.model import Limits, Policy, Scope, build_policy
from tests.support import gen
from tests.support.frontmatter import FRONT, edited, front_without, swap
from tests.support.policies import AGENTS_PROJECT, BASE_PATH, FOLDER_ID, TEMPLATE_PATH
from tests.support.rules import BASE, CATALOG, CFG, check, run_front

EXPECTED = Policy(
    agent="invoice-reminder",
    version=1,
    principal=f"agent-invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.com",
    max_class="R2",
    tools=("sheets.read", "gmail.draft", "gmail.send"),
    forbidden=("payments.*", "drive.delete", "drive.share", "gmail.send_bulk"),
    untrusted_input="strict",
    limits=Limits(
        emails_per_day=10,
        records_per_run=10,
        spend_eur_per_run=0,
        max_runtime_s=300,
        runs_per_day=1,
    ),
    scope=Scope(
        drive_folder_id=FOLDER_ID,
        drive_folder_path="AIVEN Architecture Sandbox / Invoices",
        email_to=("@aivenstudios.com",),
    ),
    shadow_min_runs=10,
    sha256="sha256:" + hashlib.sha256(BASE).hexdigest(),
)


def build(front: str, data: bytes = BASE):
    return build_policy(load(front, BASE_PATH), data, CFG, CATALOG, BASE_PATH)


def leaves(table, prefix=""):
    """The dotted path of every field of the field table that holds a value (not a mapping)."""
    for name, kind in table.items():
        if isinstance(kind, dict):
            yield from leaves(kind, f"{prefix}{name}.")
        else:
            yield f"{prefix}{name}"


# --- the shape of the model


def test_the_valid_base_builds_the_policy_it_says():
    policy, findings = build(FRONT)
    assert policy == EXPECTED
    assert [f.severity for f in findings] == ["warning"] * 3  # the wrappers are planned


def test_the_sha256_is_the_hash_of_the_bytes_that_are_given():
    # The whole file is hashed, as the signer signs it (validator-spec 2), and not the front matter.
    other = BASE + b"x"
    policy, _ = build(FRONT, other)
    assert policy.sha256 == "sha256:" + hashlib.sha256(other).hexdigest()
    assert policy.sha256 != EXPECTED.sha256
    assert policy == replace(EXPECTED, sha256=policy.sha256)


def test_the_classes_are_frozen_and_hashable():
    for value, name in [
        (EXPECTED, "agent"),
        (EXPECTED.limits, "runs_per_day"),
        (EXPECTED.scope, "email_to"),
    ]:
        with pytest.raises(FrozenInstanceError):
            setattr(value, name, None)
    again, _ = build(FRONT)
    assert hash(again) == hash(EXPECTED)
    assert len({again, EXPECTED}) == 1


def test_the_classes_have_the_fields_of_the_brief_in_its_order():
    assert [f.name for f in fields(Policy)] == [
        "agent",
        "version",
        "principal",
        "max_class",
        "tools",
        "forbidden",
        "untrusted_input",
        "limits",
        "scope",
        "shadow_min_runs",
        "sha256",
    ]
    assert [f.name for f in fields(Limits)] == list(FIELDS["limits"])
    assert [f.name for f in fields(Scope)] == list(FIELDS["scope"])


def test_every_field_of_the_field_table_is_in_the_policy():
    # `schema` is a constant (only one schema is valid), `shadow` is flat, `sha256` is not a field.
    in_policy = {f.name for f in fields(Policy)} - {"sha256", "shadow_min_runs"}
    assert set(FIELDS) == in_policy | {"schema", "shadow"}
    assert list(FIELDS["shadow"]) == ["min_runs"]


def test_the_lists_of_a_policy_are_tuples():
    assert isinstance(EXPECTED.tools, tuple)
    assert isinstance(EXPECTED.forbidden, tuple)
    assert isinstance(EXPECTED.scope.email_to, tuple)


def test_the_repr_of_a_policy_holds_no_text_of_the_file():
    marker = "marker-text-of-the-file"
    run = check(
        lambda d: d.update(
            agent=marker,
            principal=marker,
            tools=[marker],
            forbidden=[marker],
            scope={"drive_folder_id": marker, "drive_folder_path": marker, "email_to": [marker]},
        )
    )
    policy = run.policy
    assert policy.agent == marker and policy.scope.email_to == (marker,)
    for shown in (repr(policy), repr(policy.scope)):
        assert marker not in shown
    for shown in (repr(EXPECTED), repr(EXPECTED.scope)):
        assert "invoice-reminder" not in shown and "aivenstudios" not in shown


def test_the_repr_of_a_policy_holds_no_number_of_the_file():
    # E-RANGE does not stop a Policy (ruling R4), so a number that is out of range is in it, and a
    # number can be a card number or a BSN. The guard of a Finding hides such a value; so must the
    # repr, which a log, a traceback or a failed assertion would print.
    card, bsn, other = gen.valid_card(), gen.valid_bsn(), gen.valid_bsn()

    def change(data):
        data["version"] = int(bsn)
        data["limits"]["records_per_run"] = int(card)
        data["shadow"]["min_runs"] = int(other)

    run = check(change)
    policy = run.policy
    assert run.codes().count("E-RANGE") == 3
    assert policy.version == int(bsn)
    assert policy.limits.records_per_run == int(card)
    assert policy.shadow_min_runs == int(other)
    for shown in (repr(policy), repr(policy.limits), repr(policy.scope)):
        for number in (bsn, card, other):
            assert number not in shown


def test_only_the_hash_is_in_the_repr_of_a_policy():
    # Every other field comes from the file. A field that is added later has to opt out too.
    for cls in (Policy, Limits, Scope):
        assert [f.name for f in fields(cls) if f.repr] == (["sha256"] if cls is Policy else [])
    policy, _ = build(FRONT)
    assert repr(policy) == f"Policy(sha256={policy.sha256!r})"
    assert repr(policy.limits) == "Limits()" and repr(policy.scope) == "Scope()"


# --- when there is a policy (ruling R4)

REQUIRED = [path for path in leaves(FIELDS) if not path.startswith("scope.")]


@pytest.mark.parametrize("path", [*REQUIRED, "limits", "shadow"])
def test_no_policy_when_a_required_field_is_missing(path):
    policy, _ = build(front_without(path))
    assert policy is None


@pytest.mark.parametrize("path", ["scope", *(f"scope.{name}" for name in FIELDS["scope"])])
def test_the_scope_is_optional_so_a_policy_is_built_without_it(path):
    policy, _ = build(front_without(path))
    nothing = {"drive_folder_id": None, "drive_folder_path": None, "email_to": ()}
    if path == "scope":
        assert policy.scope == Scope(**nothing)
    else:
        name = path.split(".")[1]
        assert policy.scope == replace(EXPECTED.scope, **{name: nothing[name]})


NO_POLICY = {
    "version in quotes": swap("version: 1", 'version: "1"'),
    "a tool that is a number": swap("- gmail.draft", "- 5"),
    "limits is a number": edited(lambda d: d.update(limits=5)),
    "agent is a number": swap("agent: invoice-reminder", "agent: 5"),
    "an email_to that is a number": edited(lambda d: d["scope"].update(email_to=5)),
    "scope is a list": edited(lambda d: d.update(scope=[1])),
    "max_class that is none of the classes": swap("max_class: R2", "max_class: high"),
    "a drive_folder_id of the wrong shape": edited(
        lambda d: d["scope"].update(drive_folder_id="short")
    ),
    "a number that is a placeholder": swap("max_runtime_s: 300", "max_runtime_s: TBD"),
    "a version that is a placeholder": swap("version: 1", "version: TODO"),
    "a list that is a placeholder": edited(lambda d: d.update(tools="TODO")),
    "a mapping that is a placeholder": edited(lambda d: d.update(limits="FIXME")),
    "a scope that is a placeholder": edited(lambda d: d.update(scope="REPLACE_ME_SCOPE")),
}


@pytest.mark.parametrize("front", NO_POLICY.values(), ids=NO_POLICY)
def test_no_policy_for_a_wrong_type_or_for_a_placeholder_where_a_number_belongs(front):
    policy, _ = build(front)
    assert policy is None


def test_a_front_matter_without_data_has_no_policy_and_no_findings():
    assert build_policy(FrontMatter(None, {}, []), BASE, CFG, CATALOG) == (None, [])


def test_an_empty_front_matter_has_no_policy_and_the_rules_do_not_trip_over_it():
    assert build("") == (None, [])


def test_the_rules_report_the_fields_that_are_there_when_there_is_no_policy():
    # A field that is missing does not hide the errors of the others: report everything.
    run = run_front(front_without("limits.runs_per_day").replace("max_class: R2", "max_class: R3"))
    assert run.policy is None
    assert run.codes() == ["E-MAX-CLASS-R3"]


POLICY_ANYWAY = {
    "schema": (swap("schema: aiven-policy/v1", "schema: other"), "E-SCHEMA"),
    "agent": (swap("agent: invoice-reminder", "agent: ab"), "E-AGENT-ID"),
    "principal": (swap("agent-invoice-reminder@", "agent-other@"), "E-PRINCIPAL"),
    "range": (swap("runs_per_day: 1", "runs_per_day: 11"), "E-RANGE"),
    "max_class R3": (swap("max_class: R2", "max_class: R3"), "E-MAX-CLASS-R3"),
    "max_class R4": (swap("max_class: R2", "max_class: R4"), "E-MAX-CLASS-R4"),
    "untrusted_input": (
        swap("untrusted_input: strict", "untrusted_input: off"),
        "E-UNTRUSTED-INPUT",
    ),
    "spend": (swap("spend_eur_per_run: 0", "spend_eur_per_run: 5"), "E-LIMIT-SPEND"),
    "unknown tool": (swap("- gmail.draft", "- gmail.drft"), "E-TOOL-UNKNOWN"),
    "forbidden entry": (swap("- drive.share", "- drive.shar"), "E-FORBIDDEN-UNKNOWN"),
    "folder path": (swap("Sandbox / Invoices", "Elsewhere / Invoices"), "E-SCOPE-SANDBOX"),
    "email_to": (swap('- "@aivenstudios.com"', '- "@client.nl"'), "E-SCOPE-EMAIL-EXTERNAL"),
}


@pytest.mark.parametrize(("front", "code"), POLICY_ANYWAY.values(), ids=POLICY_ANYWAY)
def test_values_that_fail_their_checks_still_make_a_policy(front, code):
    run = run_front(front)
    assert run.policy is not None
    assert code in run.codes()


def test_an_unknown_field_does_not_stop_the_policy():
    # load() reports E-FIELD-UNKNOWN and leaves the field out; every field of the table is there.
    policy, findings = build(edited(lambda d: d.update(extra=1)))
    assert policy == replace(EXPECTED, sha256=policy.sha256)
    assert [f.severity for f in findings] == ["warning"] * 3


def test_a_policy_with_errors_holds_the_values_as_they_are_written():
    front = FRONT
    for old, new in [
        ("version: 1", "version: 0"),
        ("max_class: R2", "max_class: R3"),
        ("untrusted_input: strict", "untrusted_input: off"),
        ("min_runs: 10", "min_runs: 101"),
        ("- gmail.draft", "- gmail.drft"),
        ("spend_eur_per_run: 0", "spend_eur_per_run: 5"),
    ]:
        assert front.count(old) == 1
        front = front.replace(old, new)
    policy = run_front(front).policy
    assert (policy.version, policy.max_class, policy.untrusted_input) == (0, "R3", "off")
    assert policy.shadow_min_runs == 101
    assert policy.tools == ("sheets.read", "gmail.drft", "gmail.send")
    assert policy.limits.spend_eur_per_run == 5


# --- placeholders (ruling R7): the policy keeps what is written


def test_the_template_builds_a_policy_that_holds_its_placeholders():
    front, _, _ = split(TEMPLATE_PATH.read_text(encoding="utf-8"))
    policy, findings = build(front, TEMPLATE_PATH.read_bytes())
    project = "REPLACE_ME_AGENTS_PROJECT"
    assert policy.principal == f"agent-invoice-reminder@{project}.iam.gserviceaccount.com"
    assert policy.scope.drive_folder_id == "REPLACE_ME_FOLDER_ID"
    assert policy == replace(
        EXPECTED,
        principal=policy.principal,
        scope=replace(EXPECTED.scope, drive_folder_id="REPLACE_ME_FOLDER_ID"),
        sha256="sha256:" + hashlib.sha256(TEMPLATE_PATH.read_bytes()).hexdigest(),
    )
    assert [f.code for f in findings] == ["W-TOOL-NOT-LIVE"] * 3  # no E-PRINCIPAL, no E-FIELD-TYPE


PLACEHOLDERS = {
    "agent": ("agent", "agent: invoice-reminder", "agent: TODO", "TODO"),
    "principal": (
        "principal",
        "agent-invoice-reminder@aiven-agents-test",
        "agent-invoice-reminder@TBD",
        "agent-invoice-reminder@TBD.iam.gserviceaccount.com",
    ),
    "max_class": ("max_class", "max_class: R2", "max_class: FIXME", "FIXME"),
    "untrusted_input": (
        "untrusted_input",
        "untrusted_input: strict",
        "untrusted_input: TODO",
        "TODO",
    ),
    "drive_folder_id": (
        "scope.drive_folder_id",
        FOLDER_ID,
        "REPLACE_ME_FOLDER_ID",
        "REPLACE_ME_FOLDER_ID",
    ),
}


@pytest.mark.parametrize(("name", "old", "new", "kept"), PLACEHOLDERS.values(), ids=PLACEHOLDERS)
def test_a_string_field_that_holds_a_placeholder_is_kept_as_written_and_not_checked(
    name, old, new, kept
):
    front = FRONT.replace(old, new)
    assert front != FRONT
    run = run_front(front)
    value = run.policy
    for part in name.split("."):
        value = getattr(value, part)
    assert value == kept
    assert run.codes() == []  # nothing of the field's own rules


def test_a_placeholder_entry_of_a_list_is_kept_in_the_policy():
    run = run_front(swap("- gmail.draft", "- TODO"))
    assert run.policy.tools == ("sheets.read", "TODO", "gmail.send")


# --- a repeated entry is kept once, the first time it is written (ruling R26)

REPEATS = {
    "tools": swap("- gmail.draft", "- gmail.draft\n  - gmail.draft"),
    "forbidden": swap("- drive.share", "- drive.share\n  - drive.share"),
    "email_to": edited(
        lambda d: d["scope"].update(email_to=["@aivenstudios.com", "@aivenstudios.com"])
    ),
}


@pytest.mark.parametrize("front", REPEATS.values(), ids=REPEATS)
def test_a_repeated_entry_is_kept_once_and_costs_the_checks_nothing(front):
    run = run_front(front)
    assert replace(run.policy, sha256=EXPECTED.sha256) == EXPECTED
    # The lines move down by one, so the findings are compared by code: not one more for the repeat.
    assert run.codes(wrappers=True) == run_front(FRONT).codes(wrappers=True)


def test_the_first_of_the_repeats_is_the_one_that_stays():
    run = run_front(edited(lambda d: d.update(tools=["gmail.send", "sheets.read"] * 2)))
    assert run.policy.tools == ("gmail.send", "sheets.read")


def test_a_repeat_of_an_entry_that_is_wrong_is_reported_once():
    run = run_front(swap("- gmail.draft", "- gmail.drft\n  - gmail.drft"))
    assert run.codes().count("E-TOOL-UNKNOWN") == 1


def test_build_policy_drops_exactly_the_entries_that_load_reports_as_repeats():
    # They must agree on what a repeat is, or a line would be reported twice or not at all. A
    # placeholder is never a repeat, not even of itself.
    entries = ["a.b", "TODO", "a.b", "TODO", "c.d", "TODO", "c.d"]
    loaded = load(edited(lambda d: d.update(tools=entries)), BASE_PATH)
    repeated = sorted(f.line for f in loaded.findings if f.code == "E-LIST-DUPLICATE")
    assert repeated == [loaded.lines["tools.2"], loaded.lines["tools.6"]]
    policy, _ = build_policy(loaded, BASE, CFG, CATALOG, BASE_PATH)
    assert policy.tools == ("a.b", "TODO", "TODO", "c.d", "TODO")


# --- the findings and the input


def test_the_path_that_is_given_names_the_file_in_every_finding():
    loaded = load(swap("version: 1", "version: 0"), BASE_PATH)
    _, findings = build_policy(loaded, BASE, CFG, CATALOG, BASE_PATH)
    assert len(findings) == 4  # E-RANGE and the three warnings
    assert {f.path for f in findings} == {str(BASE_PATH)}
    _, nameless = build_policy(loaded, BASE, CFG, CATALOG)
    assert {f.path for f in nameless} == {""}


def test_building_does_not_change_what_load_returned():
    loaded = load(FRONT, BASE_PATH)
    before = (deepcopy(loaded.data), dict(loaded.lines), list(loaded.findings))
    build_policy(loaded, BASE, CFG, CATALOG, BASE_PATH)
    assert (loaded.data, loaded.lines, loaded.findings) == before
