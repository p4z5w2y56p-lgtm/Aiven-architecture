"""The field rules (validator-spec 3.3): schema, agent, principal, max_class, untrusted_input and
shadow.min_runs, and E-RANGE for every number that has a ceiling.

Each case runs `build_policy` on a small front matter (tests/support/rules.py). A case says what
the rules report, and on which line. The findings of `load` (types, missing fields) are not in it.
"""

from dataclasses import replace

import pytest

from aiven.policy import constants
from aiven.policy.fields import Fields, range_finding, size_finding
from aiven.policy.frontmatter import load
from tests.support.frontmatter import front_without, swap
from tests.support.policies import AGENTS_PROJECT, BASE_PATH
from tests.support.rules import CFG, check, run_front, setting

NOT_ASCII = "caf\N{LATIN SMALL LETTER E WITH ACUTE}"


def with_agent(agent: str):
    """A change that renames the agent and keeps the principal that goes with it."""

    def change(data):
        data["agent"] = agent
        data["principal"] = f"agent-{agent}@{AGENTS_PROJECT}.iam.gserviceaccount.com"

    return change


# --- schema

SCHEMAS = {
    "another version": ("aiven-policy/v2", "aiven-policy/v2"),
    "upper case": ("aiven-policy/V1", "aiven-policy/V1"),
    "no version": ("aiven-policy", "aiven-policy"),
    "something behind it": ("aiven-policy/v1/x", "aiven-policy/v1/x"),
    "a space behind it": ('"aiven-policy/v1 "', "aiven-policy/v1 "),
    "another name": ("other", "other"),
}


@pytest.mark.parametrize(("written", "found"), SCHEMAS.values(), ids=SCHEMAS)
def test_the_schema_must_be_exactly_aiven_policy_v1(written, found):
    run = run_front(swap("schema: aiven-policy/v1", f"schema: {written}"))
    assert run.places() == [("E-SCHEMA", run.line("schema:"))]
    assert run.params("E-SCHEMA") == {"found": found}


# --- agent (and ruling R28: a bad agent is one defect, not three)

GOOD_AGENTS = {
    "three characters": "abc",
    "twenty-four characters": "a" * 24,
    "digits": "a1b",
    "a hyphen": "a-b",
    "hyphens and digits": "a1-b2-c3",
    "like the template": "invoice-reminder",
    "starts like a reserved id": "admin2",
    "has a reserved id in it": "template-x",
}


@pytest.mark.parametrize("agent", GOOD_AGENTS.values(), ids=GOOD_AGENTS)
def test_an_agent_id_of_3_to_24_lowercase_letters_digits_and_single_hyphens_is_fine(agent):
    assert check(with_agent(agent)).places() == []


BAD_AGENTS = {
    "two characters": "ab",
    "one character": "a",
    "twenty-five characters": "a" * 25,
    "far too long": "a" * 60,
    "starts with a hyphen": "-abc",
    "ends with a hyphen": "abc-",
    "two hyphens in a row": "ab--c",
    "starts with a digit": "1abc",
    "capital first": "Abc",
    "capital inside": "aBc",
    "all capitals": "ABC",
    "underscore": "a_c",
    "dot": "a.c",
    "star": "a*b",
    "not ASCII": NOT_ASCII,
    **{f"reserved: {name}": name for name in sorted(constants.RESERVED_AGENT_IDS)},
}


@pytest.mark.parametrize("agent", BAD_AGENTS.values(), ids=BAD_AGENTS)
def test_a_bad_agent_id_is_e_agent_id_and_nothing_else(agent):
    # The principal is still the one of invoice-reminder, so without ruling R28 it would be wrong
    # too. One defect, one code.
    run = check(setting("agent", agent))
    assert run.places() == [("E-AGENT-ID", run.line("agent:"))]
    assert run.params("E-AGENT-ID") == {"value": agent}


@pytest.mark.parametrize("written", ['""', '"a b"', '"abc "', "|\n  invoice-reminder"])
def test_an_agent_id_is_matched_as_a_whole(written):
    # The last one is "invoice-reminder\n": `$` would let it through, fullmatch does not.
    run = run_front(swap("agent: invoice-reminder", f"agent: {written}"))
    assert [code for code, _ in run.places()] == ["E-AGENT-ID"]


# --- version, and every other number with a ceiling

RANGED = {
    path: bounds
    for path, bounds in constants.CEILINGS.items()
    if path != "limits.spend_eur_per_run"  # the spend has a code of its own
}


def key_of(path: str) -> str:
    return path.rsplit(".", 1)[-1] + ":"


def test_the_numbers_with_a_ceiling_are_the_ones_of_section_3_3():
    assert set(RANGED) == {
        "version",
        "limits.emails_per_day",
        "limits.records_per_run",
        "limits.max_runtime_s",
        "limits.runs_per_day",
        "shadow.min_runs",
    }


@pytest.mark.parametrize("path", RANGED)
def test_a_number_one_above_its_ceiling_is_e_range(path):
    low, high = RANGED[path]
    run = check(setting(path, high + 1))
    assert run.places() == [("E-RANGE", run.line(key_of(path)))]
    assert run.params("E-RANGE") == {
        "field": path,
        "value": str(high + 1),
        "min": str(low),
        "max": str(high),
    }


@pytest.mark.parametrize("path", [path for path, (low, _) in RANGED.items() if low > 0])
def test_a_number_one_below_its_floor_is_e_range(path):
    low, _ = RANGED[path]
    run = check(setting(path, low - 1))
    assert run.places() == [("E-RANGE", run.line(key_of(path)))]
    assert run.params("E-RANGE")["value"] == str(low - 1)


@pytest.mark.parametrize(
    ("path", "value"), [(path, bound) for path, bounds in RANGED.items() for bound in bounds]
)
def test_a_number_on_its_floor_or_its_ceiling_is_not_e_range(path, value):
    assert "E-RANGE" not in check(setting(path, value)).codes()


def test_a_number_that_is_far_too_large_is_one_e_range():
    # The longest integer that load keeps has 4300 digits. The finding shows it cut to 200, or
    # hides it: a long run of digits can look like a card number.
    run = check(setting("limits.runs_per_day", 10**4299))
    assert run.places() == [("E-RANGE", run.line("runs_per_day:"))]
    assert run.params("E-RANGE")["min"] == "1" and run.params("E-RANGE")["max"] == "10"


def test_a_number_or_a_list_that_has_no_value_has_no_range_finding():
    # It is missing or a wrong type, and `load` has said so: there is nothing to measure.
    fields = Fields(load(front_without("version", "tools"), BASE_PATH))
    assert range_finding(fields, "version") is None
    assert size_finding(fields, "tools") is None


# --- principal

PRINCIPALS = {
    "another project": "agent-invoice-reminder@other-project.iam.gserviceaccount.com",
    "the example project": "agent-invoice-reminder@aiven-agents-example.iam.gserviceaccount.com",
    "another agent": f"agent-other@{AGENTS_PROJECT}.iam.gserviceaccount.com",
    "no agent- in front": f"invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.com",
    "upper case": f"Agent-invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.com",
    "another domain": f"agent-invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.org",
    "something behind it": f"agent-invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.com.nl",
    "something in front": f"x-agent-invoice-reminder@{AGENTS_PROJECT}.iam.gserviceaccount.com",
    "a subdomain": f"agent-invoice-reminder@x.{AGENTS_PROJECT}.iam.gserviceaccount.com",
    "no iam": f"agent-invoice-reminder@{AGENTS_PROJECT}.gserviceaccount.com",
    "a person": "matthijs@aivenstudios.com",
}


@pytest.mark.parametrize("principal", PRINCIPALS.values(), ids=PRINCIPALS)
def test_the_principal_must_be_exactly_the_service_account_of_this_agent(principal):
    run = check(setting("principal", principal))
    assert run.places() == [("E-PRINCIPAL", run.line("principal:"))]
    assert run.params("E-PRINCIPAL") == {
        "agent": "invoice-reminder",
        "project": AGENTS_PROJECT,
        "value": principal,
    }


def test_the_principal_must_name_the_agent_of_the_same_file():
    run = check(setting("agent", "other-agent"))
    assert run.places() == [("E-PRINCIPAL", run.line("principal:"))]
    assert run.params("E-PRINCIPAL")["agent"] == "other-agent"


def test_the_principal_is_compared_with_the_agents_project_of_the_platform_config():
    elsewhere = replace(CFG, agents_project="aiven-agents-example")
    run = check(cfg=elsewhere)
    assert run.places() == [("E-PRINCIPAL", run.line("principal:"))]
    assert run.params("E-PRINCIPAL")["project"] == "aiven-agents-example"
    other = setting("principal", PRINCIPALS["the example project"])
    assert check(other, cfg=elsewhere).places() == []


SKIPPED_PRINCIPAL = {
    "a placeholder in the principal": setting(
        "principal", "agent-invoice-reminder@TBD.iam.gserviceaccount.com"
    ),
    "a placeholder as the principal": setting("principal", "REPLACE_ME_PRINCIPAL"),
    "a placeholder agent": lambda d: d.update(agent="TODO"),
    "a bad agent": lambda d: d.update(agent="ab"),
}


@pytest.mark.parametrize("change", SKIPPED_PRINCIPAL.values(), ids=SKIPPED_PRINCIPAL)
def test_the_principal_is_not_compared_when_it_or_the_agent_cannot_be(change):
    # With a placeholder agent or a bad one the principal of invoice-reminder is wrong as well.
    assert "E-PRINCIPAL" not in check(change).codes()


# --- max_class


@pytest.mark.parametrize(("value", "code"), [("R3", "E-MAX-CLASS-R3"), ("R4", "E-MAX-CLASS-R4")])
def test_max_class_r3_and_r4_have_their_own_codes(value, code):
    run = check(setting("max_class", value))
    assert run.places() == [(code, run.line("max_class:"))]
    assert run.params(code) == {}


MAX_CLASSES = {
    "a word": ("high", "high"),
    "lower case": ("r2", "r2"),
    "a class that does not exist": ("R5", "R5"),
    "no number": ("R", "R"),
    "a space behind it": ('"R2 "', "R2 "),
    "empty": ('""', '""'),
    "two classes": ("R1 R2", "R1 R2"),
}


@pytest.mark.parametrize(("written", "found"), MAX_CLASSES.values(), ids=MAX_CLASSES)
def test_any_other_max_class_is_a_type_error_that_lists_the_classes(written, found):
    run = run_front(swap("max_class: R2", f"max_class: {written}"))
    assert run.places() == [("E-FIELD-TYPE", run.line("max_class:"))]
    assert run.params("E-FIELD-TYPE") == {
        "field": "max_class",
        "expected": "R0 | R1 | R2",
        "found": found,
    }


@pytest.mark.parametrize("value", constants.POLICY_CLASSES)
def test_r0_r1_and_r2_are_the_classes_a_policy_may_use(value):
    assert "E-FIELD-TYPE" not in check(setting("max_class", value)).codes()


# --- untrusted_input


def test_strict_is_the_default_and_has_no_finding():
    assert check(setting("untrusted_input", "strict")).places() == []


def test_taint_is_allowed_with_a_warning():
    run = check(setting("untrusted_input", "taint"))
    assert run.places() == [("W-UNTRUSTED-TAINT", run.line("untrusted_input:"))]
    assert run.params("W-UNTRUSTED-TAINT") == {}


UNTRUSTED = {
    "off": "off",
    "none": "none",
    "loose": "loose",
    "capital S": "Strict",
    "all capitals": "TAINT",
    "a space behind it": '"taint "',
    "empty": '""',
}


@pytest.mark.parametrize("written", UNTRUSTED.values(), ids=UNTRUSTED)
def test_any_other_untrusted_input_is_e_untrusted_input_and_no_warning(written):
    run = run_front(swap("untrusted_input: strict", f"untrusted_input: {written}"))
    assert run.places() == [("E-UNTRUSTED-INPUT", run.line("untrusted_input:"))]
    assert run.params("E-UNTRUSTED-INPUT") == {}


# --- shadow.min_runs


@pytest.mark.parametrize("runs", range(1, constants.SHADOW_DEFAULT))
def test_fewer_than_ten_shadow_runs_is_a_warning(runs):
    run = check(setting("shadow.min_runs", runs))
    assert run.places() == [("W-SHADOW-LOW", run.line("min_runs:"))]
    assert run.params("W-SHADOW-LOW") == {"value": str(runs)}


@pytest.mark.parametrize("runs", [10, 11, 50, 100])
def test_ten_or_more_shadow_runs_is_fine(runs):
    assert check(setting("shadow.min_runs", runs)).places() == []


@pytest.mark.parametrize("runs", [0, 101])
def test_a_value_out_of_range_has_no_warning_besides_e_range(runs):
    # Ruling R45: min_runs 0 is E-RANGE only, not W-SHADOW-LOW as well.
    run = check(setting("shadow.min_runs", runs))
    assert run.places() == [("E-RANGE", run.line("min_runs:"))]


# --- a placeholder skips the other checks of its field (validator-spec 3.1, ruling R7)

# For each field of text: a value that fails its check, and the code it earns.
WRONG_VALUES = {
    "schema": ("other", "E-SCHEMA"),
    "agent": ("ab", "E-AGENT-ID"),
    "principal": ("agent-x@y.iam.gserviceaccount.com", "E-PRINCIPAL"),
    "max_class": ("R3", "E-MAX-CLASS-R3"),
    "untrusted_input": ("off", "E-UNTRUSTED-INPUT"),
}


@pytest.mark.parametrize("path", WRONG_VALUES)
@pytest.mark.parametrize("placeholder", ["TODO", "TBD", "FIXME", "REPLACE_ME_X"])
def test_a_field_that_holds_a_placeholder_is_not_checked(path, placeholder):
    assert check(setting(path, placeholder)).places() == []


@pytest.mark.parametrize(("path", "wrong", "code"), [(p, *w) for p, w in WRONG_VALUES.items()])
def test_the_same_field_with_a_wrong_value_is_checked(path, wrong, code):
    # The control for the test above: the placeholder is what makes the field pass.
    run = check(setting(path, wrong))
    assert code in run.codes()
