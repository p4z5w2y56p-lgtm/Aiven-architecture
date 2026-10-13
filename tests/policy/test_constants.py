"""Platform constants: validator-spec section 6 and the ceilings of section 3.3, verbatim."""

import re

import pytest

from aiven.policy import constants
from aiven.policy.catalog import load_catalog
from tests.support import REPO_ROOT
from tests.support.spec_tables import code_spans, line_starting_with, table_after


@pytest.fixture(scope="module")
def spec_constants() -> dict[str, str]:
    header, *rows = table_after("6. Platform constants v1")
    assert header == ["Constant", "v1 value"]
    return {name: value for name, value in rows}


@pytest.fixture(scope="module")
def spec_field_rules() -> dict[str, str]:
    header, *rows = table_after("3.3 Fields")
    assert header == ["Field", "Rule", "Codes"]
    return {code_spans(field)[0]: rule for field, rule, _ in rows}


def _range(rule: str) -> tuple[int, int]:
    """The first number or `low–high` range in a rule cell."""
    found = re.search(r"(\d+)(?:–(\d+))?", rule)
    assert found, rule
    low = int(found.group(1))
    return low, int(found.group(2) or low)


def test_schema_signer_and_namespace(spec_constants):
    assert code_spans(spec_constants["Schema"]) == [constants.SCHEMA]
    assert code_spans(spec_constants["Signer"])[0] == constants.SIGNER
    assert f"({constants.SIGNER_NAME})" in spec_constants["Signer"]
    assert code_spans(spec_constants["Signature namespace"]) == [constants.NAMESPACE]


def test_classes(spec_constants):
    listed = re.match(r"^(R\d(?:, R\d)*)\.", spec_constants["Classes a policy may use"])
    assert listed
    assert constants.POLICY_CLASSES == tuple(listed.group(1).split(", "))


def test_lists_equal_the_spec_without_duplicates(spec_constants):
    baseline = code_spans(spec_constants["Forbidden baseline"])
    ids = code_spans(spec_constants["Reserved agent ids"])
    domains = code_spans(spec_constants["Public mail domains"])
    assert len(ids) == len(set(ids)) and len(domains) == len(set(domains))
    assert constants.FORBIDDEN_BASELINE == tuple(baseline)
    assert constants.RESERVED_AGENT_IDS == frozenset(ids)
    assert constants.PUBLIC_MAIL_DOMAINS == frozenset(domains)


def test_scalars(spec_constants):
    assert code_spans(spec_constants["Drive root"])[0] == constants.DRIVE_ROOT
    assert code_spans(spec_constants["Phase 1 email recipients"]) == [
        "@" + constants.PHASE1_EMAIL_DOMAIN
    ]
    assert code_spans(spec_constants["`untrusted_input` default"]) == [
        constants.UNTRUSTED_INPUT_DEFAULT
    ]
    assert constants.UNTRUSTED_INPUT_DEFAULT in constants.UNTRUSTED_INPUT_MODES
    assert constants.TIMEZONE in spec_constants["Day"]
    bulk = re.search(r"More than (\d+) recipients", spec_constants["Bulk email"])
    assert bulk and int(bulk.group(1)) == constants.BULK_RECIPIENTS
    assert spec_constants["Shadow default"] == f"{constants.SHADOW_DEFAULT} runs"
    assert spec_constants["Retention"] == (
        f"Snapshots: {constants.SNAPSHOT_RETENTION_DAYS} days. "
        f"Audit log: append-only, kept {constants.AUDIT_RETENTION_YEARS} year."
    )


def test_reserved_namespaces_are_the_ones_in_section_5():
    sentence = line_starting_with("These namespaces are reserved")
    assert constants.RESERVED_NAMESPACES == tuple(code_spans(sentence))


def test_ceilings_equal_the_ranges_in_section_3_3(spec_field_rules):
    assert set(constants.CEILINGS) == {
        "version",
        "limits.emails_per_day",
        "limits.records_per_run",
        "limits.spend_eur_per_run",
        "limits.max_runtime_s",
        "limits.runs_per_day",
        "shadow.min_runs",
    }
    for field, expected in constants.CEILINGS.items():
        assert _range(spec_field_rules[field]) == expected, field


def test_list_sizes_equal_the_ranges_in_section_3_3(spec_field_rules):
    assert set(constants.LIST_SIZES) == {"tools", "scope.email_to"}
    for field, expected in constants.LIST_SIZES.items():
        assert _range(spec_field_rules[field]) == expected, field


def test_spend_ceiling_is_exactly_zero():
    assert constants.CEILINGS["limits.spend_eur_per_run"] == (0, 0)


def test_deploy_specific_values_are_not_constants():
    # They live in PlatformConfig (set at deploy), never in code.
    for name in ("AGENTS_PROJECT", "TRUSTED_AUTHORS", "GATEWAY_PRINCIPAL", "SANDBOX_DRIVE_ID"):
        assert not hasattr(constants, name), name


# --- the values that the field, tool, limit and scope rules use (Task 1.4)


def test_agent_id_rule_equals_the_spec(spec_field_rules):
    rule = spec_field_rules["agent"]
    assert code_spans(rule)[0] == f"^{constants.AGENT_ID_PATTERN}$"
    assert _range(rule) == constants.AGENT_ID_LENGTH


def test_drive_folder_id_rule_equals_the_spec(spec_field_rules):
    rule = spec_field_rules["scope.drive_folder_id"]
    assert code_spans(rule)[-1] == f"^{constants.DRIVE_FOLDER_ID_PATTERN}$"


def test_the_tools_that_need_a_scope_field_equal_the_spec(spec_field_rules):
    folder = tuple(code_spans(spec_field_rules["scope.drive_folder_id"])[:2])
    email = tuple(code_spans(spec_field_rules["scope.email_to"])[:2])
    assert constants.SCOPE_TOOLS == {
        "drive_folder_id": folder,
        "drive_folder_path": folder,  # "Required with the folder ID"
        "email_to": email,
    }


def test_the_tools_that_use_a_limit_equal_the_spec():
    header, *rows = table_after("3.5 Limits, scope and untrusted input")
    assert header == ["Code", "Fails when"]
    (conflict,) = [fails for code, fails in rows if code == "E-LIMIT-CONFLICT"]
    assert tuple(code_spans(conflict)[:1]) == constants.EMAIL_LIMIT_TOOLS
    assert "an R1+ tool" in conflict
    assert constants.R1_PLUS == constants.POLICY_CLASSES[1:]


def test_wrapper_names_are_the_ones_in_section_5():
    header, *rows = table_after("5. Action catalog v1")
    assert header[2] == "Wrapper"
    catalog = load_catalog(REPO_ROOT / "catalog" / "catalog-v1.yaml")
    assert set(constants.WRAPPER_NAMES) == set(catalog.wrapper_status)
    for action_cell, _, wrapper_cell, _, _ in rows:
        action = catalog.actions[code_spans(action_cell)[0]]
        assert constants.WRAPPER_NAMES[action.wrapper] == wrapper_cell


# --- the sections of the body (Task 1.5)


def test_the_sections_and_the_minimum_text_equal_section_3_7():
    header, *rows = table_after("3.7 Body")
    assert header == ["Code", "Fails when"]
    fails = dict(rows)
    listed = re.search(r"in this order: (.+?)\. ", fails["E-BODY-SECTIONS"])
    assert listed
    assert constants.SECTIONS == tuple(listed.group(1).split(", "))
    assert constants.FREE_SECTIONS == constants.SECTIONS[:3]
    assert constants.GENERATED_SECTIONS == constants.SECTIONS[3:]
    assert all(name.endswith("(generated)") for name in constants.GENERATED_SECTIONS)
    assert not any(name.endswith("(generated)") for name in constants.FREE_SECTIONS)
    empty = fails["E-BODY-EMPTY"]
    assert [name for name in constants.SECTIONS if name in empty] == list(constants.FREE_SECTIONS)
    assert f"fewer than {constants.MIN_SECTION_CHARS} characters of text" in empty
