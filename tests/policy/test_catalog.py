"""The action catalog: catalog-v1.yaml equals validator-spec section 5, and its schemas are strict."""

import hashlib
import json
import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from aiven.policy import constants
from aiven.policy.catalog import CatalogError, is_pattern, load_catalog, matches
from tests.support import REPO_ROOT
from tests.support.spec_tables import code_spans, line_starting_with, table_after

CATALOG_PATH = REPO_ROOT / "catalog" / "catalog-v1.yaml"
SCHEMAS_DIR = REPO_ROOT / "catalog" / "schemas"

WRAPPER_IDS = {"Drive": "drive", "Email": "email", "Agent Builder": "agentbuilder"}

# Ruling R5: one strict schema per grantable Drive and Email action, nothing else.
SCHEMA_ACTIONS = {
    "drive.list",
    "drive.read",
    "sheets.read",
    "drive.create",
    "drive.update",
    "sheets.write",
    "gmail.read",
    "gmail.draft",
    "gmail.send",
}


def _spec_rows() -> list[list[str]]:
    header, *rows = table_after("5. Action catalog v1")
    assert header == ["Action", "Class", "Wrapper", "Gateway rule", "Undo text (rendered)"]
    return rows


# --- the catalog file against the spec table ---------------------------------------------------


def test_catalog_matches_spec_table():
    rows = _spec_rows()
    catalog = load_catalog(CATALOG_PATH)
    assert len(rows) == 16
    assert list(catalog.actions) == [code_spans(row[0])[0] for row in rows], "ids, in spec order"
    for action_cell, class_cell, wrapper_cell, _rule, undo_cell in rows:
        action_id = code_spans(action_cell)[0]
        action = catalog.actions[action_id]
        assert action.id == action_id
        assert action.cls == re.match(r"R[0-4]", class_cell).group(0), action_id
        assert action.escalates_when_shared == ("R2 if" in class_cell), action_id
        assert action.wrapper == WRAPPER_IDS[wrapper_cell], action_id
        assert action.undo == (None if undo_cell == "(not grantable)" else undo_cell), action_id
    assert catalog.wrapper_status == {
        "drive": "planned",
        "email": "planned",
        "agentbuilder": "planned",
    }


def test_only_r1_actions_can_escalate_and_r3_is_never_grantable():
    catalog = load_catalog(CATALOG_PATH)
    escalating = {a.id for a in catalog.actions.values() if a.escalates_when_shared}
    assert escalating == {"drive.update", "sheets.write"}
    assert all(a.cls == "R1" for a in catalog.actions.values() if a.escalates_when_shared)
    r3 = {a.id for a in catalog.actions.values() if a.cls == "R3"}
    assert r3 == {"drive.move", "drive.share", "drive.delete", "gmail.send_bulk"}
    assert all(catalog.actions[a].undo is None for a in r3)


def test_reserved_namespaces_match_spec_and_constants():
    expected = tuple(code_spans(line_starting_with("These namespaces are reserved")))
    assert len(expected) == 7
    assert load_catalog(CATALOG_PATH).reserved == expected
    assert constants.RESERVED_NAMESPACES == expected


def test_catalog_sha256_is_the_hash_of_the_file_bytes():
    expected = "sha256:" + hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest()
    assert load_catalog(CATALOG_PATH).sha256 == expected


def test_catalog_values_are_frozen_and_hashable():
    catalog = load_catalog(CATALOG_PATH)
    with pytest.raises(FrozenInstanceError):
        catalog.sha256 = "sha256:0"
    with pytest.raises(FrozenInstanceError):
        catalog.actions["drive.list"].cls = "R3"
    hash(catalog)  # usable as a cache key


# --- matches ------------------------------------------------------------------------------------


def test_matches_namespace_pattern():
    assert matches("payments.*", "payments.pay") is True
    assert matches("payments.*", "paymentsx.pay") is False
    assert matches("drive.delete", "drive.delete") is True


@pytest.mark.parametrize(
    ("pattern", "action_id", "expected"),
    [
        ("drive.delete", "drive.delete_all", False),
        ("drive.delete", "drive.delet", False),
        ("drive.delete", "drive.Delete", False),
        ("drive.*", "drive.read", True),
        ("payments.*", "payments.refunds.create", True),
        ("payments.*", "payments", False),
        ("payments.*", "Payments.pay", False),
        ("*", "drive.read", False),
        ("pay*", "payments.pay", False),
        ("payments.*.pay", "payments.x.pay", False),
    ],
)
def test_matches_edge_cases(pattern, action_id, expected):
    assert matches(pattern, action_id) is expected


# --- is_pattern: the shape of a reserved entry, and of an item in a policy's `forbidden` list


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("drive.delete", True),
        ("drive.*", True),
        ("agentbuilder.permissions", True),
        ("a1.b_2", True),
        ("drive", False),
        ("drive.", False),
        (".*", False),
        ("*", False),
        ("drive.*.x", False),
        ("drive.d*", False),
        ("Drive.delete", False),
        ("drive.Delete", False),
        ("1drive.read", False),
        ("drive.1read", False),
        ("drive.delete\n", False),
        ("drive.*\n", False),
        ("drive .delete", False),
        ("", False),
    ],
)
def test_is_pattern_accepts_an_exact_name_or_a_namespace_wildcard_and_nothing_else(entry, expected):
    assert is_pattern(entry) is expected


def test_every_action_and_every_reserved_entry_is_a_pattern():
    catalog = load_catalog(CATALOG_PATH)
    assert all(is_pattern(name) for name in (*catalog.actions, *catalog.reserved))


# --- the loader rejects a malformed catalog ------------------------------------------------------

# The reserved list of a valid catalog holds every namespace of the platform (ruling R94).
RESERVED_LINE = (
    "reserved: [payments.*, policy.*, audit.*, killswitch.*, iam.*, secrets.*, "
    "agentbuilder.permissions]\n"
)

VALID = (
    """\
schema: aiven-catalog/v1
wrappers: {drive: planned, email: planned, agentbuilder: planned}
"""
    + RESERVED_LINE
    + """\
actions:
  drive.read: {class: R0, wrapper: drive, undo: "nothing to undo (read only)."}
  drive.update: {class: R1, wrapper: drive, escalates_when_shared: true, undo: "restore it."}
  drive.share: {class: R3, wrapper: drive}
"""
)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_the_minimal_valid_catalog_loads(tmp_path):
    catalog = load_catalog(_write(tmp_path, VALID))
    assert list(catalog.actions) == ["drive.read", "drive.update", "drive.share"]
    assert catalog.actions["drive.update"].escalates_when_shared is True
    assert catalog.actions["drive.read"].escalates_when_shared is False
    assert catalog.reserved == constants.RESERVED_NAMESPACES


def test_wrapper_status_comes_from_the_wrappers_mapping(tmp_path):
    text = VALID.replace("drive: planned", "drive: built")
    assert load_catalog(_write(tmp_path, text)).wrapper_status == {
        "drive": "built",
        "email": "planned",
        "agentbuilder": "planned",
    }


def test_any_change_to_the_file_changes_the_hash(tmp_path):
    first = load_catalog(_write(tmp_path, VALID)).sha256
    second = load_catalog(_write(tmp_path, VALID + "# a comment\n")).sha256
    assert first != second
    assert first == "sha256:" + hashlib.sha256(VALID.encode()).hexdigest()


def _replace(old: str, new: str) -> str:
    assert old in VALID, old
    return VALID.replace(old, new)


BROKEN = {
    "wrong-schema": (_replace("aiven-catalog/v1", "aiven-catalog/v2"), "schema"),
    "missing-reserved": (_replace(RESERVED_LINE, ""), "reserved"),
    # The extreme cases of a reserved list that lacks the entries of the platform (ruling R94).
    "empty-reserved-list": (_replace(RESERVED_LINE, "reserved: []\n"), "non-empty list"),
    "reserved-that-is-not-a-list": (
        _replace(RESERVED_LINE, "reserved: payments.*\n"),
        "non-empty list",
    ),
    "unknown-top-level-key": (VALID + "extra: 1\n", "unknown key 'extra'"),
    "unknown-wrapper-in-wrappers": (
        _replace("agentbuilder: planned}", "agentbuilder: planned, sharepoint: planned}"),
        "sharepoint",
    ),
    "missing-wrapper": (_replace(", agentbuilder: planned}", "}"), "agentbuilder"),
    "unknown-wrapper-status": (_replace("drive: planned", "drive: live"), "unknown status 'live'"),
    "unknown-class": (_replace("{class: R0,", "{class: R9,"), "unknown class 'R9'"),
    "lowercase-class": (_replace("{class: R0,", "{class: r0,"), "unknown class 'r0'"),
    "unknown-wrapper-in-action": (
        _replace("{class: R3, wrapper: drive}", "{class: R3, wrapper: sharepoint}"),
        "unknown wrapper 'sharepoint'",
    ),
    "unknown-action-key": (
        _replace("{class: R3, wrapper: drive}", "{class: R3, wrapper: drive, rule: x}"),
        "unknown key 'rule'",
    ),
    "missing-class": (
        _replace("{class: R3, wrapper: drive}", "{wrapper: drive}"),
        "missing key 'class'",
    ),
    "escalation-flag-not-a-boolean": (
        _replace("escalates_when_shared: true", 'escalates_when_shared: "yes"'),
        "true or false",
    ),
    "grantable-action-without-undo": (
        _replace(', undo: "nothing to undo (read only)."', ""),
        "needs an undo text",
    ),
    "r3-action-with-undo": (
        _replace("{class: R3, wrapper: drive}", '{class: R3, wrapper: drive, undo: "x"}'),
        "must not have an undo text",
    ),
    "action-inside-a-reserved-namespace": (
        VALID + '  payments.pay: {class: R0, wrapper: drive, undo: "x"}\n',
        "reserved namespace",
    ),
    "duplicate-action": (VALID + "  drive.read: {class: R3, wrapper: drive}\n", "duplicate key"),
    "malformed-reserved-entry": (_replace("payments.*,", "pay*,"), "'pay\\*'"),
    "reserved-entry-listed-twice": (
        _replace("[payments.*,", "[payments.*, payments.*,"),
        "listed twice",
    ),
    "bad-action-id": (_replace("drive.read:", "Drive.Read:"), "'Drive.Read'"),
    "no-actions": (_replace(VALID[VALID.index("actions:") :], "actions: {}\n"), "actions"),
    "action-id-with-trailing-newline": (
        _replace(
            '  drive.read: {class: R0, wrapper: drive, undo: "nothing to undo (read only)."}\n',
            '  ? |\n    drive.read\n  : {class: R0, wrapper: drive, undo: "nothing to undo (read only)."}\n',
        ),
        "not a valid action id",
    ),
    "reserved-entry-with-trailing-newline": (
        _replace(
            RESERVED_LINE,
            "reserved:\n  - |\n    payments.*\n"
            + "".join(f"  - {name}\n" for name in constants.RESERVED_NAMESPACES[1:]),
        ),
        "neither an exact name",
    ),
    "top-level-is-not-a-mapping": ("- a\n- b\n", "must be a mapping"),
    "invalid-yaml": ("actions: [\n", "not valid"),
}


@pytest.mark.parametrize(("text", "problem"), BROKEN.values(), ids=BROKEN.keys())
def test_load_catalog_rejects(tmp_path, text, problem):
    with pytest.raises(CatalogError, match=problem):
        load_catalog(_write(tmp_path, text))


# --- the reserved list is held to the platform's (ruling R94)
#
# The catalog is the biggest single risk (validator-spec section 5): a catalog that has lost an
# entry of the reserved list would let a tool in that namespace be granted. So the loader refuses
# it, and every entry of the platform's list is held in turn: the first of them is `payments.*`,
# and the last one is `agentbuilder.permissions`.


def _reserved_line(*names: str) -> str:
    return f"reserved: [{', '.join(names)}]\n"


@pytest.mark.parametrize("name", constants.RESERVED_NAMESPACES)
def test_a_reserved_list_that_lacks_an_entry_of_the_platform_is_refused(tmp_path, name):
    kept = [other for other in constants.RESERVED_NAMESPACES if other != name]
    text = _replace(RESERVED_LINE, _reserved_line(*kept))
    # (it is the one entry that is missing, so the list of what lacks ends behind it)
    with pytest.raises(CatalogError, match=rf"^catalog\.yaml: reserved: lacks {re.escape(name)} "):
        load_catalog(_write(tmp_path, text))


def test_the_error_names_every_entry_that_is_missing_and_no_other(tmp_path):
    text = _replace(RESERVED_LINE, _reserved_line("policy.*", "audit.*", "killswitch.*", "iam.*"))
    with pytest.raises(CatalogError) as raised:
        load_catalog(_write(tmp_path, text))
    message = str(raised.value)
    assert "lacks payments.*, secrets.*, agentbuilder.permissions" in message
    for present in ("policy.*", "audit.*", "killswitch.*", "iam.*"):
        assert present not in message


def test_a_reserved_list_with_none_of_the_platform_entries_is_refused(tmp_path):
    text = _replace(RESERVED_LINE, _reserved_line("ops.*"))
    with pytest.raises(CatalogError, match="lacks payments"):
        load_catalog(_write(tmp_path, text))


RESERVED_LISTS = {
    "the list of the platform": constants.RESERVED_NAMESPACES,
    "more entries than the platform has": (*constants.RESERVED_NAMESPACES, "ops.*"),
    "the platform entries in another order": constants.RESERVED_NAMESPACES[::-1],
}


@pytest.mark.parametrize("names", RESERVED_LISTS.values(), ids=RESERVED_LISTS)
def test_a_reserved_list_that_has_every_entry_of_the_platform_loads(tmp_path, names):
    text = _replace(RESERVED_LINE, _reserved_line(*names))
    assert load_catalog(_write(tmp_path, text)).reserved == tuple(names)


def test_load_catalog_rejects_bytes_that_are_not_utf8(tmp_path):
    path = tmp_path / "catalog.yaml"
    path.write_bytes(VALID.encode() + b"# \xff\n")
    with pytest.raises(CatalogError, match="UTF-8"):
        load_catalog(path)


def test_catalog_errors_name_the_file(tmp_path):
    with pytest.raises(CatalogError, match=r"^catalog\.yaml: "):
        load_catalog(_write(tmp_path, VALID + "extra: 1\n"))


# --- JSON Schemas --------------------------------------------------------------------------------


def _schemas() -> dict[str, dict]:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(SCHEMAS_DIR.glob("*.json"))
    }


def test_every_write_schema_is_strict():
    schemas = _schemas()
    assert schemas, "no schemas found"
    for action, schema in schemas.items():
        assert schema["additionalProperties"] is False, action
        assert isinstance(schema["required"], list), action


def test_schemas_exist_for_exactly_the_grantable_drive_and_email_actions():
    catalog = load_catalog(CATALOG_PATH)
    grantable = {
        a.id
        for a in catalog.actions.values()
        if a.cls in constants.POLICY_CLASSES and a.wrapper in ("drive", "email")
    }
    assert grantable == SCHEMA_ACTIONS
    assert set(_schemas()) == SCHEMA_ACTIONS


@pytest.mark.parametrize("action", sorted(SCHEMA_ACTIONS))
def test_schema_shape(action):
    schema = _schemas()[action]
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["type"] == "object"
    required = schema["required"]
    assert len(required) == len(set(required)), "required lists a name twice"
    assert set(required) <= set(schema["properties"])
    for name, definition in schema["properties"].items():
        assert "type" in definition, f"{action}.{name} has no type"


# property names and required names, as in drive-wrapper section 3 and email-wrapper section 4
ARGUMENTS = {
    "drive.list": ({"folder_id", "name_contains", "page_token", "page_size"}, set()),
    "drive.read": ({"file_id"}, {"file_id"}),
    "sheets.read": ({"file_id", "range"}, {"file_id", "range"}),
    "drive.create": (
        {"parent_id", "name", "type", "content"},
        {"parent_id", "name", "type", "content"},
    ),
    "drive.update": ({"file_id", "name", "content"}, {"file_id"}),
    "sheets.write": ({"file_id", "range", "values"}, {"file_id", "range", "values"}),
    "gmail.read": ({"message_id", "from", "subject_contains", "newer_than_days"}, set()),
    "gmail.draft": ({"to", "cc", "bcc", "subject", "body", "draft_id"}, {"to", "subject", "body"}),
    "gmail.send": ({"draft_id"}, {"draft_id"}),
}


@pytest.mark.parametrize("action", sorted(ARGUMENTS))
def test_schema_arguments_match_the_wrapper_docs(action):
    properties, required = ARGUMENTS[action]
    schema = _schemas()[action]
    assert set(schema["properties"]) == properties
    assert set(schema["required"]) == required


def test_schema_value_constraints():
    schemas = _schemas()
    assert schemas["drive.list"]["properties"]["page_size"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 100,
    }
    assert schemas["drive.create"]["properties"]["type"]["enum"] == [
        "text",
        "markdown",
        "csv",
        "json",
        "google_doc",
        "google_sheet",
    ]
    assert schemas["gmail.read"]["properties"]["newer_than_days"] == {
        "type": "integer",
        "minimum": 1,
    }
    cell = {"type": ["string", "number", "boolean"]}
    assert schemas["sheets.write"]["properties"]["values"] == {
        "type": "array",
        "items": {"type": "array", "items": cell},
    }
    strings = {"type": "array", "items": {"type": "string"}}
    for name in ("to", "cc", "bcc"):
        assert schemas["gmail.draft"]["properties"][name] == strings
