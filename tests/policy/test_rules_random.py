"""Random policies through the field, tool, limit and scope rules: what must hold for any of them.

A policy is `DATA` with a few fields changed to values from short pools of good, bad and odd
ones, or left out. The pools hold what the rules tell apart: every tool of the catalog, wildcards,
reserved names, the baseline and its look-alikes, addresses of every kind. The seed is fixed, so
a failure repeats.

For each policy:
- Nothing raises, whole-file validation included.
- Every finding formats in English and Dutch, on one line, and stands on a line of the file.
- No finding is made twice. A defect is reported once.
- There is a `Policy` exactly when every field of the table has a usable value: no field is
  missing, and `max_class` and the folder ID are not of the wrong type (ruling R4).
- A `Policy` holds what the front matter says, with each list entry once (ruling R26).
"""

import random
import re
from copy import deepcopy

from aiven.policy.catalog import load_catalog
from aiven.policy.findings import format_line, message
from aiven.policy.frontmatter import FIELDS, load
from aiven.policy.model import Limits, build_policy
from aiven.policy.validate import validate_file
from tests.support import REPO_ROOT
from tests.support.frontmatter import DATA, emit
from tests.support.policies import AGENTS_PROJECT, BASE_PATH, FOLDER_ID, platform_config, valid_base

CFG = platform_config()
CATALOG = load_catalog(REPO_ROOT / "catalog" / "catalog-v1.yaml")
BASE = valid_base()

COUNT = 400
SEED = 20261013

TOOLS = [
    *CATALOG.actions,
    *CATALOG.actions,
    "drive.*",
    "*",
    "payments.pay",
    "policy.sign",
    "agentbuilder.permissions",
    "drive.reed",
    "Drive.read",
    "payments.*",
    "x",
]
FORBIDDEN = [
    *DATA["forbidden"],
    *DATA["forbidden"],
    "sheets.read",
    "sheets.*",
    "gmail.*",
    "drive.*",
    "paymnets.*",
    "drive",
    "*",
    "Drive.delete",
    "agentbuilder.permissions",
    "agentbuilder.*",
    "gmail.send",
    "drive.move",
    "x.*",
]
EMAILS = [
    "@aivenstudios.com",
    "a@aivenstudios.com",
    "@gmail.com",
    "a@gmail.com",
    "@client.nl",
    "*@x.nl",
    "@Aivenstudios.com",
    "@x",
    "@mail.aivenstudios.com",
    "a b@x.nl",
    "@xn--bcher-kva.nl",
]
PATHS = [
    DATA["scope"]["drive_folder_path"],
    "AIVEN Architecture Sandbox",
    "AIVEN Architecture Sandbox/Invoices",
    "AIVEN Architecture Sandbox / a / b",
    "Other",
    "AIVEN Architecture Sandbox /  x",
]
FOLDER_IDS = [FOLDER_ID, "a" * 10, "a" * 100, "a" * 9, "a" * 101, "abcde fghij"]
AGENTS = ["invoice-reminder", "ab", "admin", "a" * 24, "a" * 25, "Abc", "a--b", "x1y"]
NUMBERS = [0, 1, 5, 10, 11, 29, 30, 50, 51, 200, 201, 900, 901, 9999, 10000]
DROPPABLE = [
    "schema",
    "agent",
    "version",
    "principal",
    "max_class",
    "tools",
    "forbidden",
    "untrusted_input",
    "limits.emails_per_day",
    "limits.max_runtime_s",
    "shadow.min_runs",
    "scope.drive_folder_id",
    "scope.drive_folder_path",
    "scope.email_to",
]


def drop(data: dict, path: str) -> None:
    *parents, name = path.split(".")
    for parent in parents:
        data = data.get(parent, {})
    data.pop(name, None)


# One change of a policy: it takes the generator and the data.
CHANGES = [
    lambda rng, d: d.update(schema=rng.choice(["aiven-policy/v2", "other"])),
    lambda rng, d: d.update(agent=rng.choice(AGENTS)),
    lambda rng, d: d.update(max_class=rng.choice(["R0", "R1", "R2", "R3", "R4", "high"])),
    lambda rng, d: d.update(version=rng.choice(NUMBERS)),
    lambda rng, d: d.update(untrusted_input=rng.choice(["strict", "taint", "off"])),
    lambda rng, d: d.update(tools=rng.choices(TOOLS, k=rng.randint(0, 8))),
    lambda rng, d: d.update(forbidden=rng.choices(FORBIDDEN, k=rng.randint(0, 8))),
    lambda rng, d: d.setdefault("limits", {}).update(
        {rng.choice(list(FIELDS["limits"])): rng.choice(NUMBERS)}
    ),
    lambda rng, d: d.setdefault("scope", {}).update(drive_folder_id=rng.choice(FOLDER_IDS)),
    lambda rng, d: d.setdefault("scope", {}).update(drive_folder_path=rng.choice(PATHS)),
    lambda rng, d: d.setdefault("scope", {}).update(
        email_to=rng.choices(EMAILS, k=rng.randint(0, 5))
    ),
    lambda rng, d: d.setdefault("shadow", {}).update(min_runs=rng.choice(NUMBERS)),
    lambda rng, d: d.pop("scope", None),
    lambda rng, d: drop(d, rng.choice(DROPPABLE)),
]


def random_policy(rng: random.Random) -> dict:
    data = deepcopy(DATA)
    for _ in range(rng.randint(0, 5)):
        rng.choice(CHANGES)(rng, data)
        if rng.random() < 0.3:  # the principal of the agent, most of the time
            agent = data.get("agent", "")
            data["principal"] = f"agent-{agent}@{AGENTS_PROJECT}.iam.gserviceaccount.com"
    return data


def complete_and_typed(data: dict) -> bool:
    """Whether a policy must come out of this data, by the rule of ruling R4."""
    needed = [name for name in FIELDS if name not in ("limits", "shadow", "scope")]
    if any(name not in data for name in needed):
        return False
    if any(name not in data.get("limits", {}) for name in FIELDS["limits"]):
        return False
    if "min_runs" not in data.get("shadow", {}):
        return False
    folder_id = data.get("scope", {}).get("drive_folder_id", FOLDER_ID)
    return data["max_class"] in ("R0", "R1", "R2", "R3", "R4") and bool(
        re.fullmatch(r"[A-Za-z0-9_-]{10,100}", folder_id)
    )


def once(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


POLICIES = [random_policy(random.Random(SEED + number)) for number in range(COUNT)]


def test_a_random_policy_is_judged_without_error_and_every_finding_can_be_printed():
    for number, data in enumerate(POLICIES):
        front = "\n".join(emit(data)) + "\n"
        file = f"---\n{front}---\n".encode()
        lines = len(file.split(b"\n"))
        for finding in validate_file(BASE_PATH, file, CFG, CATALOG):
            assert finding.line is None or 1 <= finding.line <= lines, number
            assert "\n" not in format_line(finding), number
            assert message(finding, "nl"), number

        loaded = load(front, BASE_PATH)
        policy, findings = build_policy(loaded, BASE, CFG, CATALOG, BASE_PATH)
        shown = [(f.code, f.line, tuple(sorted(f.params.items()))) for f in findings]
        assert len(shown) == len(set(shown)), f"policy {number}: a defect was reported twice"
        for finding in findings:
            assert 1 <= finding.line <= lines, number
            assert message(finding, "en"), number

        assert (policy is not None) == complete_and_typed(loaded.data), number
        if policy is not None:
            scope = loaded.data.get("scope", {})
            assert policy.tools == once(loaded.data["tools"]), number
            assert policy.forbidden == once(loaded.data["forbidden"]), number
            assert policy.scope.email_to == once(scope.get("email_to", [])), number
            assert policy.scope.drive_folder_id == scope.get("drive_folder_id"), number
            assert policy.limits == Limits(**loaded.data["limits"]), number


def test_the_random_policies_reach_every_kind_of_finding():
    # The pools must reach all of them, or the test above checks very little.
    codes: set[str] = set()
    for data in POLICIES:
        _, findings = build_policy(load("\n".join(emit(data)) + "\n"), BASE, CFG, CATALOG)
        codes |= {f.code for f in findings}
    assert {
        "E-AGENT-ID",
        "E-FIELD-TYPE",
        "E-FORBIDDEN-BASELINE",
        "E-FORBIDDEN-PATTERN",
        "E-FORBIDDEN-UNKNOWN",
        "E-LIMIT-CONFLICT",
        "E-LIMIT-SPEND",
        "E-MAX-CLASS-R3",
        "E-MAX-CLASS-R4",
        "E-PRINCIPAL",
        "E-RANGE",
        "E-SCHEMA",
        "E-SCOPE-EMAIL",
        "E-SCOPE-EMAIL-EXTERNAL",
        "E-SCOPE-EMAIL-PUBLIC",
        "E-SCOPE-MISSING",
        "E-SCOPE-SANDBOX",
        "E-TOOL-ABOVE-MAX-CLASS",
        "E-TOOL-FORBIDDEN",
        "E-TOOL-R3",
        "E-TOOL-R4",
        "E-TOOL-UNKNOWN",
        "E-TOOL-WILDCARD",
        "E-UNTRUSTED-INPUT",
        "W-LIMIT-UNUSED",
        "W-MAX-CLASS-SLACK",
        "W-SCOPE-UNUSED",
        "W-SHADOW-LOW",
        "W-TOOL-NOT-LIVE",
        "W-UNTRUSTED-TAINT",
    } <= codes
