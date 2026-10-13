"""The deploy checks (gateway-design section 11, drill BD-3; plan Task 2.5; ruling R112).

Every test runs on a stand-in for Google's REST APIs that answers from a table of URLs: nothing here
reaches Google, and a call to a URL that is not in the table fails the test. The table of
`planned()` is a deployment as Terraform makes it.
"""

import copy
import subprocess
import sys
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

from aiven import deploy_check
from aiven.deploy_check import Deployment, GoogleApiError, RestGoogle, main
from tests.support import REPO_ROOT

AGENTS, GATEWAY, CONTROL = "aiven-agents-test", "aiven-gateway-test", "aiven-control-test"
OWNER = "owner@aivenstudios.com"
DRIVE_ID = "0AbCdEfGhIjKlMnOpQ"
SA = "iam.gserviceaccount.com"
AGENT = f"agent-invoice-reminder@{AGENTS}.{SA}"
GATEWAY_SA = f"gateway@{GATEWAY}.{SA}"

DEPLOYMENT = Deployment(
    agents_project=AGENTS,
    gateway_project=GATEWAY,
    control_project=CONTROL,
    region="europe-west4",
    agents=("invoice-reminder",),
    billing_account="01ABCD-23EF45-6789AB",
    currency="EUR",
    alert_amount=Decimal(10),
    stop_amount=Decimal(25),
    gateway_account=GATEWAY_SA,
    organizers=(OWNER,),
    sandbox_drive_id=DRIVE_ID,
)

IAM = "https://iam.googleapis.com/v1"
CRM = "https://cloudresourcemanager.googleapis.com/v1"
STORAGE = "https://storage.googleapis.com/storage/v1"
LOGGING = "https://logging.googleapis.com/v2"
FIRESTORE = "https://firestore.googleapis.com/v1"
AUDIT_FILTER = f'logName="projects/{CONTROL}/logs/aiven-audit"'
BUDGETS = "https://billingbudgets.googleapis.com/v1/billingAccounts/01ABCD-23EF45-6789AB/budgets"
DRIVE = "https://www.googleapis.com/drive/v3"
PERMISSIONS = (
    f"{DRIVE}/files/{DRIVE_ID}/permissions?supportsAllDrives=true"
    "&fields=nextPageToken,permissions(type,role,emailAddress,domain)"
)
SERVICES = f"https://serviceusage.googleapis.com/v1/projects/{AGENTS}/services?filter=state:ENABLED&pageSize=200"
GATEWAY_SERVICE = f"https://run.googleapis.com/v2/projects/{GATEWAY}/locations/europe-west4/services/gateway:getIamPolicy"


def accounts(project: str, *names: str) -> dict:
    return {"accounts": [{"email": f"{name}@{project}.{SA}"} for name in names]}


def budget(name: str, units: str, thresholds: list, topic: str | None = None) -> dict:
    found = {
        "displayName": name,
        "budgetFilter": {
            "projects": ["projects/111", "projects/222", "projects/333"],
            "creditTypesTreatment": "EXCLUDE_ALL_CREDITS",
            "calendarPeriod": "MONTH",
        },
        "amount": {"specifiedAmount": {"currencyCode": "EUR", "units": units}},
        "thresholdRules": [
            {"thresholdPercent": t, "spendBasis": "CURRENT_SPEND"} for t in thresholds
        ],
    }
    if topic:
        found["notificationsRule"] = {"pubsubTopic": topic, "schemaVersion": "1.0"}
    return found


def planned() -> dict:
    """The answers for a deployment as Terraform makes it, by URL."""
    table: dict = {}
    for project, names in (
        (AGENTS, ["agent-invoice-reminder"]),
        (GATEWAY, ["gateway"]),
        (CONTROL, ["control-ui", "budget-stop", "credit-reminder", "function-builder"]),
    ):
        table[f"{IAM}/projects/{project}/serviceAccounts?pageSize=100"] = accounts(project, *names)
        for name in names:
            key_url = f"{IAM}/projects/{project}/serviceAccounts/{name}@{project}.{SA}/keys"
            table[f"{key_url}?keyTypes=USER_MANAGED"] = {}
    table[SERVICES] = {
        "services": [
            {"name": f"projects/111/services/{api}", "config": {"name": api}}
            for api in ["aiplatform.googleapis.com", "iam.googleapis.com", "run.googleapis.com"]
        ]
    }
    owner = {"role": "roles/owner", "members": [f"user:{OWNER}"]}
    stopper = {
        "role": "roles/billing.projectManager",
        "members": [f"serviceAccount:budget-stop@{CONTROL}.{SA}"],
    }
    table[f"{CRM}/projects/{AGENTS}:getIamPolicy"] = {
        "bindings": [
            owner,
            stopper,
            {"role": "roles/aiplatform.user", "members": [f"serviceAccount:{AGENT}"]},
        ]
    }
    table[f"{CRM}/projects/{GATEWAY}:getIamPolicy"] = {"bindings": [owner, stopper]}
    table[f"{CRM}/projects/{CONTROL}:getIamPolicy"] = {
        "bindings": [
            owner,
            {"role": "roles/logging.logWriter", "members": [f"serviceAccount:{GATEWAY_SA}"]},
        ]
    }
    table[GATEWAY_SERVICE] = None  # the gateway service comes with M3
    iam_config = {
        "uniformBucketLevelAccess": {"enabled": True},
        "publicAccessPrevention": "enforced",
    }
    table[f"{STORAGE}/b/{CONTROL}-policies"] = {
        "location": "EUROPE-WEST4",
        "versioning": {"enabled": True},
        "iamConfiguration": iam_config,
    }
    table[f"{STORAGE}/b/{CONTROL}-snapshots"] = {
        "location": "EUROPE-WEST4",
        "iamConfiguration": iam_config,
        "retentionPolicy": {"retentionPeriod": "2592000"},
        "lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 30}}]},
    }
    table[f"{LOGGING}/projects/{CONTROL}/locations/europe-west4/buckets/aiven-audit"] = {
        "retentionDays": 365
    }
    table[f"{LOGGING}/projects/{CONTROL}/sinks/aiven-audit"] = {
        "destination": f"logging.googleapis.com/projects/{CONTROL}/locations/europe-west4/buckets/aiven-audit",
        "filter": AUDIT_FILTER,
    }
    table[f"{LOGGING}/projects/{CONTROL}/exclusions"] = {
        "exclusions": [{"name": "aiven-audit-only-in-its-bucket", "filter": AUDIT_FILTER}]
    }
    database = {
        "locationId": "europe-west4",
        "type": "FIRESTORE_NATIVE",
        "deleteProtectionState": "DELETE_PROTECTION_ENABLED",
    }
    table[f"{FIRESTORE}/projects/{CONTROL}/databases/control"] = dict(database)
    table[f"{FIRESTORE}/projects/{GATEWAY}/databases/gateway"] = dict(database)
    for group in ("runs", "calls"):
        url = f"{FIRESTORE}/projects/{GATEWAY}/databases/gateway/collectionGroups/{group}/fields/expire_at"
        table[url] = {"ttlConfig": {"state": "ACTIVE"}}
    table[BUDGETS] = {
        "budgets": [
            budget("aiven-alert", "10", [0.5, 0.9, 1]),
            budget("aiven-stop", "25", [1], f"projects/{CONTROL}/topics/budget-stop"),
        ]
    }
    for project, number in ((AGENTS, "111"), (GATEWAY, "222"), (CONTROL, "333")):
        table[f"{CRM}/projects/{project}"] = {"projectId": project, "projectNumber": number}
    table[f"{DRIVE}/drives/{DRIVE_ID}?fields=id,name,restrictions"] = {
        "id": DRIVE_ID,
        "restrictions": {"driveMembersOnly": True},
    }
    table[PERMISSIONS] = {
        "permissions": [
            {"type": "user", "role": "organizer", "emailAddress": OWNER},
            {"type": "user", "role": "writer", "emailAddress": GATEWAY_SA},
        ]
    }
    return table


class FakeGoogle:
    """Answers from a table of URLs; an answer that is an exception is raised."""

    def __init__(self, table: dict) -> None:
        self.table = table
        self.calls: list[tuple[str, str, str]] = []

    def _answer(self, url: str):
        assert url in self.table, f"a call nobody expected: {url}"
        answer = self.table[url]
        if isinstance(answer, Exception):
            raise answer
        return copy.deepcopy(answer)

    def get(self, url: str, quota_project: str):
        self.calls.append(("GET", url, quota_project))
        return self._answer(url)

    def post(self, url: str, body: dict, quota_project: str):
        self.calls.append(("POST", url, quota_project))
        return self._answer(url)


# Files that exist; what they hold is not read, because Deployment.load is replaced.
FILES = [
    "--tfvars",
    str(REPO_ROOT / "infra" / "terraform" / "terraform.tfvars.example"),
    "--config",
    str(REPO_ROOT / "config" / "platform.example.yaml"),
]


def run(capsys, monkeypatch, table: dict, *groups: str, deployment=DEPLOYMENT):
    """Run the command on `groups` against `table`: the exit code, the lines, and the fake."""
    google = FakeGoogle(table)
    monkeypatch.setattr(deploy_check, "_google", lambda: google)
    monkeypatch.setattr(deploy_check.Deployment, "load", classmethod(lambda cls, *a: deployment))
    status = main([*groups, *FILES])
    return status, capsys.readouterr().out.splitlines(), google


def lines_of(lines: list[str], status: str) -> list[str]:
    return [line for line in lines if line.startswith(status + " ")]


# --- a deployment as planned


def test_a_deployment_as_planned_passes_every_check(capsys, monkeypatch):
    status, lines, google = run(capsys, monkeypatch, planned(), "all")
    assert status == 0, lines
    assert lines_of(lines, "FAIL") == []
    assert lines_of(lines, "NOTE") == [
        "NOTE iam gateway service: it does not exist yet (M3); then agents may only invoke it",
        "NOTE stores aiven-audit lock: not locked; the lock waits for Matthijs's confirmation (ruling R105)",
    ]
    assert len(lines_of(lines, "PASS")) == 18
    assert all(line.split(" ", 1)[0] in ("PASS", "NOTE") for line in lines)


def test_it_only_reads(capsys, monkeypatch):
    _, _, google = run(capsys, monkeypatch, planned(), "all")
    for method, url, _ in google.calls:
        assert method == "GET" or url.endswith(":getIamPolicy"), url


def test_calls_are_billed_to_control_and_drive_calls_to_gateway(capsys, monkeypatch):
    _, _, google = run(capsys, monkeypatch, planned(), "all")
    for _, url, quota in google.calls:
        assert quota == (GATEWAY if url.startswith(DRIVE) else CONTROL), url


@pytest.mark.parametrize("group", ["keys", "apis", "iam", "stores", "budgets", "drive"])
def test_a_group_makes_only_its_own_calls(capsys, monkeypatch, group):
    status, lines, _ = run(capsys, monkeypatch, planned(), group)
    assert status == 0
    assert all(line.split(" ", 2)[1] == group for line in lines), lines


def test_the_groups_are_those_of_the_plan():
    assert list(deploy_check.GROUPS) == ["keys", "apis", "iam", "stores", "budgets", "drive"]


# --- what fails


def failing(capsys, monkeypatch, table: dict, group: str, **kwargs) -> list[str]:
    status, lines, _ = run(capsys, monkeypatch, table, group, **kwargs)
    assert status == 1, lines
    return lines_of(lines, "FAIL")


def test_a_user_managed_key_fails(capsys, monkeypatch):
    table = planned()
    table[f"{IAM}/projects/{GATEWAY}/serviceAccounts/{GATEWAY_SA}/keys?keyTypes=USER_MANAGED"] = {
        "keys": [{"name": "k1", "keyType": "USER_MANAGED"}]
    }
    assert failing(capsys, monkeypatch, table, "keys") == [
        f"FAIL keys {GATEWAY}: user-managed keys on {GATEWAY_SA}"
    ]


def test_service_accounts_are_read_page_by_page(capsys, monkeypatch):
    table = planned()
    first = f"{IAM}/projects/{CONTROL}/serviceAccounts?pageSize=100"
    table[first] = {**accounts(CONTROL, "control-ui"), "nextPageToken": "T2"}
    table[first + "&pageToken=T2"] = accounts(CONTROL, "budget-stop")
    status, lines, google = run(capsys, monkeypatch, table, "keys")
    assert status == 0
    assert any(url == first + "&pageToken=T2" for _, url, _ in google.calls)
    assert f"PASS keys {CONTROL}: no user-managed key on its 2 service accounts" in lines


@pytest.mark.parametrize(
    "api", ["drive.googleapis.com", "sheets.googleapis.com", "gmail.googleapis.com"]
)
def test_a_workspace_api_in_agents_fails(capsys, monkeypatch, api):
    table = planned()
    table[SERVICES]["services"].append(
        {"name": f"projects/111/services/{api}", "config": {"name": api}}
    )
    assert failing(capsys, monkeypatch, table, "apis") == [
        f"FAIL apis agents: {api} is enabled in {AGENTS}; Drive, Sheets and Gmail must be off"
    ]


def test_an_agent_without_vertex_fails(capsys, monkeypatch):
    table = planned()
    table[f"{CRM}/projects/{AGENTS}:getIamPolicy"]["bindings"].pop()
    assert failing(capsys, monkeypatch, table, "iam") == [
        "FAIL iam agents vertex: no roles/aiplatform.user for invoice-reminder"
    ]


@pytest.mark.parametrize(
    ("project", "role"),
    [(CONTROL, "roles/datastore.viewer"), (GATEWAY, "roles/run.invoker"), (AGENTS, "roles/editor")],
)
def test_an_agent_with_another_role_fails(capsys, monkeypatch, project, role):
    table = planned()
    table[f"{CRM}/projects/{project}:getIamPolicy"]["bindings"].append(
        {"role": role, "members": [f"serviceAccount:{AGENT}"]}
    )
    assert failing(capsys, monkeypatch, table, "iam") == [
        f"FAIL iam agents other roles: agent-invoice-reminder holds {role} on {project}"
    ]


def test_an_agent_account_that_terraform_does_not_know_is_still_an_agent(capsys, monkeypatch):
    table = planned()
    stray = f"serviceAccount:agent-old-one@{AGENTS}.{SA}"
    table[f"{CRM}/projects/{CONTROL}:getIamPolicy"]["bindings"].append(
        {"role": "roles/logging.viewer", "members": [stray]}
    )
    assert failing(capsys, monkeypatch, table, "iam") == [
        f"FAIL iam agents other roles: agent-old-one holds roles/logging.viewer on {CONTROL}"
    ]


def test_the_gateway_service_once_it_exists(capsys, monkeypatch):
    table = planned()
    table[GATEWAY_SERVICE] = {
        "bindings": [{"role": "roles/run.invoker", "members": [f"serviceAccount:{AGENT}"]}]
    }
    status, lines, _ = run(capsys, monkeypatch, table, "iam")
    assert status == 0
    assert "PASS iam gateway service: agents may only invoke it" in lines
    table[GATEWAY_SERVICE]["bindings"].append(
        {"role": "roles/run.developer", "members": [f"serviceAccount:{AGENT}"]}
    )
    assert failing(capsys, monkeypatch, table, "iam") == [
        "FAIL iam gateway service: agent-invoice-reminder holds roles/run.developer on the gateway service"
    ]


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (
            lambda t: t[f"{STORAGE}/b/{CONTROL}-policies"].update(versioning={"enabled": False}),
            f"FAIL stores {CONTROL}-policies: not versioned",
        ),
        (
            lambda t: t[f"{STORAGE}/b/{CONTROL}-policies"]["iamConfiguration"].update(
                publicAccessPrevention="inherited"
            ),
            f"FAIL stores {CONTROL}-policies: public access is not prevented",
        ),
        (
            lambda t: t.update({f"{STORAGE}/b/{CONTROL}-policies": None}),
            f"FAIL stores {CONTROL}-policies: the bucket does not exist",
        ),
        (
            lambda t: t[f"{STORAGE}/b/{CONTROL}-policies"]["iamConfiguration"].update(
                uniformBucketLevelAccess={"enabled": False}
            ),
            f"FAIL stores {CONTROL}-policies: uniform access is off",
        ),
        (
            lambda t: t.update({f"{STORAGE}/b/{CONTROL}-snapshots": None}),
            f"FAIL stores {CONTROL}-snapshots: the bucket does not exist",
        ),
        (
            lambda t: t.update(
                {f"{LOGGING}/projects/{CONTROL}/locations/europe-west4/buckets/aiven-audit": None}
            ),
            "FAIL stores aiven-audit: the log bucket does not exist",
        ),
        (
            lambda t: t.update({f"{FIRESTORE}/projects/{GATEWAY}/databases/gateway": None}),
            "FAIL stores firestore gateway: the database does not exist",
        ),
        (
            lambda t: t[f"{FIRESTORE}/projects/{CONTROL}/databases/control"].update(
                type="DATASTORE_MODE"
            ),
            "FAIL stores firestore control: not in native mode",
        ),
        (
            lambda t: t[f"{FIRESTORE}/projects/{CONTROL}/databases/control"].update(
                locationId="eur3"
            ),
            "FAIL stores firestore control: not in europe-west4",
        ),
        (
            lambda t: t[f"{STORAGE}/b/{CONTROL}-snapshots"].update(
                retentionPolicy={"retentionPeriod": "604800"}
            ),
            f"FAIL stores {CONTROL}-snapshots: retention is not 30 days",
        ),
        (
            lambda t: t[f"{STORAGE}/b/{CONTROL}-snapshots"].update(lifecycle={"rule": []}),
            f"FAIL stores {CONTROL}-snapshots: no deletion at 30 days",
        ),
        (
            lambda t: t[f"{STORAGE}/b/{CONTROL}-snapshots"]["retentionPolicy"].update(
                isLocked=True
            ),
            f"FAIL stores {CONTROL}-snapshots: the retention policy is locked, which nobody decided",
        ),
        (
            lambda t: t[f"{STORAGE}/b/{CONTROL}-snapshots"].update(location="US"),
            f"FAIL stores {CONTROL}-snapshots: not in europe-west4",
        ),
        (
            lambda t: t[
                f"{LOGGING}/projects/{CONTROL}/locations/europe-west4/buckets/aiven-audit"
            ].update(retentionDays=30),
            "FAIL stores aiven-audit: keeps 30 days, not 365",
        ),
        (
            lambda t: t[f"{LOGGING}/projects/{CONTROL}/exclusions"].update(exclusions=[]),
            "FAIL stores aiven-audit routing: not kept out of _Default",
        ),
        (
            lambda t: t[f"{LOGGING}/projects/{CONTROL}/exclusions"].update(
                exclusions=[{"name": "x", "filter": AUDIT_FILTER, "disabled": True}]
            ),
            "FAIL stores aiven-audit routing: not kept out of _Default",
        ),
        (
            lambda t: t[f"{LOGGING}/projects/{CONTROL}/sinks/aiven-audit"].update(
                filter="severity>=ERROR"
            ),
            "FAIL stores aiven-audit routing: the sink aiven-audit does not route log aiven-audit to its bucket",
        ),
        (
            lambda t: t[f"{FIRESTORE}/projects/{CONTROL}/databases/control"].update(
                deleteProtectionState="DELETE_PROTECTION_DISABLED"
            ),
            "FAIL stores firestore control: not protected from deletion",
        ),
        (
            lambda t: t[
                f"{FIRESTORE}/projects/{GATEWAY}/databases/gateway/collectionGroups/runs/fields/expire_at"
            ].update(ttlConfig={"state": "NEEDS_REPAIR"}),
            "FAIL stores firestore gateway ttl: runs do not expire by expire_at (NEEDS_REPAIR)",
        ),
        (
            lambda t: t.update(
                {
                    f"{FIRESTORE}/projects/{GATEWAY}/databases/gateway/collectionGroups/calls/fields/expire_at": {}
                }
            ),
            "FAIL stores firestore gateway ttl: calls do not expire by expire_at (no TTL)",
        ),
    ],
)
def test_a_store_that_differs_fails(capsys, monkeypatch, change, expected):
    table = planned()
    change(table)
    assert expected in failing(capsys, monkeypatch, table, "stores")


def test_a_locked_audit_log_passes_its_lock_check(capsys, monkeypatch):
    table = planned()
    table[f"{LOGGING}/projects/{CONTROL}/locations/europe-west4/buckets/aiven-audit"]["locked"] = (
        True
    )
    status, lines, _ = run(capsys, monkeypatch, table, "stores")
    assert status == 0
    assert "PASS stores aiven-audit lock: locked" in lines
    assert lines_of(lines, "NOTE") == []


def test_a_ttl_still_being_made_is_a_note(capsys, monkeypatch):
    table = planned()
    url = f"{FIRESTORE}/projects/{GATEWAY}/databases/gateway/collectionGroups/runs/fields/expire_at"
    table[url] = {"ttlConfig": {"state": "CREATING"}}
    status, lines, _ = run(capsys, monkeypatch, table, "stores")
    assert status == 0
    assert "NOTE stores firestore gateway ttl: runs: the TTL is still being made" in lines


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (
            lambda b: b[0]["budgetFilter"].update(creditTypesTreatment="INCLUDE_ALL_CREDITS"),
            "FAIL budgets aiven-alert: it does not count gross cost (credits are not excluded)",
        ),
        (
            lambda b: b[1]["amount"]["specifiedAmount"].update(units="250"),
            "FAIL budgets aiven-stop: the amount is 250 EUR, not 25 EUR",
        ),
        (
            lambda b: b[1]["amount"]["specifiedAmount"].update(currencyCode="USD"),
            "FAIL budgets aiven-stop: the amount is 25 USD, not 25 EUR",
        ),
        (
            lambda b: b[0]["budgetFilter"].update(projects=["projects/111"]),
            "FAIL budgets aiven-alert: it does not cover exactly the agents, gateway and control projects",
        ),
        (
            lambda b: b[0].update(thresholdRules=[{"thresholdPercent": 1}]),
            "FAIL budgets aiven-alert: its thresholds are 1, not 0.5, 0.9 and 1",
        ),
        (
            lambda b: b[1].pop("notificationsRule"),
            "FAIL budgets aiven-stop: it does not publish to topic budget-stop",
        ),
        (lambda b: b.pop(1), "FAIL budgets aiven-stop: there is no such budget"),
        (
            lambda b: b[0]["budgetFilter"].update(calendarPeriod="QUARTER"),
            "FAIL budgets aiven-alert: it is not per calendar month",
        ),
    ],
)
def test_a_budget_that_differs_fails(capsys, monkeypatch, change, expected):
    table = planned()
    change(table[BUDGETS]["budgets"])
    assert expected in failing(capsys, monkeypatch, table, "budgets")


def test_a_budget_with_cents_is_read_exactly(capsys, monkeypatch):
    table = planned()
    table[BUDGETS]["budgets"][1]["amount"]["specifiedAmount"].update(units="24", nanos=990000000)
    assert "FAIL budgets aiven-stop: the amount is 24.99 EUR, not 25 EUR" in failing(
        capsys, monkeypatch, table, "budgets"
    )


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (
            lambda t: t[f"{DRIVE}/drives/{DRIVE_ID}?fields=id,name,restrictions"].update(
                restrictions={"driveMembersOnly": False}
            ),
            "FAIL drive sandbox sharing: files can be shared with people outside the drive",
        ),
        (
            lambda t: t[PERMISSIONS]["permissions"].append({"type": "anyone", "role": "reader"}),
            "FAIL drive sandbox members: also anyone (reader)",
        ),
        (
            lambda t: t[PERMISSIONS]["permissions"][1].update(role="fileOrganizer"),
            f"FAIL drive sandbox members: also {GATEWAY_SA} (fileOrganizer); missing {GATEWAY_SA} (writer)",
        ),
        (
            lambda t: t[PERMISSIONS]["permissions"].pop(0),
            f"FAIL drive sandbox members: missing {OWNER} (organizer)",
        ),
        (
            lambda t: t.update({f"{DRIVE}/drives/{DRIVE_ID}?fields=id,name,restrictions": None}),
            "FAIL drive sandbox sharing: the drive does not exist, or this login cannot see it",
        ),
    ],
)
def test_a_sandbox_that_differs_fails(capsys, monkeypatch, change, expected):
    table = planned()
    change(table)
    assert expected in failing(capsys, monkeypatch, table, "drive")


def test_without_the_drive_id_the_drive_checks_fail(capsys, monkeypatch):
    deployment = Deployment(**{**DEPLOYMENT.__dict__, "sandbox_drive_id": None})
    assert failing(capsys, monkeypatch, planned(), "drive", deployment=deployment) == [
        "FAIL drive sandbox: sandbox_drive_id is not in config/platform.yaml yet (setup step S5)"
    ]


def test_an_answer_that_is_an_error_fails_that_check_only(capsys, monkeypatch):
    table = planned()
    table[BUDGETS] = GoogleApiError(403)
    status, lines, _ = run(capsys, monkeypatch, table, "budgets", "apis")
    assert status == 1
    assert lines_of(lines, "FAIL") == ["FAIL budgets: could not read it (HTTP 403)"]
    assert any(line.startswith("PASS apis") for line in lines)


def test_a_drive_answer_of_403_says_how_to_log_in(capsys, monkeypatch):
    table = planned()
    table[f"{DRIVE}/drives/{DRIVE_ID}?fields=id,name,restrictions"] = GoogleApiError(403)
    found = failing(capsys, monkeypatch, table, "drive")
    assert found[0].startswith("FAIL drive sandbox sharing: could not read it (HTTP 403)")
    assert "check the Sandbox by hand" in found[0]


# --- when it cannot run


def test_a_crash_says_the_name_of_the_class_only(capsys, monkeypatch):
    def broken():
        raise RuntimeError("a message with an address user@aivenstudios.com")

    monkeypatch.setattr(deploy_check, "_google", broken)
    monkeypatch.setattr(deploy_check.Deployment, "load", classmethod(lambda cls, *a: DEPLOYMENT))
    assert main(["keys", *FILES]) == 2
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err and "user@" not in captured.err + captured.out


def test_an_unknown_group_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["everything"])
    assert caught.value.code == 2


# --- the expected values come from the committed files


def test_the_deployment_is_read_from_tfvars_and_the_platform_values(tmp_path):
    (tmp_path / "variables.tf").write_text(
        "".join(
            f'variable "{name}" {{\n}}\n'
            for name in (
                "agents_project",
                "gateway_project",
                "control_project",
                "scratch_project",
                "region",
                "agents",
                "billing_account",
                "budget_currency",
                "budget_alert_amount",
                "budget_stop_amount",
            )
        ),
        encoding="utf-8",
    )
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text(
        f'agents_project = "{AGENTS}"\ngateway_project = "{GATEWAY}"\ncontrol_project = "{CONTROL}"\n'
        'scratch_project = "aiven-scratch-test"\nagents = ["invoice-reminder"]\n'
        'billing_account = "01ABCD-23EF45-6789AB"\nbudget_currency = "EUR"\n'
        "budget_alert_amount = 10\nbudget_stop_amount = 25\n",
        encoding="utf-8",
    )
    platform = tmp_path / "platform.yaml"
    platform.write_text(
        f"agents_project: {AGENTS}\ntrusted_authors:\n  - {OWNER}\n"
        f"gateway_principal: {GATEWAY_SA}\nsandbox_drive_id: {DRIVE_ID}\n",
        encoding="utf-8",
    )
    assert Deployment.load(tfvars, platform) == DEPLOYMENT


def test_a_missing_file_stops_the_check_with_a_clear_line(tmp_path, capsys):
    assert main(["keys", "--tfvars", str(tmp_path / "terraform.tfvars")]) == 2
    assert "terraform.tfvars is missing" in capsys.readouterr().err


# --- the REST client


class FakeSession:
    def __init__(self, status: int, payload: dict | None = None) -> None:
        self.status, self.payload = status, payload
        self.requests: list = []

    def request(self, method, url, json=None, headers=None, timeout=None):
        self.requests.append((method, url, json, headers, timeout))
        content = b"{}" if self.payload is not None else b""
        return SimpleNamespace(status_code=self.status, content=content, json=lambda: self.payload)


def test_the_client_names_the_quota_project_and_reads_json():
    session = FakeSession(200, {"a": 1})
    assert RestGoogle(session=session).get("https://x.googleapis.com/v1/y", CONTROL) == {"a": 1}
    (method, url, body, headers, timeout) = session.requests[0]
    assert (method, headers, timeout) == ("GET", {"x-goog-user-project": CONTROL}, 30)
    assert RestGoogle(session=FakeSession(200, {"b": 2})).post(
        "https://x/y:getIamPolicy", {}, CONTROL
    ) == {"b": 2}
    assert RestGoogle(session=FakeSession(204)).get("https://x/y", CONTROL) == {}


def test_the_client_gives_none_for_404_and_raises_for_other_errors():
    assert RestGoogle(session=FakeSession(404)).get("https://x/y", CONTROL) is None
    with pytest.raises(GoogleApiError) as caught:
        RestGoogle(session=FakeSession(403)).get("https://x/y", CONTROL)
    assert caught.value.status == 403


def test_the_real_client_uses_the_application_default_login(monkeypatch):
    import google.auth

    made: list = []
    monkeypatch.setattr(
        google.auth, "default", lambda scopes: made.append(scopes) or ("credentials", None)
    )
    client = deploy_check._google()
    assert isinstance(client, RestGoogle)
    assert made == [deploy_check.SCOPES]


# --- the script of the plan


def test_the_script_of_the_plan_runs_the_same_command():
    done = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "deploy_check.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0
    assert "aiven-deploy-check" in done.stdout
    assert Path(REPO_ROOT / "scripts" / "deploy_check.py").read_text().count("main") >= 1
