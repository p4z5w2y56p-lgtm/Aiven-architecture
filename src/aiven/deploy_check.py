"""`aiven-deploy-check`: what no policy file can enforce, checked on the live projects.

gateway-design section 11 and drill BD-3 (plan Task 2.5; ruling R112). It only reads, with
Matthijs's own login (application default credentials): no key, and nothing an agent runs. Every
call names the control project as its quota project; the Drive calls name the gateway project,
the only one with the Drive API on. Each check prints one line:

    PASS <check>: <what holds>
    FAIL <check>: <what does not>
    NOTE <check>: <what is pending on purpose>

A NOTE does not fail the run. Two are expected in M2: the audit log lock waits for Matthijs's
confirmation (ruling R105), and the gateway service comes with M3. Exit code 0 when no check
failed, 1 when one did, 2 when the check could not run (with the name of the class of the error
only; its message can quote an answer).

The groups are those of the plan: keys, apis, iam, stores, budgets and drive, or all. What is
expected comes from infra/terraform/terraform.tfvars and config/platform.yaml: IDs and addresses,
which the lines name freely.
"""

import argparse
import sys
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, Protocol

from aiven.common.config_guard import read_tfvars
from aiven.policy.config import load_platform_config

IAM = "https://iam.googleapis.com/v1"
CRM = "https://cloudresourcemanager.googleapis.com/v1"
SERVICE_USAGE = "https://serviceusage.googleapis.com/v1"
RUN = "https://run.googleapis.com/v2"
STORAGE = "https://storage.googleapis.com/storage/v1"
LOGGING = "https://logging.googleapis.com/v2"
FIRESTORE = "https://firestore.googleapis.com/v1"
BUDGETS = "https://billingbudgets.googleapis.com/v1"
DRIVE = "https://www.googleapis.com/drive/v3"

# The Drive scope is read only; `gcloud auth application-default login` must have asked for it.
SCOPES = (
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/drive.readonly",
)
WORKSPACE_APIS = ("drive.googleapis.com", "sheets.googleapis.com", "gmail.googleapis.com")
THIRTY_DAYS = 30 * 24 * 60 * 60

Status = Literal["PASS", "FAIL", "NOTE"]


class GoogleApiError(Exception):
    """A Google API answered with an error. `status` is its HTTP status; the body is not kept."""

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


class Google(Protocol):
    """The calls the checks make: reads, and getIamPolicy, which is a read with POST."""

    def get(self, url: str, quota_project: str) -> dict[str, Any] | None: ...

    def post(self, url: str, body: dict[str, Any], quota_project: str) -> dict[str, Any] | None: ...


class RestGoogle:
    """Google's REST APIs with the application default login. A 404 is None, not an error."""

    def __init__(self, session: Any = None) -> None:
        if session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession

            # A user login has no quota project of its own; every call names one (x-goog-user-project),
            # so google.auth's warning about it says nothing here.
            warnings.filterwarnings(
                "ignore", message="Your application has authenticated using end user"
            )
            credentials, _ = google.auth.default(scopes=SCOPES)
            session = AuthorizedSession(credentials)
        self._session = session

    def _call(self, method: str, url: str, quota_project: str, body: Any = None) -> Any:
        response = self._session.request(
            method, url, json=body, headers={"x-goog-user-project": quota_project}, timeout=30
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise GoogleApiError(response.status_code)
        return response.json() if response.content else {}

    def get(self, url: str, quota_project: str) -> dict[str, Any] | None:
        return self._call("GET", url, quota_project)

    def post(self, url: str, body: dict[str, Any], quota_project: str) -> dict[str, Any] | None:
        return self._call("POST", url, quota_project, body)


def _google() -> Google:
    return RestGoogle()


@dataclass(frozen=True)
class Deployment:
    """What the projects must hold, from the Terraform values and the platform values."""

    agents_project: str
    gateway_project: str
    control_project: str
    region: str
    agents: tuple[str, ...]
    billing_account: str
    currency: str
    alert_amount: Decimal
    stop_amount: Decimal
    gateway_account: str
    organizers: tuple[str, ...]
    sandbox_drive_id: str | None

    @classmethod
    def load(cls, tfvars: Path, platform: Path) -> "Deployment":
        values = read_tfvars(tfvars)
        cfg = load_platform_config(platform)
        return cls(
            agents_project=str(values["agents_project"]),
            gateway_project=str(values["gateway_project"]),
            control_project=str(values["control_project"]),
            region=str(values.get("region", "europe-west4")),
            agents=tuple(values.get("agents", ())),  # type: ignore[arg-type]
            billing_account=str(values["billing_account"]),
            currency=str(values["budget_currency"]),
            alert_amount=Decimal(str(values["budget_alert_amount"])),
            stop_amount=Decimal(str(values["budget_stop_amount"])),
            gateway_account=cfg.gateway_principal,
            organizers=cfg.trusted_authors,
            sandbox_drive_id=cfg.sandbox_drive_id,
        )

    @property
    def projects(self) -> tuple[str, str, str]:
        return (self.agents_project, self.gateway_project, self.control_project)


@dataclass(frozen=True)
class Result:
    status: Status
    check: str
    detail: str

    def __str__(self) -> str:
        return f"{self.status} {self.check}: {self.detail}"


def _verdict(check: str, problems: list[str], passed: str) -> Result:
    """FAIL with the problems, or PASS with what holds."""
    if problems:
        return Result("FAIL", check, "; ".join(problems))
    return Result("PASS", check, passed)


def _guarded(check: str, run: Callable[[], list[Result]], hint: str = "") -> list[Result]:
    """The results of `run`, or one FAIL when an answer was an error."""
    try:
        return run()
    except GoogleApiError as error:
        return [Result("FAIL", check, f"could not read it ({error}){hint}")]


def _all(google: Google, url: str, key: str, quota: str) -> list[dict[str, Any]]:
    """Every item of a list that comes in pages."""
    items: list[dict[str, Any]] = []
    token = None
    while True:
        page_url = url if token is None else f"{url}{'&' if '?' in url else '?'}pageToken={token}"
        page = google.get(page_url, quota) or {}
        items += page.get(key, [])
        token = page.get("nextPageToken")
        if not token:
            return items


def _amount(value: Decimal) -> str:
    return format(value.normalize(), "f")


# --- keys: no user-managed service account keys (section 11)


def check_keys(google: Google, d: Deployment) -> list[Result]:
    results: list[Result] = []
    for project in d.projects:
        results += _guarded(f"keys {project}", lambda project=project: [_keys(google, d, project)])
    return results


def _keys(google: Google, d: Deployment, project: str) -> Result:
    accounts = _all(
        google,
        f"{IAM}/projects/{project}/serviceAccounts?pageSize=100",
        "accounts",
        d.control_project,
    )
    with_keys = []
    for account in accounts:
        url = f"{IAM}/projects/{project}/serviceAccounts/{account['email']}/keys?keyTypes=USER_MANAGED"
        if (google.get(url, d.control_project) or {}).get("keys"):
            with_keys.append(account["email"])
    problems = [f"user-managed keys on {', '.join(sorted(with_keys))}"] if with_keys else []
    return _verdict(
        f"keys {project}", problems, f"no user-managed key on its {len(accounts)} service accounts"
    )


# --- apis: Drive, Sheets and Gmail off in agents (section 11)


def check_apis(google: Google, d: Deployment) -> list[Result]:
    return _guarded("apis agents", lambda: [_apis(google, d)])


def _apis(google: Google, d: Deployment) -> Result:
    url = f"{SERVICE_USAGE}/projects/{d.agents_project}/services?filter=state:ENABLED&pageSize=200"
    services = _all(google, url, "services", d.control_project)
    enabled = {s.get("config", {}).get("name") or s["name"].rsplit("/", 1)[-1] for s in services}
    on = sorted(enabled & set(WORKSPACE_APIS))
    problems = []
    if on:
        verb = "is" if len(on) == 1 else "are"
        problems.append(
            f"{', '.join(on)} {verb} enabled in {d.agents_project}; Drive, Sheets and Gmail must be off"
        )
    return _verdict(
        "apis agents", problems, f"Drive, Sheets and Gmail are off in {d.agents_project}"
    )


# --- iam: agents hold aiplatform.user, and run.invoker on the gateway service (ruling R101)


def _agent(member: str, d: Deployment) -> str | None:
    """The account name of an agent's member (agent-<id>), or None for any other member."""
    suffix = f"@{d.agents_project}.iam.gserviceaccount.com"
    if member.startswith("serviceAccount:agent-") and member.endswith(suffix):
        return member.removeprefix("serviceAccount:").removesuffix(suffix)
    return None


def check_iam(google: Google, d: Deployment) -> list[Result]:
    return _guarded("iam", lambda: _iam(google, d))


def _iam(google: Google, d: Deployment) -> list[Result]:
    held: list[tuple[str, str, str]] = []  # (project, role, agent)
    for project in d.projects:
        policy = google.post(
            f"{CRM}/projects/{project}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}},
            d.control_project,
        )
        for binding in (policy or {}).get("bindings", []):
            for member in binding.get("members", []):
                if (agent := _agent(member, d)) is not None:
                    held.append((project, binding["role"], agent))
    vertex = {
        agent
        for project, role, agent in held
        if (project, role) == (d.agents_project, "roles/aiplatform.user")
    }
    missing = [agent for agent in d.agents if f"agent-{agent}" not in vertex]
    others = sorted(
        f"{agent} holds {role} on {project}"
        for project, role, agent in held
        if (project, role) != (d.agents_project, "roles/aiplatform.user")
    )
    results = [
        _verdict(
            "iam agents vertex",
            [f"no roles/aiplatform.user for {', '.join(missing)}"] if missing else [],
            "every agent has roles/aiplatform.user on the agents project",
        ),
        _verdict(
            "iam agents other roles",
            others,
            "no agent holds another role on the agents, gateway or control project",
        ),
    ]
    # Whether the service exists, asked of the service itself: Cloud Run answers getIamPolicy of a
    # service that does not exist with an empty policy, which reads as a PASS (seen at the apply).
    service_url = f"{RUN}/projects/{d.gateway_project}/locations/{d.region}/services/gateway"
    exists = google.get(service_url, d.control_project)
    service = (
        None if exists is None else google.get(f"{service_url}:getIamPolicy", d.control_project)
    )
    if exists is None or service is None:
        results.append(
            Result(
                "NOTE",
                "iam gateway service",
                "it does not exist yet (M3); then agents may only invoke it",
            )
        )
        return results
    wrong = sorted(
        f"{agent} holds {binding['role']} on the gateway service"
        for binding in service.get("bindings", [])
        for member in binding.get("members", [])
        if (agent := _agent(member, d)) is not None and binding["role"] != "roles/run.invoker"
    )
    results.append(_verdict("iam gateway service", wrong, "agents may only invoke it"))
    return results


# --- stores: retentions, the lock, versioning and the exclusion (plan Task 2.2)


def check_stores(google: Google, d: Deployment) -> list[Result]:
    results: list[Result] = []
    for check, run in (
        (f"stores {d.control_project}-policies", lambda: [_policies(google, d)]),
        (f"stores {d.control_project}-snapshots", lambda: [_snapshots(google, d)]),
        ("stores aiven-audit", lambda: _audit_bucket(google, d)),
        ("stores aiven-audit routing", lambda: [_routing(google, d)]),
        ("stores firestore", lambda: _firestore(google, d)),
    ):
        results += _guarded(check, run)
    return results


def _bucket_problems(bucket: dict[str, Any] | None, region: str) -> list[str]:
    if bucket is None:
        return ["the bucket does not exist"]
    problems = []
    if str(bucket.get("location", "")).lower() != region:
        problems.append(f"not in {region}")
    access = bucket.get("iamConfiguration", {})
    if not access.get("uniformBucketLevelAccess", {}).get("enabled"):
        problems.append("uniform access is off")
    if access.get("publicAccessPrevention") != "enforced":
        problems.append("public access is not prevented")
    return problems


def _policies(google: Google, d: Deployment) -> Result:
    name = f"{d.control_project}-policies"
    bucket = google.get(f"{STORAGE}/b/{name}", d.control_project)
    problems = _bucket_problems(bucket, d.region)
    if bucket is not None and not bucket.get("versioning", {}).get("enabled"):
        problems.append("not versioned")
    return _verdict(
        f"stores {name}", problems, "versioned, uniform access, never public, europe-west4"
    )


def _snapshots(google: Google, d: Deployment) -> Result:
    name = f"{d.control_project}-snapshots"
    bucket = google.get(f"{STORAGE}/b/{name}", d.control_project)
    problems = _bucket_problems(bucket, d.region)
    if bucket is not None:
        retention = bucket.get("retentionPolicy", {})
        if str(retention.get("retentionPeriod")) != str(THIRTY_DAYS):
            problems.append("retention is not 30 days")
        if retention.get("isLocked"):
            problems.append("the retention policy is locked, which nobody decided")
        rules = bucket.get("lifecycle", {}).get("rule", [])
        if not any(
            rule.get("action", {}).get("type") == "Delete"
            and rule.get("condition", {}).get("age") == 30
            for rule in rules
        ):
            problems.append("no deletion at 30 days")
    return _verdict(f"stores {name}", problems, "every object kept 30 days, then deleted")


def _audit_bucket(google: Google, d: Deployment) -> list[Result]:
    url = f"{LOGGING}/projects/{d.control_project}/locations/{d.region}/buckets/aiven-audit"
    bucket = google.get(url, d.control_project)
    if bucket is None:
        return [Result("FAIL", "stores aiven-audit", "the log bucket does not exist")]
    days = bucket.get("retentionDays")
    retention = _verdict(
        "stores aiven-audit",
        [f"keeps {days} days, not 365"] if days != 365 else [],
        "keeps 365 days",
    )
    if bucket.get("locked"):
        return [retention, Result("PASS", "stores aiven-audit lock", "locked")]
    pending = "not locked; the lock waits for Matthijs's confirmation (ruling R105)"
    return [retention, Result("NOTE", "stores aiven-audit lock", pending)]


def _routing(google: Google, d: Deployment) -> Result:
    log = f'logName="projects/{d.control_project}/logs/aiven-audit"'
    bucket = f"logging.googleapis.com/projects/{d.control_project}/locations/{d.region}/buckets/aiven-audit"
    sink = google.get(
        f"{LOGGING}/projects/{d.control_project}/sinks/aiven-audit", d.control_project
    )
    problems = []
    if sink is None or sink.get("destination") != bucket or sink.get("filter") != log:
        problems.append("the sink aiven-audit does not route log aiven-audit to its bucket")
    exclusions = _all(
        google,
        f"{LOGGING}/projects/{d.control_project}/exclusions",
        "exclusions",
        d.control_project,
    )
    if not any(each.get("filter") == log and not each.get("disabled") for each in exclusions):
        problems.append("not kept out of _Default")
    return _verdict(
        "stores aiven-audit routing", problems, "log aiven-audit goes to its own bucket only"
    )


def _firestore(google: Google, d: Deployment) -> list[Result]:
    results = []
    for project, name in ((d.control_project, "control"), (d.gateway_project, "gateway")):
        database = google.get(f"{FIRESTORE}/projects/{project}/databases/{name}", d.control_project)
        problems = []
        if database is None:
            problems.append("the database does not exist")
        else:
            if database.get("type") != "FIRESTORE_NATIVE":
                problems.append("not in native mode")
            if database.get("locationId") != d.region:
                problems.append(f"not in {d.region}")
            if database.get("deleteProtectionState") != "DELETE_PROTECTION_ENABLED":
                problems.append("not protected from deletion")
        results.append(
            _verdict(
                f"stores firestore {name}",
                problems,
                "native, europe-west4, protected from deletion",
            )
        )
    for group in ("runs", "calls"):
        url = (
            f"{FIRESTORE}/projects/{d.gateway_project}/databases/gateway/collectionGroups/{group}"
            "/fields/expire_at"
        )
        state = ((google.get(url, d.control_project) or {}).get("ttlConfig") or {}).get("state")
        check = "stores firestore gateway ttl"
        if state == "ACTIVE":
            results.append(Result("PASS", check, f"{group} expire by expire_at"))
        elif state == "CREATING":
            results.append(Result("NOTE", check, f"{group}: the TTL is still being made"))
        else:
            results.append(
                Result("FAIL", check, f"{group} do not expire by expire_at ({state or 'no TTL'})")
            )
    return results


# --- budgets: both gross, with the right amounts, currency and topic (BD-3)


def check_budgets(google: Google, d: Deployment) -> list[Result]:
    return _guarded("budgets", lambda: _budgets(google, d))


def _budgets(google: Google, d: Deployment) -> list[Result]:
    found = _all(
        google,
        f"{BUDGETS}/billingAccounts/{d.billing_account}/budgets",
        "budgets",
        d.control_project,
    )
    by_name = {budget.get("displayName"): budget for budget in found}
    numbers = set()
    for project in d.projects:
        answer = google.get(f"{CRM}/projects/{project}", d.control_project) or {}
        numbers.add(f"projects/{answer.get('projectNumber')}")
    results = []
    for name, amount, thresholds, topic in (
        ("aiven-alert", d.alert_amount, ("0.5", "0.9", "1"), None),
        ("aiven-stop", d.stop_amount, ("1",), f"projects/{d.control_project}/topics/budget-stop"),
    ):
        budget = by_name.get(name)
        if budget is None:
            results.append(Result("FAIL", f"budgets {name}", "there is no such budget"))
            continue
        problems = []
        scope = budget.get("budgetFilter", {})
        if scope.get("creditTypesTreatment") != "EXCLUDE_ALL_CREDITS":
            problems.append("it does not count gross cost (credits are not excluded)")
        if set(scope.get("projects", [])) != numbers:
            problems.append("it does not cover exactly the agents, gateway and control projects")
        if scope.get("calendarPeriod", "MONTH") != "MONTH":
            problems.append("it is not per calendar month")
        specified = budget.get("amount", {}).get("specifiedAmount", {})
        got = Decimal(str(specified.get("units", "0"))) + Decimal(specified.get("nanos", 0)) / 10**9
        currency = specified.get("currencyCode")
        if (got, currency) != (amount, d.currency):
            problems.append(
                f"the amount is {_amount(got)} {currency}, not {_amount(amount)} {d.currency}"
            )
        levels = tuple(
            _amount(Decimal(str(rule.get("thresholdPercent"))))
            for rule in budget.get("thresholdRules", [])
        )
        if sorted(levels, key=Decimal) != list(thresholds):
            wanted = " and ".join(
                [", ".join(thresholds[:-1]), thresholds[-1]] if len(thresholds) > 1 else thresholds
            )
            problems.append(f"its thresholds are {', '.join(levels) or 'none'}, not {wanted}")
        if topic is not None and budget.get("notificationsRule", {}).get("pubsubTopic") != topic:
            problems.append("it does not publish to topic budget-stop")
        passed = f"gross cost, {_amount(amount)} {d.currency} a month, over the three projects"
        if topic is not None:
            passed += ", to topic budget-stop"
        results.append(_verdict(f"budgets {name}", problems, passed))
    return results


# --- drive: the Sandbox's members and sharing (section 11; drive-wrapper section 1)

DRIVE_HINT = (
    "; Google refuses the Drive scope to gcloud's own login, so check the Sandbox by hand "
    "(runbook m2-apply.md, part 6)"
)


def check_drive(google: Google, d: Deployment) -> list[Result]:
    if not d.sandbox_drive_id:
        return [
            Result(
                "FAIL",
                "drive sandbox",
                "sandbox_drive_id is not in config/platform.yaml yet (setup step S5)",
            )
        ]
    return [
        *_guarded("drive sandbox sharing", lambda: [_sharing(google, d)], DRIVE_HINT),
        *_guarded("drive sandbox members", lambda: [_members(google, d)], DRIVE_HINT),
    ]


def _sharing(google: Google, d: Deployment) -> Result:
    url = f"{DRIVE}/drives/{d.sandbox_drive_id}?fields=id,name,restrictions"
    drive = google.get(url, d.gateway_project)
    if drive is None:
        return Result(
            "FAIL", "drive sandbox sharing", "the drive does not exist, or this login cannot see it"
        )
    problems = []
    if not drive.get("restrictions", {}).get("driveMembersOnly"):
        problems.append("files can be shared with people outside the drive")
    return _verdict("drive sandbox sharing", problems, "sharing with non-members is off")


def _members(google: Google, d: Deployment) -> Result:
    url = (
        f"{DRIVE}/files/{d.sandbox_drive_id}/permissions?supportsAllDrives=true"
        "&fields=nextPageToken,permissions(type,role,emailAddress,domain)"
    )
    permissions = _all(google, url, "permissions", d.gateway_project)
    have = {
        (each.get("emailAddress") or each.get("domain") or each.get("type"), each.get("role"))
        for each in permissions
    }
    want = {(email, "organizer") for email in d.organizers} | {(d.gateway_account, "writer")}
    problems = []
    if extra := sorted(have - want):
        problems.append("also " + ", ".join(f"{who} ({role})" for who, role in extra))
    if missing := sorted(want - have):
        problems.append("missing " + ", ".join(f"{who} ({role})" for who, role in missing))
    passed = f"exactly {', '.join(d.organizers)} (organizer) and the gateway (writer)"
    return _verdict("drive sandbox members", problems, passed)


GROUPS: dict[str, Callable[[Google, Deployment], list[Result]]] = {
    "keys": check_keys,
    "apis": check_apis,
    "iam": check_iam,
    "stores": check_stores,
    "budgets": check_budgets,
    "drive": check_drive,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and give the exit code: 0, 1 or 2 (see the module)."""
    parser = argparse.ArgumentParser(
        prog="aiven-deploy-check",
        description="Check the live projects against gateway-design section 11 and drill BD-3.",
    )
    parser.add_argument("groups", nargs="+", choices=[*GROUPS, "all"], help="what to check")
    parser.add_argument("--tfvars", type=Path, default=Path("infra/terraform/terraform.tfvars"))
    parser.add_argument("--config", type=Path, default=Path("config/platform.yaml"))
    args = parser.parse_args(argv)
    for path in (args.tfvars, args.config):
        if not path.exists():
            print(
                f"{path} is missing: the deploy check compares the projects with it",
                file=sys.stderr,
            )
            return 2
    names = list(GROUPS) if "all" in args.groups else list(dict.fromkeys(args.groups))
    failed = False
    try:
        deployment = Deployment.load(args.tfvars, args.config)
        google = _google()
        for name in names:
            for result in GROUPS[name](google, deployment):
                print(result, flush=True)
                failed = failed or result.status == "FAIL"
    except Exception as error:
        # The message of the error can quote an answer of Google; its class cannot.
        print(f"the deploy check could not run ({type(error).__name__})", file=sys.stderr)
        return 2
    return 1 if failed else 0
