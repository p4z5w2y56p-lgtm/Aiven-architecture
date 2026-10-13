"""The helpers of `scripts/m2-oneclick.sh`, the one-click apply of M2 (runbook m2-apply.md).

The script is bash, on Matthijs's Mac. What needs parsing, writing, an API call or a judgement is
here, as subcommands of `python -m aiven.m2_oneclick`:

- `values-read`: the IDs and addresses that `infra/terraform/terraform.tfvars` and
  `config/platform.yaml` hold, one `name=value` line each (a list is joined with commas). A value
  of the example files (`aiven-agents-example`, ...) counts as missing, and is not printed. A file
  that the config guard refuses, or two files that name different projects, stop it (exit 1).
- `values-write name=value ...`: writes both files with these values and the ones they hold, and
  checks them with the config guard. A file that the guard refuses is put back as it was (exit 1).
  Both take `--root DIR`, the folder that holds `config/` and `infra/terraform/`: a dry run that
  still has projects to make writes its values to a folder of its own, not to the repository.
- `plan-summary <plan.json> --mode main|drill-on|drill-off`: a short summary of a Terraform plan
  (`terraform show -json`) against the runbook. Exit 3 when the plan must not be applied: a service
  account key, a lock (`locked = true`, ruling R105), a role for anyone but a service account, or
  for the drill anything but the drill (and a drill function that stops another project than
  scratch).
- `result-write <path>`: writes the text on stdin to `path`, without any line that the content
  scan flags (a credential, a bank detail, an ID number).

No credential passes through here: the files hold IDs and addresses only, and nothing here calls a
Google API. Adding the gateway to the Sandbox drive is a step by hand: Google refuses the Drive
scope to gcloud's own login (ruling R162).
"""

import argparse
import json
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from aiven.common.config_guard import check_file, read_tfvars
from aiven.policy.config import load_platform_config
from aiven.policy.content import scan

TFVARS = Path("infra/terraform/terraform.tfvars")
PLATFORM = Path("config/platform.yaml")

EXIT_OK, EXIT_ERROR, EXIT_CRASH, EXIT_REFUSED = 0, 1, 2, 3

# What the script asks for, as `values-read` names it. `agents` and `trusted_authors` are lists.
FIELDS = (
    "agents_project",
    "gateway_project",
    "control_project",
    "scratch_project",
    "billing_account",
    "budget_currency",
    "alert_email",
    "agents",
    "trusted_authors",
    "sandbox_drive_id",
)
REQUIRED = FIELDS[:-1]  # the Sandbox drive may come later (setup step S5)
LISTS = ("agents", "trusted_authors")

# The values of the example files, which no deployment has.
EXAMPLE_VALUES = frozenset({"01ABCD-23EF45-6789AB", "trusted-author@aivenstudios.com"})

# Budgets per month by currency (setup step S2), and the dates of the credit (setup step S3).
BUDGETS = {"EUR": (10, 25), "USD": (11, 27)}
CREDIT_ALERT_DATE, CREDIT_EXPIRY_DATE = "2026-12-20", "2027-01-04"


class ValuesError(Exception):
    """The values cannot be read or written; the message says why, and holds no value."""


def is_example(value: str) -> bool:
    """Whether a value is one of the example files' stand-ins."""
    return value in EXAMPLE_VALUES or value.endswith("-example") or "-example." in value


def _guarded(path: Path) -> None:
    """Raise ValuesError with the guard's lines when the guard refuses the file."""
    problems = check_file(path)
    if problems:
        lines = "\n".join(str(problem) for problem in problems)
        raise ValuesError(f"{path} does not pass aiven-check-config:\n{lines}")


def gateway_principal(gateway_project: str) -> str:
    return f"gateway@{gateway_project}.iam.gserviceaccount.com"


def read_values(tfvars: Path = TFVARS, platform: Path = PLATFORM) -> dict[str, Any]:
    """The values both files hold: those of `FIELDS`, and the other Terraform values as they are.

    A value of the example files is left out. The keys of the other Terraform values are
    prefixed with `tfvars.`, so that `write_values` keeps them.
    """
    values: dict[str, Any] = {}
    if tfvars.exists():
        _guarded(tfvars)
        for name, value in read_tfvars(tfvars).items():
            values[name if name in FIELDS else f"tfvars.{name}"] = value
    if platform.exists():
        _guarded(platform)
        cfg = load_platform_config(platform)
        if "agents_project" in values and values["agents_project"] != cfg.agents_project:
            raise ValuesError(
                f"{tfvars} and {platform} name a different agents project: make them the same"
            )
        values.setdefault("agents_project", cfg.agents_project)
        values["trusted_authors"] = cfg.trusted_authors
        if cfg.sandbox_drive_id:
            values["sandbox_drive_id"] = cfg.sandbox_drive_id
        if "gateway_project" in values and cfg.gateway_principal != gateway_principal(
            values["gateway_project"]
        ):
            raise ValuesError(
                f"{platform} names another gateway account than the gateway project of {tfvars}"
            )
    kept: dict[str, Any] = {}
    for name, value in values.items():
        items = value if isinstance(value, tuple) else (value,)
        if not any(isinstance(item, str) and is_example(item) for item in items):
            kept[name] = value
    return kept


def _hcl(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal | int):
        return str(value)
    if isinstance(value, tuple):
        return "[" + ", ".join(f'"{item}"' for item in value) + "]"
    return f'"{value}"'


def _block(pairs: list[tuple[str, Any]]) -> str:
    """Assignments with their `=` in one column, as `terraform fmt` writes them."""
    width = max(len(name) for name, _ in pairs)
    return "".join(f"{name.ljust(width)} = {_hcl(value)}\n" for name, value in pairs)


def render_tfvars(values: dict[str, Any]) -> str:
    """The Terraform values file, in the layout of terraform.tfvars.example."""
    alert, stop = BUDGETS.get(values["budget_currency"], (None, None))
    budget_alert = values.get("tfvars.budget_alert_amount", alert)
    budget_stop = values.get("tfvars.budget_stop_amount", stop)
    region = values.get("tfvars.region", "europe-west4")
    credit_alert = values.get("tfvars.credit_alert_date", CREDIT_ALERT_DATE)
    credit_expiry = values.get("tfvars.credit_expiry_date", CREDIT_EXPIRY_DATE)
    shown = {
        "region",
        "budget_alert_amount",
        "budget_stop_amount",
        "credit_alert_date",
        "credit_expiry_date",
    }
    others = [
        (name.removeprefix("tfvars."), value)
        for name, value in values.items()
        if name.startswith("tfvars.") and name.removeprefix("tfvars.") not in shown
    ]
    text = (
        "# The Terraform values of the deployment: IDs and addresses only, never a credential, a key"
        " or a\n"
        "# token. CI refuses anything else here (aiven-check-config). scripts/m2-oneclick.sh wrote"
        " it from\n"
        "# terraform.tfvars.example and the answers it was given.\n"
        "\n"
        + _block(
            [
                ("agents_project", values["agents_project"]),
                ("gateway_project", values["gateway_project"]),
                ("control_project", values["control_project"]),
                ("scratch_project", values["scratch_project"]),
                ("region", region),
            ]
        )
        + "\n# Budgets, gross cost per month (setup step S2): 10 and 25 in EUR, 11 and 27 in USD.\n"
        + _block(
            [
                ("billing_account", values["billing_account"]),
                ("budget_currency", values["budget_currency"]),
                ("budget_alert_amount", budget_alert),
                ("budget_stop_amount", budget_stop),
            ]
        )
        + "\n# Alerts, and the reminder before the promotional credit ends (setup step S3).\n"
        + _block(
            [
                ("alert_email", values["alert_email"]),
                ("credit_alert_date", credit_alert),
                ("credit_expiry_date", credit_expiry),
            ]
        )
        + "\n# The agents, by agent ID (validator-spec 3.3). Each gets the service account"
        " agent-<id>.\n" + _block([("agents", tuple(values["agents"]))])
    )
    if others:
        text += "\n# Other settings (runbook budget-stop.md).\n" + _block(others)
    return text


def render_platform(values: dict[str, Any]) -> str:
    """The platform values file, in the layout of platform.example.yaml."""
    authors = "".join(f"  - {author}\n" for author in values["trusted_authors"])
    drive = values.get("sandbox_drive_id")
    drive_line = (
        f'sandbox_drive_id: "{drive}"\n'
        if drive
        else "# sandbox_drive_id: added once the drive exists (setup step S5).\n"
    )
    return (
        "# The platform values of the deployment (docs/validator-spec.md section 6): IDs and"
        " addresses\n"
        "# only, never a credential, a key or a token. CI refuses anything else here"
        " (aiven-check-config).\n"
        "# scripts/m2-oneclick.sh wrote it from platform.example.yaml and the answers it was"
        " given.\n"
        "\n"
        "# The project that holds the agents' service accounts. It is the project in every"
        " policy's `principal`.\n"
        f"agents_project: {values['agents_project']}\n"
        "\n"
        "# AIVEN accounts whose edits to a Drive file do not make a run untrusted"
        " (docs/drive-wrapper.md section 5).\n"
        f"trusted_authors:\n{authors}"
        "\n"
        "# The gateway's own service account (docs/drive-wrapper.md section 1).\n"
        f"gateway_principal: {gateway_principal(values['gateway_project'])}\n"
        "\n"
        '# The ID of the Shared Drive "AIVEN Architecture Sandbox" (setup step S5).\n'
        f"{drive_line}"
    )


def write_values(
    updates: dict[str, Any], tfvars: Path = TFVARS, platform: Path = PLATFORM
) -> dict[str, Any]:
    """Write both files with `updates` over the values they hold, and give the values written.

    Both are checked with the config guard after they are written; when the guard refuses one,
    both are put back as they were and ValuesError says why.
    """
    values = {**read_values(tfvars, platform), **updates}
    if missing := [name for name in REQUIRED if not values.get(name)]:
        raise ValuesError("these values are missing: " + ", ".join(missing))
    if values["budget_currency"] not in BUDGETS:
        raise ValuesError("the billing account's currency must be EUR or USD")
    texts = {tfvars: render_tfvars(values), platform: render_platform(values)}
    before = {path: path.read_bytes() if path.exists() else None for path in texts}
    try:
        for path, text in texts.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="ascii")
        for path in texts:
            _guarded(path)
    except (ValuesError, UnicodeEncodeError) as error:
        for path, old in before.items():
            if old is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(old)
        if isinstance(error, UnicodeEncodeError):
            raise ValuesError("a value is not plain ASCII") from None
        raise
    return values


def _parse_updates(pairs: Sequence[str]) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or name not in FIELDS:
            raise ValuesError(f"not a value to write: {name!r}")
        if name in LISTS:
            updates[name] = tuple(item.strip() for item in value.split(",") if item.strip())
        else:
            updates[name] = value.strip()
    return updates


def _shown(value: Any) -> str:
    return ",".join(value) if isinstance(value, tuple) else str(value)


# --- the plan (terraform show -json)

DRILL = "budget-stop-drill"
DRILL_FUNCTION = f'module.control.google_cloudfunctions2_function.stop["{DRILL}"]'
DRILL_ADDRESSES = frozenset(
    {
        f'module.control.google_pubsub_topic.stop["{DRILL}"]',
        DRILL_FUNCTION,
        f'module.control.google_cloud_run_v2_service_iam_member.stop_invoker["{DRILL}"]',
        "module.control.google_project_iam_member.drill[0]",
    }
)
# Its filter names the drill's function while the drill is on (alerts.tf).
ALERT_POLICY = "module.control.google_monitoring_alert_policy.alert_entries"

# The APIs of each project, as runbook part 4 has them.
APIS = {"control": 17, "agents": 5, "gateway": 7}


def _managed(module: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for resource in module.get("resources", []):
        if resource.get("mode") == "managed":
            yield resource
    for child in module.get("child_modules", []):
        yield from _managed(child)


def _locks(value: Any, path: str = "") -> Iterator[str]:
    """Where a value of the plan sets a lock: `locked` or `is_locked` true, at any depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("locked", "is_locked") and item is True:
                yield f"{path}.{key}".lstrip(".")
            yield from _locks(item, f"{path}.{key}")
    elif isinstance(value, list):
        for number, item in enumerate(value):
            yield from _locks(item, f"{path}[{number}]")


@dataclass(frozen=True)
class Summary:
    lines: list[str]
    refused: list[str]

    @property
    def status(self) -> int:
        return EXIT_REFUSED if self.refused else EXIT_OK


def _actions(changes: list[dict[str, Any]]) -> dict[str, list[str]]:
    """The addresses of the managed resources that the plan creates, changes, replaces, deletes."""
    found: dict[str, list[str]] = {"create": [], "update": [], "replace": [], "delete": []}
    for change in changes:
        if change.get("mode") != "managed":
            continue
        actions = change["change"]["actions"]
        if actions == ["create"]:
            found["create"].append(change["address"])
        elif actions == ["update"]:
            found["update"].append(change["address"])
        elif actions == ["delete"]:
            found["delete"].append(change["address"])
        elif "delete" in actions:  # delete then create, or create then delete
            found["replace"].append(change["address"])
    return found


def _row(ok: bool, what: str, detail: str) -> str:
    return f"  {'ok' if ok else '!!'}  {what:<24}{detail}"


def summarize(plan: dict[str, Any], mode: str, scratch: str | None = None) -> Summary:
    """The summary of a plan, and what makes it one not to apply (see the module)."""
    changes = plan.get("resource_changes", [])
    resources = list(_managed(plan.get("planned_values", {}).get("root_module", {})))
    acted = _actions(changes)
    lines = [
        f"Terraform plan: {len(acted['create'])} to create, {len(acted['update'])} to change, "
        f"{len(acted['replace'])} to replace, {len(acted['delete'])} to delete."
    ]
    refused: list[str] = []

    # Never in any plan: a key, a lock, a role for a person (runbook part 4).
    every_type = {change["type"] for change in changes} | {r["type"] for r in resources}
    if "google_service_account_key" in every_type:
        refused.append("the plan makes a service account key")
    for resource in resources:
        for where in _locks(resource.get("values", {})):
            refused.append(f"{resource['address']} sets {where} = true (the lock waits, R105)")
        if resource["type"].endswith("_iam_member"):
            member = resource.get("values", {}).get("member", "")
            if not member.startswith("serviceAccount:"):
                refused.append(f"{resource['address']} grants a role to {member or 'nobody'}")

    if mode == "main":
        lines += _main_rows(resources)
        risky = acted["delete"] + acted["replace"]
        drill = [address for address in risky if address in DRILL_ADDRESSES]
        other = [address for address in risky if address not in DRILL_ADDRESSES]
        if drill:
            lines.append(
                f"  The copy of the drill is still there and goes: {len(drill)} resources."
            )
        if other:
            lines.append(f"  WARNING: this plan deletes or replaces {len(other)} resources:")
            lines += [f"    - {address}" for address in other[:10]]
            if len(other) > 10:
                lines.append(f"    - and {len(other) - 10} more")
    else:
        allowed = {
            "drill-on": {("create", a) for a in DRILL_ADDRESSES} | {("update", ALERT_POLICY)},
            "drill-off": {("delete", a) for a in DRILL_ADDRESSES} | {("update", ALERT_POLICY)},
        }[mode]
        for action, addresses in acted.items():
            for address in addresses:
                if (action, address) not in allowed:
                    refused.append(f"the {mode} plan would also {action} {address}")
        if mode == "drill-on":
            function = next((r for r in resources if r["address"] == DRILL_FUNCTION), None)
            stops = None
            if function is not None:
                config = function.get("values", {}).get("service_config") or [{}]
                stops = (config[0].get("environment_variables") or {}).get("STOP_PROJECTS")
            if stops != scratch:
                refused.append(
                    f"the drill function would stop {stops or 'nothing known'}, "
                    f"not only the scratch project {scratch}"
                )
            else:
                lines.append(f"  The drill function stops {scratch} only.")

    if not refused:
        lines.append(
            "Safety: no service account key, no lock (the audit log lock stays off), "
            "no role for a person."
        )
    else:
        lines.append("NOT TO BE APPLIED:")
        lines += [f"  - {reason}" for reason in refused]
    return Summary(lines, refused)


def _main_rows(resources: list[dict[str, Any]]) -> list[str]:
    """The rows of the runbook's part 4: what exists after the apply, against what it says."""
    by_type = Counter(resource["type"] for resource in resources)
    values = {resource["address"]: resource.get("values", {}) for resource in resources}
    agents = sum(
        1
        for resource in resources
        if resource["type"] == "google_service_account"
        and str(resource.get("values", {}).get("account_id", "")).startswith("agent-")
    )
    rows = []
    rows.append(
        _row(
            by_type["google_org_policy_policy"] == 6,
            "organisation policies",
            f"{by_type['google_org_policy_policy']} (runbook: 6)",
        )
    )
    apis = Counter()
    for resource in resources:
        if resource["type"] == "google_project_service":
            address = resource["address"]
            project = (
                "control"
                if address.startswith("google_project_service.control")
                else address.split(".")[1]
            )
            apis[project] += 1
    rows.append(
        _row(
            dict(apis) == APIS,
            "APIs",
            f"{sum(apis.values())}: control {apis['control']}, agents {apis['agents']}, "
            f"gateway {apis['gateway']} (runbook: 17, 5, 7)",
        )
    )
    rows.append(
        _row(
            by_type["google_service_account"] == 5 + agents,
            "service accounts",
            f"{by_type['google_service_account']} (runbook: 5 + {agents} agent)",
        )
    )
    project_roles = by_type["google_project_iam_member"] - (
        1 if "module.control.google_project_iam_member.drill[0]" in values else 0
    )
    rows.append(
        _row(
            project_roles == 12 + agents,
            "roles on the projects",
            f"{project_roles} (runbook: 12 + {agents} agent)",
        )
    )
    names = sorted(
        str(resource.get("values", {}).get("name", ""))
        for resource in resources
        if resource["type"] == "google_storage_bucket"
    )
    rows.append(_row(len(names) == 3, "buckets", f"{len(names)}: {', '.join(names)}"))
    audit = [
        resource.get("values", {})
        for resource in resources
        if resource["type"] == "google_logging_project_bucket_config"
    ]
    audit_ok = (
        len(audit) == 1 and audit[0].get("retention_days") == 365 and not audit[0].get("locked")
    )
    rows.append(_row(audit_ok, "audit log bucket", "aiven-audit, 365 days, not locked"))
    rows.append(
        _row(
            by_type["google_firestore_database"] == 2,
            "Firestore databases",
            f"{by_type['google_firestore_database']} (control, gateway)",
        )
    )
    budgets = []
    for resource in resources:
        if resource["type"] == "google_billing_budget":
            budget = resource.get("values", {})
            amount = (budget.get("amount") or [{}])[0].get("specified_amount") or [{}]
            budgets.append(
                f"{budget.get('display_name')} {amount[0].get('units')} "
                f"{amount[0].get('currency_code')}"
            )
    rows.append(_row(len(budgets) == 2, "budgets", ", ".join(sorted(budgets))))
    functions = sorted(
        str(resource.get("values", {}).get("name", ""))
        for resource in resources
        if resource["type"] == "google_cloudfunctions2_function"
    )
    rows.append(
        _row(
            functions == ["budget-stop", "credit-reminder"],
            "functions",
            ", ".join(functions),
        )
    )
    rows.append(
        _row(
            by_type["google_cloud_scheduler_job"] == 1,
            "scheduler job",
            "credit-reminder, 20 December 09:00",
        )
    )
    channel = next(
        (
            resource.get("values", {}).get("labels", {}).get("email_address")
            for resource in resources
            if resource["type"] == "google_monitoring_notification_channel"
        ),
        None,
    )
    rows.append(
        _row(
            by_type["google_monitoring_alert_policy"] == 2 and channel is not None,
            "alerts",
            f"{by_type['google_monitoring_alert_policy']} alert policies, email to {channel}",
        )
    )
    return rows


# --- the result file


def clean_result(text: str) -> str:
    """The result text without a line that the content scan flags."""
    flagged = {hit.line for hit in scan(text)}
    lines = text.splitlines()
    return "".join(
        "[line left out: it looked like a secret]\n" if number in flagged else f"{line}\n"
        for number, line in enumerate(lines, start=1)
    )


# --- the command line


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aiven.m2_oneclick", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    reading = commands.add_parser("values-read")
    writing = commands.add_parser("values-write")
    writing.add_argument("pairs", nargs="*", metavar="name=value")
    for command in (reading, writing):
        command.add_argument(
            "--root",
            type=Path,
            default=Path("."),
            help="the folder that holds config/ and infra/terraform/ (default: here)",
        )
    summary = commands.add_parser("plan-summary")
    summary.add_argument("plan", type=Path)
    summary.add_argument("--mode", choices=["main", "drill-on", "drill-off"], default="main")
    summary.add_argument("--scratch")
    result = commands.add_parser("result-write")
    result.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "values-read":
            for name, value in read_values(args.root / TFVARS, args.root / PLATFORM).items():
                if name in FIELDS:
                    print(f"{name}={_shown(value)}")
            return EXIT_OK
        if args.command == "values-write":
            write_values(_parse_updates(args.pairs), args.root / TFVARS, args.root / PLATFORM)
            return EXIT_OK
        if args.command == "plan-summary":
            plan = json.loads(args.plan.read_text(encoding="utf-8"))
            done = summarize(plan, args.mode, args.scratch)
            print("\n".join(done.lines))
            return done.status
        args.path.write_text(clean_result(sys.stdin.read()), encoding="utf-8")
        return EXIT_OK
    except ValuesError as error:
        print(str(error), file=sys.stderr)
        return EXIT_ERROR
    except Exception as error:
        # The message of an error can quote an answer of Google or a file; its class cannot.
        print(f"{args.command} could not run ({type(error).__name__})", file=sys.stderr)
        return EXIT_CRASH


if __name__ == "__main__":
    sys.exit(main())
