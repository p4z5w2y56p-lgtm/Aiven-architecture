"""The budget stop (gateway-design section 9; runbook docs/runbooks/budget-stop.md).

Budget `aiven-stop` (25 in the billing account's currency, gross cost) publishes to Pub/Sub topic
`budget-stop` in control. Eventarc hands each message to `main`, a Cloud Run function in control
that runs as `budget-stop`. Cloud Billing sends a notification several times a day, whatever the
cost, so `handle` decides on each one (ruling R108):

- It writes one structured log line for every notification, not an audit entry, so the wiring can
  be checked without a stop.
- A notification of another budget: "ignored".
- One that cannot be read, or that is not in the currency of the budgets: "ignored", with an audit
  entry that has alert: true. The stop acts on an unambiguous stop only.
- A cost below the budget: "below".
- STOP_ENABLED is false (step 3 of the restart): "disabled".
- Billing is off already on every project of STOP_PROJECTS: "already_stopped". Notifications
  repeat, and a stop is done once.
- Otherwise billing is unlinked from each project that still has it, and a `budget_stop` audit
  entry with alert: true says so: "stopped".

When a project cannot be unlinked, the others are unlinked all the same, an alert entry is written,
and StopFailed is raised: Pub/Sub delivers the notification again, and the retry finishes the job.
When the audit log does not take an entry, the stop stands, because stopping is the safe direction,
and the log line raises the alert instead (alert: true; the alert policy reads the functions' own
log as well, Task 2.4; ruling R130).

The amounts are Decimals. `main` reads the JSON with `parse_float=Decimal`, and a float given to
`handle` is read through its shortest form, so 24.99 stays below 25.
"""

import base64
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal, Protocol

import functions_framework
from google.cloud import billing_v1

from aiven.common.audit import AuditEntry, AuditLog, AuditWriteFailed, AuditWriter
from aiven.policy.constants import PROJECT_ID_PATTERN
from aiven.policy.content import safe_text

Outcome = Literal["ignored", "below", "already_stopped", "stopped", "disabled"]

BUDGET = "aiven-stop"
CURRENCIES = ("EUR", "USD")
RUNBOOK = "budget-stop.md"
_PROJECT_ID = re.compile(PROJECT_ID_PATTERN)


class BillingApi(Protocol):
    """What the stop needs of Cloud Billing."""

    def billing_enabled(self, project: str) -> bool: ...

    def unlink(self, project: str) -> None: ...


class StopFailed(Exception):
    """Billing could not be unlinked from every project. Pub/Sub delivers the notification again."""


@dataclass(frozen=True)
class StopConfig:
    """What the stop acts on. `from_env` reads it from the function's environment (Terraform)."""

    projects: tuple[str, ...]
    enabled: bool
    currency: str
    budget_name: str = BUDGET
    actor: str | None = None
    audit_project: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "StopConfig":
        """STOP_PROJECTS, STOP_ENABLED, BUDGET_CURRENCY, AUDIT_PROJECT and AUDIT_ACTOR.

        Only `false` switches the stop off: anything else, or nothing, leaves it on.
        """
        projects = tuple(project.strip() for project in env.get("STOP_PROJECTS", "").split(","))
        if not all(_PROJECT_ID.fullmatch(project) for project in projects) or len(
            set(projects)
        ) != len(projects):
            raise ValueError("STOP_PROJECTS must be distinct project IDs, separated by commas")
        currency = env.get("BUDGET_CURRENCY", "")
        if currency not in CURRENCIES:
            raise ValueError(f"BUDGET_CURRENCY must be one of {', '.join(CURRENCIES)}")
        audit_project = env.get("AUDIT_PROJECT", "")
        if not _PROJECT_ID.fullmatch(audit_project):
            raise ValueError("AUDIT_PROJECT must be the project ID of the control project")
        return cls(
            projects=projects,
            enabled=env.get("STOP_ENABLED", "true").strip().lower() != "false",
            currency=currency,
            actor=env.get("AUDIT_ACTOR") or None,
            audit_project=audit_project,
        )


class CloudBilling:
    """BillingApi on the Cloud Billing API, as the account the function runs as. No key."""

    def __init__(self, client: Any = None) -> None:
        self._client = client if client is not None else billing_v1.CloudBillingClient()

    def billing_enabled(self, project: str) -> bool:
        info = self._client.get_project_billing_info(name=f"projects/{project}")
        return bool(info.billing_enabled)

    def unlink(self, project: str) -> None:
        # An empty billing account name unlinks the project (Google's guide to stopping usage).
        self._client.update_project_billing_info(
            name=f"projects/{project}",
            project_billing_info=billing_v1.ProjectBillingInfo(billing_account_name=""),
        )


@dataclass(frozen=True)
class _Notification:
    name: str
    cost: Decimal
    budget: Decimal
    currency: str


def _amount(value: object) -> Decimal | None:
    """An amount of a notification: a finite number of 0 or more. A bool is not a number here."""
    if isinstance(value, bool) or not isinstance(value, int | float | Decimal):
        return None
    amount = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    return amount if amount.is_finite() and amount >= 0 else None


def _read(notification: object) -> _Notification | str | None:
    """The notification; the name of its budget alone when that is all there is to read; or None."""
    if not isinstance(notification, Mapping):
        return None
    name = notification.get("budgetDisplayName")
    if not isinstance(name, str):
        return None
    cost = _amount(notification.get("costAmount"))
    budget = _amount(notification.get("budgetAmount"))
    currency = notification.get("currencyCode")
    if cost is None or budget is None or budget == 0 or not isinstance(currency, str):
        return name
    return _Notification(name, cost, budget, currency)


def _log(
    outcome: str,
    read: object,
    *,
    alert: bool = False,
    audit_failed: bool = False,
    errors: tuple[str, ...] = (),
) -> None:
    """The one log line of a notification, on stdout, which Cloud Logging reads as JSON.

    `errors` are the names of the classes of the errors of a failed unlink, never their messages.
    """
    severity = "ALERT" if alert else "ERROR" if outcome == "failed" else "INFO"
    line: dict[str, Any] = {
        "severity": severity,
        "message": "budget notification",
        "outcome": outcome,
        "budget": None,
        "cost": None,
        "budget_amount": None,
        "currency": None,
        "alert": alert,
        "audit_write_failed": audit_failed,
        "errors": list(errors),
    }
    if isinstance(read, str):
        line["budget"] = safe_text(read)
    elif isinstance(read, _Notification):
        line["budget"] = safe_text(read.name)
        line["cost"], line["budget_amount"] = safe_text(str(read.cost)), safe_text(str(read.budget))
        line["currency"] = safe_text(read.currency)
    print(json.dumps(line), flush=True)


def _write(audit: AuditWriter, cfg: StopConfig, **fields: Any) -> bool:
    """Write a budget_stop entry with an alert; False when it was not written.

    That is when the audit log did not take it, and also when the entry refused its note (a cost
    that reads like an ID number, say): the stop has been done by then, and stands either way.
    """
    try:
        audit.write(AuditEntry(event="budget_stop", actor=cfg.actor, alert=True, **fields))
    except (AuditWriteFailed, ValueError):
        return False
    return True


def handle(
    notification: object, cfg: StopConfig, billing: BillingApi, audit: AuditWriter
) -> Outcome:
    """Decide on one budget notification, and act on it (see the module)."""
    read = _read(notification)
    name = read.name if isinstance(read, _Notification) else read
    if isinstance(name, str) and name != cfg.budget_name:
        _log("ignored", read)  # another budget: its name decides, whatever the rest holds
        return "ignored"
    if not isinstance(read, _Notification):
        note = (
            f"A budget notification could not be read, so the budget stop did not act. Check "
            f"budget {cfg.budget_name} and its Pub/Sub topic."
        )
        return _ignore(read, cfg, audit, "MALFORMED_NOTIFICATION", note)
    if read.currency != cfg.currency:
        note = (
            f"A notification of budget {cfg.budget_name} was not in {cfg.currency}, so the budget "
            "stop did not act. Check the currency of the budgets."
        )
        return _ignore(read, cfg, audit, "CURRENCY_MISMATCH", note)
    if read.cost < read.budget:
        _log("below", read)
        return "below"
    if not cfg.enabled:
        _log("disabled", read)
        return "disabled"
    return _stop(read, cfg, billing, audit)


def _ignore(read: object, cfg: StopConfig, audit: AuditWriter, reason: str, note: str) -> Outcome:
    written = _write(audit, cfg, outcome="ignored", reason=reason, note=note)
    _log("ignored", read, alert=not written, audit_failed=not written)
    return "ignored"


def _stop(read: _Notification, cfg: StopConfig, billing: BillingApi, audit: AuditWriter) -> Outcome:
    unlinked = 0
    errors: list[str] = []
    for project in cfg.projects:
        try:
            if billing.billing_enabled(project):
                billing.unlink(project)
                unlinked += 1
        except Exception as error:
            # The others are stopped all the same; the retry tries this one again.
            errors.append(type(error).__name__)
    failed, total = len(errors), len(cfg.projects)
    spent = f"{read.cost} {cfg.currency} of {read.budget} {cfg.currency}"
    if failed:
        note = (
            f"Budget {cfg.budget_name} reached: {spent} this month. Billing could not be unlinked "
            f"from {failed} of {total} projects; Pub/Sub delivers the notification again."
        )
        written = _write(audit, cfg, outcome="failed", reason="UNLINK_FAILED", note=note)
        _log("failed", read, alert=not written, audit_failed=not written, errors=tuple(errors))
        raise StopFailed(f"billing could not be unlinked from {failed} of {total} projects")
    if unlinked == 0:
        _log("already_stopped", read)
        return "already_stopped"
    note = (
        f"Budget {cfg.budget_name} reached: {spent} this month. Billing was unlinked from "
        f"{unlinked} of {total} projects; restart with runbook {RUNBOOK}."
    )
    written = _write(audit, cfg, outcome="stopped", reason="BUDGET_EXCEEDED", note=note)
    _log("stopped", read, alert=not written, audit_failed=not written)
    return "stopped"


def _notification_of(cloud_event: Any) -> object:
    """The JSON of the Pub/Sub message in a CloudEvent, amounts as Decimals; None if unreadable."""
    try:
        raw = base64.b64decode(cloud_event.data["message"]["data"], validate=True)
        return json.loads(raw.decode("utf-8"), parse_float=Decimal)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None  # binascii.Error, UnicodeDecodeError and JSONDecodeError are ValueErrors


def _billing() -> BillingApi:
    return CloudBilling()


def _audit(project: str) -> AuditWriter:
    return AuditLog(project)


@functions_framework.cloud_event
def main(cloud_event: Any) -> Outcome:
    """The entry point: a Pub/Sub message of topic budget-stop, delivered by Eventarc."""
    cfg = StopConfig.from_env(os.environ)
    return handle(_notification_of(cloud_event), cfg, _billing(), _audit(str(cfg.audit_project)))
