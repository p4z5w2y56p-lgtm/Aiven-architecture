"""The credit reminder (gateway-design section 14; plan Task 2.4; ruling R109).

Cloud Scheduler job `credit-reminder` calls this function at 09:00 Europe/Amsterdam on the day of
`credit_alert_date` (2026-12-20), with an OIDC token of the account `credit-reminder`. The function
writes one `control` audit entry with alert: true, whose note is the reminder, and the alert policy
emails it to Matthijs (Task 2.4).

A cron schedule comes back every year. So the reminder is written only while the day in
Europe/Amsterdam is not after CREDIT_EXPIRY (2027-01-04); a later run writes a log line and nothing
else. A run by hand before then (`gcloud scheduler jobs run credit-reminder`) delivers the email:
that is the test of the whole alert path.

When the audit log does not take the reminder, the function answers 500, so that Cloud Scheduler
tries again, and its log line carries alert: true, which the alert policy reads as well (R130).
"""

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal
from zoneinfo import ZoneInfo

import functions_framework

from aiven.common.audit import AuditEntry, AuditLog, AuditWriteFailed, AuditWriter
from aiven.policy.constants import PROJECT_ID_PATTERN

Outcome = Literal["reminded", "expired"]

REASON = "CREDIT_EXPIRY"
AMSTERDAM = ZoneInfo("Europe/Amsterdam")
_PROJECT_ID = re.compile(PROJECT_ID_PATTERN)
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def reminder_text(expiry: date) -> str:
    """The note of the reminder: the text of plan Task 2.4, for the day the credit ends."""
    return (
        f"Google Cloud credit expires on {expiry.isoformat()} (\N{EURO SIGN}252.56 at the "
        "upgrade). Check what is left; from then on all usage is billed."
    )


@dataclass(frozen=True)
class ReminderConfig:
    """The day the credit ends, and the audit log. `from_env` reads them (Terraform sets them)."""

    expiry: date
    actor: str | None
    audit_project: str

    @classmethod
    def from_env(cls, env: Any) -> "ReminderConfig":
        """CREDIT_EXPIRY (YYYY-MM-DD), AUDIT_PROJECT and AUDIT_ACTOR."""
        text = env.get("CREDIT_EXPIRY", "")
        try:
            if not _ISO_DATE.fullmatch(text):
                raise ValueError
            expiry = date.fromisoformat(text)
        except ValueError:
            raise ValueError("CREDIT_EXPIRY must be a date, YYYY-MM-DD") from None
        project = env.get("AUDIT_PROJECT", "")
        if not _PROJECT_ID.fullmatch(project):
            raise ValueError("AUDIT_PROJECT must be the project ID of the control project")
        return cls(expiry=expiry, actor=env.get("AUDIT_ACTOR") or None, audit_project=project)


def _today(now: datetime | None = None) -> date:
    """The day in Europe/Amsterdam, now or at `now`."""
    return (now or datetime.now(UTC)).astimezone(AMSTERDAM).date()


def _log(outcome: str, *, alert: bool = False, audit_failed: bool = False) -> None:
    """One log line per run, on stdout, which Cloud Logging reads as JSON."""
    line = {
        "severity": "ALERT" if alert else "INFO",
        "message": "credit reminder",
        "outcome": outcome,
        "alert": alert,
        "audit_write_failed": audit_failed,
    }
    print(json.dumps(line), flush=True)


def remind(today: date, cfg: ReminderConfig, audit: AuditWriter) -> Outcome:
    """Write the reminder while the credit lasts. Raises AuditWriteFailed when it was not taken."""
    if today > cfg.expiry:
        _log("expired")
        return "expired"
    entry = AuditEntry(
        event="control", actor=cfg.actor, reason=REASON, alert=True, note=reminder_text(cfg.expiry)
    )
    audit.write(entry)
    _log("reminded")
    return "reminded"


def _audit(project: str) -> AuditWriter:
    return AuditLog(project)


@functions_framework.http
def main(request: Any) -> tuple[str, int]:
    """The entry point: a POST from Cloud Scheduler, with an OIDC token of credit-reminder."""
    cfg = ReminderConfig.from_env(os.environ)
    try:
        outcome = remind(_today(), cfg, _audit(cfg.audit_project))
    except AuditWriteFailed:
        _log("failed", alert=True, audit_failed=True)
        return "the audit log did not take the reminder", 500
    return outcome, 200
