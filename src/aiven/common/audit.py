"""The audit log (gateway-design section 5): one entry per event, in log `aiven-audit` of control.

The gateway, the control UI and both functions write it through `AuditLog`, and through nothing
else. Cloud Logging routes the log to the log bucket `aiven-audit` (365 days) and keeps it out of
`_Default` (infra/terraform/modules/control/stores.tf).

`AuditEntry` holds exactly the fields of the entry in section 5; on `run_end` also `usage`,
`cost_estimate_eur` and `end_reason`; and `note`, a fixed text of the system for an entry that a
person reads in an alert email: the credit reminder, the budget stop (ruling R107). Any other field
is a ValueError. An entry holds IDs and hashes, never file content, file names or email text; the
one free text, the note, is refused when `content.is_sensitive` sees a credential, a bank detail or
an ID number in it.

`AuditLog(project).write(entry)` makes one synchronous write with the Cloud Logging client, and
raises AuditWriteFailed when the entry was not taken. The gateway then refuses the call it was
about to make (fail closed).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol

from aiven.policy.constants import PROJECT_ID_PATTERN
from aiven.policy.content import is_sensitive, safe_text

AUDIT_LOG = "aiven-audit"

EVENTS = (
    "run_start",
    "call_start",
    "call",
    "decision",
    "run_end",
    "policy_load",
    "control",
    "budget_stop",
)
CLASSES = ("R0", "R1", "R2", "R3", "R4")

_RUN_END_ONLY = ("usage", "cost_estimate_eur", "end_reason")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_PROJECT_ID = re.compile(PROJECT_ID_PATTERN)


def _now() -> str:
    """The time now in UTC, as `2026-10-12T09:15:02.123Z`."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True, init=False)
class AuditEntry:
    """One entry of the audit log. Make it with keywords; `class_` is the field `class`.

    The fields are in the order of the example in gateway-design section 5, and `payload` writes
    them in that order, null where there is no value. The three fields of `run_end` and `note` are
    written only when they have a value.
    """

    event: str
    ts: str = ""  # now, when not given
    agent: str | None = None
    actor: str | None = None
    run_id: str | None = None
    call_id: str | None = None
    action: str | None = None
    class_: str | None = None
    outcome: str | None = None
    reason: str | None = None
    approver: str | None = None
    policy_hash: str | None = None
    catalog_hash: str | None = None
    tainted: bool = False
    taint_sources: tuple[str, ...] = field(default=())
    snapshot: str | None = None
    confirm_id: str | None = None
    args_sha256: str | None = None
    alert: bool = False
    usage: Mapping[str, Any] | None = None
    cost_estimate_eur: Decimal | None = None
    end_reason: str | None = None
    note: str | None = None

    def __init__(self, **values: Any) -> None:
        names = [each.name for each in fields(self)]
        unknown = sorted(set(values) - set(names))
        if unknown:
            shown = safe_text(", ".join(unknown))
            raise ValueError(f"an audit entry has no field {shown} (gateway-design section 5)")
        if "event" not in values:
            raise ValueError("an audit entry needs its event")
        for each in fields(self):
            value = values.get(each.name, each.default)
            object.__setattr__(self, each.name, value)
        if not values.get("ts"):
            object.__setattr__(self, "ts", _now())
        if isinstance(self.taint_sources, list):
            object.__setattr__(self, "taint_sources", tuple(self.taint_sources))
        self._check()

    def _check(self) -> None:
        if self.event not in EVENTS:
            raise ValueError(f"event must be one of {', '.join(EVENTS)}")
        if not (isinstance(self.ts, str) and _TS.fullmatch(self.ts)):
            raise ValueError("ts must be a UTC time to the millisecond: 2026-10-12T09:15:02.123Z")
        if self.class_ is not None and self.class_ not in CLASSES:
            raise ValueError(f"class must be one of {', '.join(CLASSES)}, or none")
        for name in ("tainted", "alert"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be true or false")
        if not (
            isinstance(self.taint_sources, tuple)
            and all(isinstance(source, str) for source in self.taint_sources)
        ):
            raise ValueError("taint_sources must be a list of file IDs")
        for each in fields(self):
            value = getattr(self, each.name)
            if each.type == str | None and value is not None and not isinstance(value, str):
                raise ValueError(f"{each.name.rstrip('_')} must be a string, or none")
        if self.event != "run_end":
            for name in _RUN_END_ONLY:
                if getattr(self, name) is not None:
                    raise ValueError(f"{name} belongs to a run_end entry only")
        if self.usage is not None and not isinstance(self.usage, Mapping):
            raise ValueError("usage must be a mapping: model, input and output tokens")
        if self.cost_estimate_eur is not None and not isinstance(self.cost_estimate_eur, Decimal):
            raise ValueError("cost_estimate_eur must be a Decimal")
        if self.note is not None and is_sensitive(self.note):
            # The note is not repeated: what it holds is what must stay out of the log.
            raise ValueError(
                "the note holds what looks like a credential, a bank detail or an ID number"
            )

    def payload(self) -> dict[str, Any]:
        """The entry as the jsonPayload of the log entry."""
        payload: dict[str, Any] = {}
        for each in fields(self):
            name, value = each.name, getattr(self, each.name)
            if name in (*_RUN_END_ONLY, "note") and value is None:
                continue
            if name == "taint_sources":
                value = list(value)
            elif name == "usage":
                value = dict(value)
            elif name == "cost_estimate_eur":
                value = float(value)
            payload["class" if name == "class_" else name] = value
        return payload


class AuditWriteFailed(Exception):
    """The audit log did not take an entry. The message names the error's class only."""


class AuditWriter(Protocol):
    """What writes an audit entry: `AuditLog`, or a stand-in in a test."""

    def write(self, entry: AuditEntry) -> None: ...


def _logging_client(project: str) -> Any:
    """A Cloud Logging client for `project`, with the account the code runs as. No key."""
    from google.cloud import logging as cloud_logging

    return cloud_logging.Client(project=project)


class AuditLog:
    """The audit log of the control project. `write` takes one entry, synchronously."""

    def __init__(self, project: str, client: Any = None) -> None:
        if not (isinstance(project, str) and _PROJECT_ID.fullmatch(project)):
            raise ValueError("the audit log needs the project ID of the control project")
        self.project = project
        self._client = client

    def write(self, entry: AuditEntry) -> None:
        """Write `entry` to log aiven-audit. Raises AuditWriteFailed when it was not taken."""
        try:
            if self._client is None:
                self._client = _logging_client(self.project)
            logger = self._client.logger(AUDIT_LOG)
            logger.log_struct(entry.payload(), severity="ALERT" if entry.alert else "INFO")
        except Exception as error:
            # The class of the error says enough, and its message stays out of what is shown.
            raise AuditWriteFailed(
                f"the audit log did not take the entry ({type(error).__name__})"
            ) from error
