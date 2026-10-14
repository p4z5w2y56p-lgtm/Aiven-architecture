"""The decision function (plan Task 3.2; validator-spec section 4, gateway-design section 6).

`decide` takes what the gateway knows about one call and gives one Decision. It reads nothing and
writes nothing: the pipeline (pipeline.py) reads the control switches, classifies the call with the
wrapper, reserves the limits and writes the audit log around it. The first matching step wins:

1. A kill switch is on, globally or for the agent: KILL_SWITCH.
2. The run is not open: RUN_CLOSED. The deadline has passed: LIMIT_RUNTIME, and the run ends.
3. The call is in a reserved namespace, or its class is R4: RESERVED_R4, alert. It matches the
   policy's `forbidden` or the platform's baseline: FORBIDDEN, alert. (The baseline is on every
   policy by the validator's rules; it is checked here again, because a catalog or validator bug
   must not open it.)
4. The action is not in `tools` (an action the catalog does not know is not either): NOT_GRANTED.
5. The wrapper is switched off for the agent: WRAPPER_DISABLED.
6. The class is R3: R3_DISABLED.
7. The effective class (after escalation, a shared file making R1 into R2) is above `max_class`:
   ABOVE_MAX_CLASS.
8. The call is outside `scope`: OUT_OF_SCOPE.
9. The call would cross `records_per_run`: LIMIT_RECORDS; `emails_per_day`: LIMIT_EMAILS. Both end
   the run. (The store's reservation is the binding check; this one refuses early.)
10. The run is in shadow mode and the class is R1 or higher: propose.
11. R0: execute. R1: queue when the policy is `strict` and the run is tainted, else execute with a
    snapshot first. R2: queue.

The policy refusals (3, 4, 6, 7 and 8) count: the third in a run ends it and alerts, whatever the
step (an agent probing for tools is a sign of injection, section 6). `run.refusals` is the count
before this call; the pipeline counts atomically in the store, and its count is the binding one.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from aiven.gateway.types import Class, DayCounters, RunState, rank
from aiven.policy.catalog import matches
from aiven.policy.constants import FORBIDDEN_BASELINE
from aiven.policy.model import Policy

POLICY_REFUSALS = frozenset(
    {"FORBIDDEN", "RESERVED_R4", "NOT_GRANTED", "R3_DISABLED", "ABOVE_MAX_CLASS", "OUT_OF_SCOPE"}
)
REFUSALS_BEFORE_STOP = 3  # gateway-design section 13

DecisionOutcome = Literal["execute", "propose", "queue", "refuse"]


@dataclass(frozen=True)
class Classification:
    """A call as the wrapper classes it (catalog, escalation, smuggled fields).

    `action` is the id after reclassification: an update that trashes a file is `drive.delete`.
    `cls` is the catalog's class, None for an action the catalog does not know; `effective_cls` is
    the class after escalation. `reserved` says the action is in a reserved namespace.
    """

    action: str
    cls: Class | None
    effective_cls: Class | None
    in_scope: bool
    records: int
    email_recipients: int
    taint_sources: tuple[str, ...]
    reserved: bool


@dataclass(frozen=True)
class ControlSnapshot:
    """The switches in control, read on every call (section 8)."""

    kill_global: bool
    kill_agent: bool
    wrapper_enabled: bool


@dataclass(frozen=True)
class Decision:
    """What happens to the call. `snapshot`: an R1 that executes takes its snapshot first."""

    outcome: DecisionOutcome
    reason: str | None
    cls: Class | None
    alert: bool
    end_run: bool
    snapshot: bool


def decide(
    p: Policy,
    ctl: ControlSnapshot,
    run: RunState,
    c: Classification,
    day: DayCounters,
    now: datetime,
) -> Decision:
    """The decision on one call. See the module docstring."""
    cls = c.effective_cls

    def refuse(reason: str, *, alert: bool = False, end_run: bool = False) -> Decision:
        if reason in POLICY_REFUSALS and run.refusals + 1 >= REFUSALS_BEFORE_STOP:
            alert = end_run = True
        return Decision("refuse", reason, cls, alert, end_run, False)

    if ctl.kill_global or ctl.kill_agent:
        return refuse("KILL_SWITCH")
    if run.status != "open":
        return refuse("RUN_CLOSED")
    if now >= run.deadline:
        return refuse("LIMIT_RUNTIME", end_run=True)
    if c.reserved or cls == "R4":
        return refuse("RESERVED_R4", alert=True)
    if any(matches(pattern, c.action) for pattern in (*p.forbidden, *FORBIDDEN_BASELINE)):
        return refuse("FORBIDDEN", alert=True)
    if c.action not in p.tools or cls is None:
        return refuse("NOT_GRANTED")
    if not ctl.wrapper_enabled:
        return refuse("WRAPPER_DISABLED")
    if cls == "R3":
        return refuse("R3_DISABLED")
    if rank(cls) > rank(p.max_class):
        return refuse("ABOVE_MAX_CLASS")
    if not c.in_scope:
        return refuse("OUT_OF_SCOPE")
    if run.records_used + c.records > p.limits.records_per_run:
        return refuse("LIMIT_RECORDS", end_run=True)
    if day.email_recipients + c.email_recipients > p.limits.emails_per_day:
        return refuse("LIMIT_EMAILS", end_run=True)
    if run.shadow and cls != "R0":
        return Decision("propose", None, cls, False, False, False)
    if cls == "R0":
        return Decision("execute", None, cls, False, False, False)
    if cls == "R1" and not (p.untrusted_input == "strict" and run.tainted):
        return Decision("execute", None, cls, False, False, True)
    return Decision("queue", None, cls, False, False, False)
