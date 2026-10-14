"""The gateway's own types (plan Task 3.1; gateway-design sections 4 and 5).

A run, a call, a confirm and the counters as the working store holds them. Nothing here holds
content: a call keeps its outcome and IDs, and the result of a write (its new IDs), never what an
agent read (section 5, ruling R171).
"""

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal, get_args

Class = Literal["R0", "R1", "R2", "R3", "R4"]
CLASSES: tuple[Class, ...] = get_args(Class)

RunStatus = Literal["open", "ended", "stopped"]
ConfirmStatus = Literal["pending", "approved", "rejected", "expired", "executed", "failed"]

# What a call can come to (section 4), and "pending" while its first request is still in flight.
Outcome = Literal["executed", "proposed", "queued", "refused"]
PENDING = "pending"


@dataclass(frozen=True)
class Caller:
    """Who calls: the email of a verified Google ID token, and which API it may use (section 4).

    `kind` is "control" for the control UI's account and "agent" for every other account; an agent
    still needs a policy whose `principal` is its email.
    """

    email: str
    kind: Literal["agent", "control"]


def rank(cls: Class) -> int:
    """The order of the classes: R0 < R1 < R2 < R3 < R4."""
    return CLASSES.index(cls)


@dataclass(frozen=True)
class RunState:
    """One run: `runs/{run_id}` of the working store (section 5)."""

    run_id: str
    agent: str
    policy_sha256: str
    catalog_sha256: str
    started_at: datetime
    deadline: datetime
    status: RunStatus
    stop_reason: str | None
    shadow: bool
    tainted: bool
    taint_sources: tuple[str, ...]
    records_used: int
    refusals: int


@dataclass(frozen=True)
class Refusal:
    """A refusal before a call or a run exists: the reason code of section 4, and whether it alerts."""

    reason: str
    alert: bool = False


@dataclass(frozen=True)
class StoredCall:
    """The answer to one call, kept so that a retry with the same `request_id` gets it again.

    `outcome` is "pending" while the first request is still being handled. `result` is kept for a
    write only (its new IDs), never for a read: the working store holds no content (R171).
    """

    call_id: str
    outcome: str
    reason: str | None
    result: dict[str, Any] | None
    cls: Class | None = None
    confirm_id: str | None = None
    tainted: bool = False


@dataclass(frozen=True)
class RunSummary:
    """What `POST /v1/runs/{run_id}:end` answers (section 4)."""

    run_id: str
    calls_by_outcome: dict[str, int]
    records_used: int
    tainted: bool
    cost_estimate_eur: Decimal | None


@dataclass(frozen=True)
class DayCounters:
    """`counters/{agent}_{date}`: runs and email recipients of one day in Europe/Amsterdam."""

    runs: int
    email_recipients: int


@dataclass(frozen=True)
class ShadowState:
    """`shadow/{agent}`: the shadow runs done, and the capability they cover (section 5)."""

    runs: int
    tools: tuple[str, ...]
    max_class: Class


@dataclass(frozen=True)
class ConfirmRecord:
    """`confirms/{confirm_id}`: a queued R2 call, waiting for a decision in control (section 7).

    `target` is what the wrapper saw of the target when the preview was made (its revision, say),
    so that `:apply` can tell that it changed (STALE_TARGET).
    """

    confirm_id: str
    run_id: str
    call_id: str
    agent: str
    action: str
    cls: Class
    args: dict[str, Any] = field(repr=False)
    target: dict[str, Any] = field(repr=False)
    preview_en: str = field(repr=False)
    preview_nl: str = field(repr=False)
    preview_sha256: str
    taint_sources: tuple[str, ...]
    status: ConfirmStatus
    created_at: datetime
    expires_at: datetime
