"""The gateway's working store (plan Task 3.1; gateway-design section 5, Firestore `gateway`).

Working state only: lost, it is rebuilt empty. `FirestoreStore` (store_firestore.py) is the store
of the deployment, and tests/gateway/fakes.py holds an in-memory one; one contract suite runs
against both (tests/gateway/test_store_contract.py).

Everything that two calls of one run could race for is one atomic step of the store:

- `reserve_run`: a run of the day, up to `runs_per_day`.
- `reserve`: records of the run and email recipients of the day, both or neither, never past
  `records_per_run` or `emails_per_day` (review focus 1). It names the limit it would cross.
- `claim_call`: the first request of a `request_id` claims the call; every other one gets the
  stored answer, or "pending" while the first is still in flight (gateway-design section 4).
- `count_refusal`, `taint_run`: counters and sets that only grow.
- `close_confirm`: a confirm leaves `pending` once.
- `set_active`: the high-water mark of an agent's policy version, which never goes down.

Runs and calls carry `expire_at` = now + 90 days, for Firestore's TTL (ruling R106); a confirm
carries `erase_at` = closing + 7 days once it closes (section 13).
"""

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from aiven.gateway.types import (
    Class,
    ConfirmRecord,
    ConfirmStatus,
    DayCounters,
    RunState,
    ShadowState,
    StoredCall,
)
from aiven.policy.model import Limits
from aiven.policy.verify import ActiveVersion

# Section 13: runs and calls are kept 90 days; a closed confirm's args and previews 7 days.
WORKING_TTL = timedelta(days=90)
CONFIRM_ERASE_AFTER = timedelta(days=7)

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


def call_id_for(run_id: str, request_id: str) -> str:
    """The ID of the call that `request_id` asks for in `run_id`: `c_` and 32 hex digits.

    It is derived, so the second request with the same ID finds the first call without a query.
    The request ID is the agent's own text, and never becomes a document ID as it is.
    """
    digest = hashlib.sha256(f"{run_id}\x00{request_id}".encode()).hexdigest()
    return "c_" + digest[:32]


class Store(Protocol):
    """What the gateway keeps in its working store. See the module docstring."""

    def create_run(self, run: RunState) -> None: ...

    def get_run(self, run_id: str) -> RunState | None: ...

    def update_run(self, run_id: str, **fields: Any) -> None: ...

    def taint_run(self, run_id: str, sources: tuple[str, ...]) -> None: ...

    def count_refusal(self, run_id: str) -> int: ...

    def reserve_run(self, agent: str, day: str, runs_per_day: int) -> bool: ...

    def reserve(
        self, run_id: str, agent: str, day: str, records: int, recipients: int, limits: Limits
    ) -> str | None: ...

    def day_counters(self, agent: str, day: str) -> DayCounters: ...

    def claim_call(self, run_id: str, request_id: str) -> tuple[str, StoredCall | None]: ...

    def get_call(self, run_id: str, request_id: str) -> StoredCall | None: ...

    def put_call(
        self, run_id: str, request_id: str, call: StoredCall, meta: dict[str, Any]
    ) -> None: ...

    def calls_by_outcome(self, run_id: str) -> dict[str, int]: ...

    def put_confirm(self, confirm: ConfirmRecord) -> None: ...

    def get_confirm(self, confirm_id: str) -> ConfirmRecord | None: ...

    def close_confirm(
        self, confirm_id: str, allowed: tuple[str, ...], status: ConfirmStatus, now: datetime
    ) -> bool: ...

    def put_proposal(
        self, call_id: str, run_id: str, agent: str, preview: dict[str, str]
    ) -> None: ...

    def get_shadow(self, agent: str) -> ShadowState | None: ...

    def inc_shadow_runs(self, agent: str, tools: tuple[str, ...], max_class: Class) -> int: ...

    def get_active(self, agent: str) -> ActiveVersion | None: ...

    def set_active(self, agent: str, active: ActiveVersion) -> bool: ...


def check_limits(
    records_used: int,
    records: int,
    recipients_today: int,
    recipients: int,
    limits: Limits,
) -> str | None:
    """The limit that taking `records` and `recipients` would cross, or None (both stores use it)."""
    if records_used + records > limits.records_per_run:
        return "LIMIT_RECORDS"
    if recipients_today + recipients > limits.emails_per_day:
        return "LIMIT_EMAILS"
    return None


def may_set_active(current: ActiveVersion | None, new: ActiveVersion) -> bool:
    """Whether `new` may be the high-water mark after `current`: a higher version, or the same."""
    if current is None or new.version > current.version:
        return True
    return new == current
