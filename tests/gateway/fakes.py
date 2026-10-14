"""Stand-ins for the gateway's tests: an in-memory working store (plan Task 3.1).

`FakeStore` keeps each collection of section 5 as a dict of documents, the way Firestore holds
them, so `raw(collection, doc_id)` shows what a document holds (its `expire_at`, say). One lock
makes every method one atomic step, which is what the contract asks of the real store.
"""

import copy
import threading
from collections import Counter
from dataclasses import asdict, fields
from typing import Any

from aiven.gateway.store import (
    CONFIRM_ERASE_AFTER,
    WORKING_TTL,
    Clock,
    call_id_for,
    check_limits,
    may_set_active,
    utc_now,
)
from aiven.gateway.types import (
    PENDING,
    ConfirmRecord,
    DayCounters,
    RunState,
    ShadowState,
    StoredCall,
)
from aiven.policy.model import Limits
from aiven.policy.verify import ActiveVersion

_RUN_FIELDS = {each.name for each in fields(RunState)}


class FakeStore:
    """The working store in memory. See the module docstring."""

    def __init__(self, clock: Clock = utc_now) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._docs: dict[str, dict[str, dict[str, Any]]] = {}

    def raw(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            found = self._docs.get(collection, {}).get(doc_id)
            return copy.deepcopy(found)

    def _col(self, name: str) -> dict[str, dict[str, Any]]:
        return self._docs.setdefault(name, {})

    # --- runs

    def create_run(self, run: RunState) -> None:
        with self._lock:
            doc = asdict(run) | {"expire_at": run.started_at + WORKING_TTL}
            self._col("runs")[run.run_id] = doc

    def get_run(self, run_id: str) -> RunState | None:
        with self._lock:
            return self._run(run_id)

    def _run(self, run_id: str) -> RunState | None:
        doc = self._col("runs").get(run_id)
        if doc is None:
            return None
        values = {name: doc[name] for name in _RUN_FIELDS}
        values["taint_sources"] = tuple(values["taint_sources"])
        return RunState(**values)

    def update_run(self, run_id: str, **changes: Any) -> None:
        unknown = set(changes) - _RUN_FIELDS
        if unknown:
            raise ValueError(f"a run has no field {sorted(unknown)}")
        with self._lock:
            self._col("runs")[run_id].update(changes)

    def taint_run(self, run_id: str, sources: tuple[str, ...]) -> None:
        with self._lock:
            doc = self._col("runs")[run_id]
            known = list(doc["taint_sources"])
            known += [source for source in sources if source not in known]
            doc.update(tainted=True, taint_sources=tuple(known))

    def count_refusal(self, run_id: str) -> int:
        with self._lock:
            doc = self._col("runs")[run_id]
            doc["refusals"] += 1
            return doc["refusals"]

    # --- the day counters and the limits

    def _counters(self, agent: str, day: str) -> dict[str, Any]:
        return self._col("counters").setdefault(
            f"{agent}_{day}", {"runs": 0, "email_recipients": 0}
        )

    def reserve_run(self, agent: str, day: str, runs_per_day: int) -> bool:
        with self._lock:
            counters = self._counters(agent, day)
            if counters["runs"] + 1 > runs_per_day:
                return False
            counters["runs"] += 1
            return True

    def reserve(
        self, run_id: str, agent: str, day: str, records: int, recipients: int, limits: Limits
    ) -> str | None:
        with self._lock:
            run = self._col("runs")[run_id]
            counters = self._counters(agent, day)
            crossed = check_limits(
                run["records_used"], records, counters["email_recipients"], recipients, limits
            )
            if crossed is None:
                run["records_used"] += records
                counters["email_recipients"] += recipients
            return crossed

    def day_counters(self, agent: str, day: str) -> DayCounters:
        with self._lock:
            doc = self._col("counters").get(f"{agent}_{day}", {})
            return DayCounters(doc.get("runs", 0), doc.get("email_recipients", 0))

    # --- calls

    def claim_call(self, run_id: str, request_id: str) -> tuple[str, StoredCall | None]:
        call_id = call_id_for(run_id, request_id)
        with self._lock:
            calls = self._col("calls")
            if call_id in calls:
                return call_id, self._stored(calls[call_id])
            calls[call_id] = {
                "run_id": run_id,
                "call_id": call_id,
                "outcome": PENDING,
                "reason": None,
                "result": None,
                "cls": None,
                "confirm_id": None,
                "tainted": False,
                "expire_at": self._clock() + WORKING_TTL,
            }
            return call_id, None

    @staticmethod
    def _stored(doc: dict[str, Any]) -> StoredCall:
        return StoredCall(
            call_id=doc["call_id"],
            outcome=doc["outcome"],
            reason=doc["reason"],
            result=copy.deepcopy(doc["result"]),
            cls=doc["cls"],
            confirm_id=doc["confirm_id"],
            tainted=doc["tainted"],
        )

    def get_call(self, run_id: str, request_id: str) -> StoredCall | None:
        with self._lock:
            doc = self._col("calls").get(call_id_for(run_id, request_id))
            return None if doc is None else self._stored(doc)

    def put_call(
        self, run_id: str, request_id: str, call: StoredCall, meta: dict[str, Any]
    ) -> None:
        with self._lock:
            self._col("calls")[call.call_id] = (
                copy.deepcopy(meta)
                | asdict(call)
                | {"run_id": run_id, "expire_at": self._clock() + WORKING_TTL}
            )

    def calls_by_outcome(self, run_id: str) -> dict[str, int]:
        with self._lock:
            return dict(
                Counter(
                    doc["outcome"]
                    for doc in self._col("calls").values()
                    if doc["run_id"] == run_id and doc["outcome"] != PENDING
                )
            )

    # --- confirms and proposals

    def put_confirm(self, confirm: ConfirmRecord) -> None:
        with self._lock:
            self._col("confirms")[confirm.confirm_id] = copy.deepcopy(asdict(confirm))

    def get_confirm(self, confirm_id: str) -> ConfirmRecord | None:
        with self._lock:
            doc = self._col("confirms").get(confirm_id)
            if doc is None:
                return None
            values = {each.name: copy.deepcopy(doc[each.name]) for each in fields(ConfirmRecord)}
            values["taint_sources"] = tuple(values["taint_sources"])
            return ConfirmRecord(**values)

    def close_confirm(
        self, confirm_id: str, allowed: tuple[str, ...], status: str, now: Any
    ) -> bool:
        with self._lock:
            doc = self._col("confirms").get(confirm_id)
            if doc is None or doc["status"] not in allowed:
                return False
            doc["status"] = status
            doc["erase_at"] = now + CONFIRM_ERASE_AFTER
            return True

    def put_proposal(self, call_id: str, run_id: str, agent: str, preview: dict[str, str]) -> None:
        with self._lock:
            self._col("proposals")[call_id] = {
                "run_id": run_id,
                "agent": agent,
                "preview": dict(preview),
                "at": self._clock(),
            }

    # --- shadow and the active version

    def get_shadow(self, agent: str) -> ShadowState | None:
        with self._lock:
            doc = self._col("shadow").get(agent)
            if doc is None:
                return None
            return ShadowState(doc["runs"], tuple(doc["tools"]), doc["max_class"])

    def inc_shadow_runs(self, agent: str, tools: tuple[str, ...], max_class: Any) -> int:
        with self._lock:
            doc = self._col("shadow").setdefault(agent, {"runs": 0})
            doc.update(runs=doc["runs"] + 1, tools=tuple(tools), max_class=max_class)
            return doc["runs"]

    def get_active(self, agent: str) -> ActiveVersion | None:
        with self._lock:
            doc = self._col("active").get(agent)
            return None if doc is None else ActiveVersion(doc["version"], doc["sha256"])

    def set_active(self, agent: str, active: ActiveVersion) -> bool:
        with self._lock:
            doc = self._col("active").get(agent)
            current = None if doc is None else ActiveVersion(doc["version"], doc["sha256"])
            if not may_set_active(current, active):
                return False
            self._col("active")[agent] = {"version": active.version, "sha256": active.sha256}
            return True
