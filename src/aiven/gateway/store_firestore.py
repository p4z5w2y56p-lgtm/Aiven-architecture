"""The working store on Firestore `gateway` (plan Task 3.1; see store.py for the contract).

Every step that two calls could race for runs in one Firestore transaction, which Firestore retries
when another transaction touched the same documents. A transaction that runs out of attempts
raises, and the gateway refuses the call: fail closed, never past a limit.

Within one instance, the steps on one document also take a lock of that document first (ruling
R172). The calls of a run all contend for one run document and one counter; with twenty at once,
Firestore aborts them against each other until some run out of attempts (seen on the emulator), and
those calls would be refused although the limit had room. With the lock, only the instances contend
in Firestore, and Cloud Run runs at most two (section 13).
"""

import threading
from collections import defaultdict
from contextlib import ExitStack
from datetime import datetime
from typing import Any

from google.cloud import firestore

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

_ATTEMPTS = 50

_RUN_FIELDS = tuple(RunState.__dataclass_fields__)
_CONFIRM_FIELDS = tuple(ConfirmRecord.__dataclass_fields__)


def _run_of(doc: dict[str, Any]) -> RunState:
    values = {name: doc[name] for name in _RUN_FIELDS}
    values["taint_sources"] = tuple(values["taint_sources"])
    return RunState(**values)


def _call_of(doc: dict[str, Any]) -> StoredCall:
    return StoredCall(
        call_id=doc["call_id"],
        outcome=doc["outcome"],
        reason=doc.get("reason"),
        result=doc.get("result"),
        cls=doc.get("cls"),
        confirm_id=doc.get("confirm_id"),
        tainted=doc.get("tainted", False),
    )


def _call_doc(call: StoredCall) -> dict[str, Any]:
    return {
        "call_id": call.call_id,
        "outcome": call.outcome,
        "reason": call.reason,
        "result": call.result,
        "cls": call.cls,
        "confirm_id": call.confirm_id,
        "tainted": call.tainted,
    }


class FirestoreStore:
    """The working store of the deployment: Firestore database `gateway` of the gateway project."""

    def __init__(self, client: Any, clock: Clock = utc_now) -> None:
        self._db = client
        self._clock = clock
        self._guard = threading.Lock()
        self._locks: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)

    def _doc(self, collection: str, doc_id: str) -> Any:
        return self._db.collection(collection).document(doc_id)

    def _transaction(self) -> Any:
        return self._db.transaction(max_attempts=_ATTEMPTS)

    def _locked(self, *refs: Any) -> ExitStack:
        """Hold the lock of each document of `refs`, always in the same order (no deadlock)."""
        stack = ExitStack()
        with self._guard:
            locks = [self._locks[path] for path in sorted({ref.path for ref in refs})]
        for lock in locks:
            stack.enter_context(lock)
        return stack

    def _run_step(self, step: Any, *refs: Any) -> Any:
        """Run the transactional `step` under the locks of `refs` (ruling R172)."""
        with self._locked(*refs):
            return step(self._transaction())

    # --- runs

    def create_run(self, run: RunState) -> None:
        doc = {name: getattr(run, name) for name in _RUN_FIELDS}
        doc["taint_sources"] = list(run.taint_sources)
        doc["expire_at"] = run.started_at + WORKING_TTL
        self._doc("runs", run.run_id).create(doc)

    def get_run(self, run_id: str) -> RunState | None:
        snapshot = self._doc("runs", run_id).get()
        return _run_of(snapshot.to_dict()) if snapshot.exists else None

    def update_run(self, run_id: str, **changes: Any) -> None:
        unknown = set(changes) - set(_RUN_FIELDS)
        if unknown:
            raise ValueError(f"a run has no field {sorted(unknown)}")
        if "taint_sources" in changes:
            changes["taint_sources"] = list(changes["taint_sources"])
        self._doc("runs", run_id).update(changes)

    def taint_run(self, run_id: str, sources: tuple[str, ...]) -> None:
        ref = self._doc("runs", run_id)

        @firestore.transactional
        def step(transaction: Any) -> None:
            known = list(ref.get(transaction=transaction).to_dict()["taint_sources"])
            known += [source for source in sources if source not in known]
            transaction.update(ref, {"tainted": True, "taint_sources": known})

        self._run_step(step, ref)

    def count_refusal(self, run_id: str) -> int:
        ref = self._doc("runs", run_id)

        @firestore.transactional
        def step(transaction: Any) -> int:
            count = ref.get(transaction=transaction).to_dict()["refusals"] + 1
            transaction.update(ref, {"refusals": count})
            return count

        return self._run_step(step, ref)

    # --- the day counters and the limits

    def _counter_ref(self, agent: str, day: str) -> Any:
        return self._doc("counters", f"{agent}_{day}")

    @staticmethod
    def _counts(snapshot: Any) -> dict[str, int]:
        doc = snapshot.to_dict() if snapshot.exists else {}
        return {"runs": doc.get("runs", 0), "email_recipients": doc.get("email_recipients", 0)}

    def reserve_run(self, agent: str, day: str, runs_per_day: int) -> bool:
        ref = self._counter_ref(agent, day)

        @firestore.transactional
        def step(transaction: Any) -> bool:
            counts = self._counts(ref.get(transaction=transaction))
            if counts["runs"] + 1 > runs_per_day:
                return False
            transaction.set(ref, counts | {"runs": counts["runs"] + 1})
            return True

        return self._run_step(step, ref)

    def reserve(
        self, run_id: str, agent: str, day: str, records: int, recipients: int, limits: Limits
    ) -> str | None:
        run_ref, counter_ref = self._doc("runs", run_id), self._counter_ref(agent, day)

        @firestore.transactional
        def step(transaction: Any) -> str | None:
            run = run_ref.get(transaction=transaction).to_dict()
            counts = self._counts(counter_ref.get(transaction=transaction))
            crossed = check_limits(
                run["records_used"], records, counts["email_recipients"], recipients, limits
            )
            if crossed is None:
                transaction.update(run_ref, {"records_used": run["records_used"] + records})
                transaction.set(
                    counter_ref,
                    counts | {"email_recipients": counts["email_recipients"] + recipients},
                )
            return crossed

        return self._run_step(step, run_ref, counter_ref)

    def day_counters(self, agent: str, day: str) -> DayCounters:
        counts = self._counts(self._counter_ref(agent, day).get())
        return DayCounters(counts["runs"], counts["email_recipients"])

    # --- calls

    def claim_call(self, run_id: str, request_id: str) -> tuple[str, StoredCall | None]:
        call_id = call_id_for(run_id, request_id)
        ref = self._doc("calls", call_id)

        @firestore.transactional
        def step(transaction: Any) -> StoredCall | None:
            snapshot = ref.get(transaction=transaction)
            if snapshot.exists:
                return _call_of(snapshot.to_dict())
            pending = StoredCall(call_id, PENDING, None, None)
            doc = _call_doc(pending) | {
                "run_id": run_id,
                "expire_at": self._clock() + WORKING_TTL,
            }
            transaction.create(ref, doc)
            return None

        return call_id, self._run_step(step, ref)

    def get_call(self, run_id: str, request_id: str) -> StoredCall | None:
        snapshot = self._doc("calls", call_id_for(run_id, request_id)).get()
        return _call_of(snapshot.to_dict()) if snapshot.exists else None

    def put_call(
        self, run_id: str, request_id: str, call: StoredCall, meta: dict[str, Any]
    ) -> None:
        doc = dict(meta) | _call_doc(call)
        doc |= {"run_id": run_id, "expire_at": self._clock() + WORKING_TTL}
        self._doc("calls", call.call_id).set(doc)

    def get_call_by_id(self, call_id: str) -> tuple[str, StoredCall] | None:
        snapshot = self._doc("calls", call_id).get()
        if not snapshot.exists:
            return None
        doc = snapshot.to_dict()
        return doc["run_id"], _call_of(doc)

    def update_call(self, call_id: str, call: StoredCall) -> None:
        self._doc("calls", call_id).update(_call_doc(call))

    def calls_by_outcome(self, run_id: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        query = self._db.collection("calls").where(
            filter=firestore.FieldFilter("run_id", "==", run_id)
        )
        for snapshot in query.stream():
            outcome = snapshot.to_dict()["outcome"]
            if outcome != PENDING:
                counts[outcome] = counts.get(outcome, 0) + 1
        return counts

    # --- confirms and proposals

    def put_confirm(self, confirm: ConfirmRecord) -> None:
        doc = {name: getattr(confirm, name) for name in _CONFIRM_FIELDS}
        doc["taint_sources"] = list(confirm.taint_sources)
        self._doc("confirms", confirm.confirm_id).create(doc)

    def get_confirm(self, confirm_id: str) -> ConfirmRecord | None:
        snapshot = self._doc("confirms", confirm_id).get()
        if not snapshot.exists:
            return None
        doc = snapshot.to_dict()
        values = {name: doc[name] for name in _CONFIRM_FIELDS}
        values["taint_sources"] = tuple(values["taint_sources"])
        return ConfirmRecord(**values)

    def close_confirm(
        self, confirm_id: str, allowed: tuple[str, ...], status: ConfirmStatus, now: datetime
    ) -> bool:
        ref = self._doc("confirms", confirm_id)

        @firestore.transactional
        def step(transaction: Any) -> bool:
            snapshot = ref.get(transaction=transaction)
            if not snapshot.exists or snapshot.to_dict()["status"] not in allowed:
                return False
            transaction.update(ref, {"status": status, "erase_at": now + CONFIRM_ERASE_AFTER})
            return True

        return self._run_step(step, ref)

    def put_proposal(self, call_id: str, run_id: str, agent: str, preview: dict[str, str]) -> None:
        self._doc("proposals", call_id).set(
            {"run_id": run_id, "agent": agent, "preview": dict(preview), "at": self._clock()}
        )

    # --- shadow and the active version

    def get_shadow(self, agent: str) -> ShadowState | None:
        snapshot = self._doc("shadow", agent).get()
        if not snapshot.exists:
            return None
        doc = snapshot.to_dict()
        return ShadowState(doc["runs"], tuple(doc["tools"]), doc["max_class"])

    def inc_shadow_runs(self, agent: str, tools: tuple[str, ...], max_class: Class) -> int:
        ref = self._doc("shadow", agent)

        @firestore.transactional
        def step(transaction: Any) -> int:
            snapshot = ref.get(transaction=transaction)
            runs = (snapshot.to_dict()["runs"] if snapshot.exists else 0) + 1
            transaction.set(ref, {"runs": runs, "tools": list(tools), "max_class": max_class})
            return runs

        return self._run_step(step, ref)

    def get_active(self, agent: str) -> ActiveVersion | None:
        snapshot = self._doc("active", agent).get()
        if not snapshot.exists:
            return None
        doc = snapshot.to_dict()
        return ActiveVersion(doc["version"], doc["sha256"])

    def set_active(self, agent: str, active: ActiveVersion) -> bool:
        ref = self._doc("active", agent)

        @firestore.transactional
        def step(transaction: Any) -> bool:
            snapshot = ref.get(transaction=transaction)
            current = None
            if snapshot.exists:
                doc = snapshot.to_dict()
                current = ActiveVersion(doc["version"], doc["sha256"])
            if not may_set_active(current, active):
                return False
            transaction.set(ref, {"version": active.version, "sha256": active.sha256})
            return True

        return self._run_step(step, ref)
