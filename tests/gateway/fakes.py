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

    def get_call_by_id(self, call_id: str) -> tuple[str, StoredCall] | None:
        with self._lock:
            doc = self._col("calls").get(call_id)
            return None if doc is None else (doc["run_id"], self._stored(doc))

    def update_call(self, call_id: str, call: StoredCall) -> None:
        with self._lock:
            self._col("calls")[call_id].update(asdict(call))

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


# --- the other stand-ins of the pipeline's tests (plan Tasks 3.4 to 3.8)


class FakeControl:
    """Control as the gateway reads it: switches, wrapper lists, decisions, sign-offs, releases.

    `down = True` makes every read raise ControlUnavailable; `reads` counts the reads of `read`.
    """

    def __init__(self) -> None:
        self.kill_global = False
        self.killed: set[str] = set()
        self.enabled: dict[str, list[str]] = {}
        self.decisions: dict[str, Any] = {}
        self.signoffs: dict[str, Any] = {}
        self.versions: dict[str, Any] = {}
        self.cleared: dict[str, str] = {}
        self.down = False
        self.reads = 0

    def _up(self) -> None:
        from aiven.gateway.control import ControlUnavailable

        if self.down:
            raise ControlUnavailable("control could not be read (Stand-in)")

    def read(self, agent: str, wrapper: str | None) -> Any:
        from aiven.gateway.decide import ControlSnapshot

        self._up()
        self.reads += 1
        enabled = wrapper is not None and agent in self.enabled.get(wrapper, [])
        return ControlSnapshot(self.kill_global, agent in self.killed, enabled)

    def wrapper_live(self, wrapper: str, agent: str) -> bool:
        self._up()
        return agent in self.enabled.get(wrapper, [])

    def policy_version(self, agent: str) -> Any:
        self._up()
        return self.versions.get(agent)

    def policy_versions(self) -> dict[str, Any]:
        self._up()
        return dict(self.versions)

    def decision(self, confirm_id: str) -> Any:
        self._up()
        return self.decisions.get(confirm_id)

    def signoff(self, agent: str) -> Any:
        self._up()
        return self.signoffs.get(agent)

    def taint_cleared(self, file_id: str, revision: str) -> bool:
        self._up()
        return self.cleared.get(file_id) == revision


class FakeAudit:
    """The audit log: keeps each entry; `fail_on` names the events whose write fails."""

    def __init__(self) -> None:
        self.entries: list[Any] = []
        self.fail_on: set[str] = set()

    def write(self, entry: Any) -> None:
        from aiven.common.audit import AuditWriteFailed

        if entry.event in self.fail_on or "*" in self.fail_on:
            raise AuditWriteFailed("the audit log did not take the entry (Stand-in)")
        self.entries.append(entry)

    def events(self) -> list[str]:
        return [entry.event for entry in self.entries]

    def of(self, event: str) -> list[Any]:
        return [entry for entry in self.entries if entry.event == event]


class FakePolicies:
    """The policy registry as the pipeline uses it: verified policies by principal and agent."""

    def __init__(self, catalog: Any, *policies: Any, pricing: Any = None) -> None:
        self.catalog = catalog
        self.pricing = pricing
        self.policies = {policy.agent: policy for policy in policies}
        self.refreshed: list[tuple[Any, bool]] = []

    def for_principal(self, email: str) -> Any:
        return next((p for p in self.policies.values() if p.principal == email), None)

    def for_agent(self, agent: str) -> Any:
        return self.policies.get(agent)

    def refresh(self, now: Any, *, force: bool = False) -> None:
        self.refreshed.append((now, force))


class FakeWrapper:
    """A wrapper that keeps what it was asked, for G-4 and G-10 ("receives nothing").

    It classes by the catalog, with these hooks in `args`: `trashed` makes an update a
    drive.delete (smuggled), `shared` escalates R1 to R2, `bad` is BAD_ARGS, `outside` is out of
    scope, `records` and `recipients` are counted, and `taint` lists the files a read taints with.
    `refuse_with` makes `execute` refuse; `fail` makes it fail with an unknown outcome.
    """

    def __init__(self, name: str, catalog: Any) -> None:
        self.name = name
        self.catalog = catalog
        self.executed: list[tuple[str, dict[str, Any], bool]] = []
        self.revision = "1"
        self.refuse_with: str | None = None
        self.fail = False
        self.audit_seen: list[int] = []  # entries in the audit log at each execute
        self.audit: FakeAudit | None = None

    def classify(self, action: str, args: dict[str, Any], policy: Any) -> Any:
        from aiven.gateway.decide import Classification
        from aiven.gateway.wrapper import WrapperRefusal

        if "bad" in args:
            raise WrapperRefusal("BAD_ARGS")
        if args.get("trashed"):
            action = "drive.delete"
        known = self.catalog.actions.get(action)
        cls = None if known is None else known.cls
        effective = "R2" if args.get("shared") and cls == "R1" else cls
        return Classification(
            action=action,
            cls=cls,
            effective_cls=effective,
            in_scope=not args.get("outside", False),
            records=args.get("records", 1 if cls in ("R1", "R2") else 0),
            email_recipients=args.get("recipients", 0),
            taint_sources=tuple(args.get("taint", ())),
            reserved=False,
        )

    def target(self, action: str, args: dict[str, Any], policy: Any) -> dict[str, Any]:
        return {"file_id": args.get("file_id", "f1"), "revision": self.revision}

    def agent_text(self, action: str, args: dict[str, Any]) -> dict[str, str]:
        return {"content": args["content"]} if "content" in args else {}

    def execute(
        self,
        action: str,
        args: dict[str, Any],
        policy: Any,
        run: Any,
        call_id: str,
        *,
        snapshot: bool,
        expect_target: dict[str, Any] | None,
    ) -> Any:
        from aiven.gateway.wrapper import Executed, WrapperFailure, WrapperRefusal

        if self.audit is not None:
            self.audit_seen.append(len(self.audit.entries))
        if expect_target is not None and expect_target != self.target(action, args, policy):
            raise WrapperRefusal("STALE_TARGET")
        if self.refuse_with:
            raise WrapperRefusal(self.refuse_with, alert=self.refuse_with == "SNAPSHOT_FAILED")
        if self.fail:
            self.executed.append((action, dict(args), snapshot))
            raise WrapperFailure("the write timed out after reaching Google")
        self.executed.append((action, dict(args), snapshot))
        known = self.catalog.actions[action]
        if known.cls == "R0":
            return Executed({"text": "what was read"}, None, tuple(args.get("taint", ())))
        path = f"gs://ctl-snapshots/{run.agent}/{run.run_id}/{call_id}/" if snapshot else None
        return Executed({"file_id": "new-file"}, path, ())
