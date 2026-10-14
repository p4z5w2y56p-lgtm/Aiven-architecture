"""The gateway's pipeline (plan Tasks 3.4, 3.6, 3.7, 3.8; gateway-design sections 4 to 8).

`Gateway` is what the HTTP layer (app.py) calls, with a verified caller. Every method gives an
`Answer`: an HTTP status and a JSON body. Policy decisions are 200 with an `outcome`; the other
statuses are those of section 4: 400 malformed, 403 identity, 404 unknown, 409 run closed (or a
request still in flight), 503 failing closed because control is unreachable.

A call (`call`) goes through these steps; nothing reaches a wrapper before the last ones:

1. Identity: the caller's email must be the `principal` of a verified policy (NO_POLICY, alert).
2. The run must exist and be this agent's (RUN_CLOSED; another agent's run alerts). A run that was
   started under another version of the policy is stopped (POLICY_CHANGED): a run is one version.
3. Idempotency: the first request of a `request_id` claims the call; a retry gets the stored
   answer, or 409 while the first is still in flight (G-3).
4. Control: both kill switches and the wrapper's switch, read now (CONTROL_UNREACHABLE, 503).
5. Classify with the wrapper (or from the catalog alone when the wrapper is not live), then
   `decide` (decide.py). A reserved namespace is judged on the requested action and on the
   classified one, so a wrapper cannot hide it.
6. Limits: the store reserves the records and recipients, atomically (review focus 1).
7. No log, no action: the `call_start` entry must be written, or the call is refused (G-4).
8. Execute (R0; R1 after its snapshot), propose (shadow) or queue (R2; R1 when strict and
   tainted), then the `call` entry, and the answer is stored.

A refusal for control or the audit log also prints the fallback line (control.py), so it alerts
even when the audit log cannot. A run ends at the third policy refusal (TOO_MANY_REFUSALS), at a
crossed limit and at its deadline. `apply_confirm` re-checks everything at `:apply` (section 7).
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Protocol

from aiven.common.audit import AuditEntry, AuditWriteFailed, AuditWriter
from aiven.gateway.control import ControlReader, ControlUnavailable, fail_closed_line
from aiven.gateway.decide import (
    POLICY_REFUSALS,
    REFUSALS_BEFORE_STOP,
    Classification,
    ControlSnapshot,
    Decision,
    decide,
)
from aiven.gateway.preview import Preview, build_preview
from aiven.gateway.pricing import Pricing, Usage
from aiven.gateway.runs import END_REASONS, amsterdam_day, end_run, new_id, start_run
from aiven.gateway.shadow import count_shadow_run, in_shadow, record_proposal
from aiven.gateway.store import Store, utc_now
from aiven.gateway.taint import mark_tainted
from aiven.gateway.types import (
    PENDING,
    Caller,
    Class,
    ConfirmRecord,
    Refusal,
    RunState,
    StoredCall,
    rank,
)
from aiven.gateway.wrapper import Executed, Wrapper, WrapperFailure, WrapperRefusal
from aiven.policy.catalog import Catalog, matches
from aiven.policy.model import Policy

CONFIRM_EXPIRY = timedelta(hours=24)  # section 13
# A text longer than this cannot be read before deciding on it: such an R2 call is refused (R176).
MAX_PREVIEW_CHARS = 50_000

_ACTION = re.compile(r"[a-z][a-z0-9]*\.[a-z][a-z0-9_]*")
_STATUS = {"CONTROL_UNREACHABLE": 503, "RUN_CLOSED": 409, "NO_POLICY": 403}
_USAGE_FIELDS = {"model", "input_tokens", "output_tokens"}


@dataclass(frozen=True)
class Answer:
    """An HTTP status and the JSON body that goes with it."""

    status: int
    body: dict[str, Any]


class PolicySource(Protocol):
    """The policy registry as the pipeline uses it (policies.py)."""

    catalog: Catalog
    pricing: Pricing | None

    def for_principal(self, email: str) -> Policy | None: ...

    def for_agent(self, agent: str) -> Policy | None: ...

    def refresh(self, now: datetime, *, force: bool = False) -> None: ...


def args_sha256(args: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON of a call's arguments, for the audit entry."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _refused_body(reason: str, **more: Any) -> dict[str, Any]:
    return {"outcome": "refused", "reason": reason, **more}


@dataclass
class _Call:
    """One call on its way through the pipeline."""

    caller: Caller
    policy: Policy
    run: RunState
    action: str
    args: dict[str, Any]
    args_hash: str
    request_id: str
    call_id: str = ""
    cls: Class | None = None


class Gateway:
    """The gateway's pipeline. See the module docstring."""

    def __init__(
        self,
        *,
        store: Store,
        control: ControlReader,
        audit: AuditWriter,
        policies: PolicySource,
        wrappers: dict[str, Wrapper],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.store = store
        self.control = control
        self.audit = audit
        self.policies = policies
        self.wrappers = wrappers
        self.clock = clock

    # --- the audit log

    def _write(self, **fields: Any) -> bool:
        """Write one audit entry; False when the log did not take it."""
        try:
            self.audit.write(AuditEntry(**fields))
        except AuditWriteFailed:
            return False
        return True

    def _context(self, policy: Policy | None, run: RunState | None, caller: Caller) -> dict:
        context: dict[str, Any] = {"actor": caller.email, "catalog_hash": self.catalog.sha256}
        if policy is not None:
            context |= {"agent": policy.agent, "policy_hash": policy.sha256}
        if run is not None:
            context |= {
                "run_id": run.run_id,
                "tainted": run.tainted,
                "taint_sources": run.taint_sources,
            }
        return context

    @property
    def catalog(self) -> Catalog:
        return self.policies.catalog

    def _no_policy(self, caller: Caller, event: str) -> Answer:
        self._write(
            event=event,
            actor=caller.email,
            outcome="refused",
            reason="NO_POLICY",
            approver="none",
            catalog_hash=self.catalog.sha256,
            alert=True,
        )
        return Answer(403, _refused_body("NO_POLICY"))

    def _unreachable(
        self, *, written: bool, run_id: str | None, call_id: str | None, agent: str | None
    ) -> None:
        fail_closed_line(
            "CONTROL_UNREACHABLE",
            run_id=run_id,
            call_id=call_id,
            agent=agent,
            audit_write_failed=not written,
        )

    # --- GET /v1/me

    def me(self, caller: Caller) -> Answer:
        policy = self.policies.for_principal(caller.email)
        if policy is None:
            return self._no_policy(caller, "control")
        try:
            ctl = self.control.read(policy.agent, None)
            signoff = self.control.signoff(policy.agent)
        except ControlUnavailable:
            self._unreachable(written=True, run_id=None, call_id=None, agent=policy.agent)
            return Answer(503, _refused_body("CONTROL_UNREACHABLE"))
        return Answer(
            200,
            {
                "agent": policy.agent,
                "version": policy.version,
                "policy_hash": policy.sha256,
                "catalog_hash": self.catalog.sha256,
                "tools": [
                    {"action": tool, "class": self.catalog.actions[tool].cls}
                    for tool in policy.tools
                    if tool in self.catalog.actions
                ],
                "limits": asdict(policy.limits),
                "shadow": in_shadow(policy, signoff),
                "kill_switch": ctl.kill_global or ctl.kill_agent,
            },
        )

    # --- POST /v1/runs

    def start_run(self, caller: Caller) -> Answer:
        policy = self.policies.for_principal(caller.email)
        if policy is None:
            return self._no_policy(caller, "run_start")
        now = self.clock()
        context = self._context(policy, None, caller)
        try:
            ctl = self.control.read(policy.agent, None)
            signoff = self.control.signoff(policy.agent)
        except ControlUnavailable:
            written = self._write(
                event="run_start",
                **context,
                outcome="refused",
                reason="CONTROL_UNREACHABLE",
                approver="none",
                alert=True,
            )
            self._unreachable(written=written, run_id=None, call_id=None, agent=policy.agent)
            return Answer(503, _refused_body("CONTROL_UNREACHABLE"))
        if ctl.kill_global or ctl.kill_agent:
            self._write(
                event="run_start",
                **context,
                outcome="refused",
                reason="KILL_SWITCH",
                approver="none",
            )
            return Answer(200, _refused_body("KILL_SWITCH"))
        run = start_run(
            self.store, policy, self.catalog.sha256, shadow=in_shadow(policy, signoff), now=now
        )
        if isinstance(run, Refusal):
            self._write(
                event="run_start", **context, outcome="refused", reason=run.reason, approver="none"
            )
            return Answer(200, _refused_body(run.reason))
        if not self._write(
            event="run_start", **self._context(policy, run, caller), outcome="started"
        ):
            self.store.update_run(run.run_id, status="stopped", stop_reason="CONTROL_UNREACHABLE")
            self._unreachable(written=False, run_id=run.run_id, call_id=None, agent=policy.agent)
            return Answer(503, _refused_body("CONTROL_UNREACHABLE"))
        return Answer(
            200,
            {
                "outcome": "started",
                "run_id": run.run_id,
                "deadline": run.deadline.isoformat(),
                "shadow": run.shadow,
                "policy_hash": policy.sha256,
            },
        )

    # --- POST /v1/runs/{run_id}/calls

    def call(
        self, caller: Caller, run_id: str, action: str, args: dict[str, Any], request_id: str
    ) -> Answer:
        policy = self.policies.for_principal(caller.email)
        if policy is None:
            return self._no_policy(caller, "call")
        if not (_ACTION.fullmatch(action) and len(action) <= 64):
            return Answer(400, {"error": "action must be a catalog action id"})
        run = self.store.get_run(run_id)
        if run is None or run.agent != policy.agent:
            foreign = run is not None
            self._write(
                event="call",
                **self._context(policy, None, caller),
                action=action,
                outcome="refused",
                reason="RUN_CLOSED",
                approver="none",
                alert=foreign,
            )
            return Answer(409, _refused_body("RUN_CLOSED"))
        if run.policy_sha256 != policy.sha256 and run.status == "open":
            self.store.update_run(run_id, status="stopped", stop_reason="POLICY_CHANGED")
            run = replace(run, status="stopped", stop_reason="POLICY_CHANGED")
        ctx = _Call(caller, policy, run, action, args, args_sha256(args), request_id)
        ctx.call_id, existing = self.store.claim_call(run_id, request_id)
        if existing is not None:
            if existing.outcome == PENDING:
                return Answer(409, {"error": "the first request is still running",
                                    "reason": "IN_PROGRESS"})  # fmt: skip
            return Answer(_STATUS.get(existing.reason or "", 200), self._call_body(existing))
        return self._handle(ctx)

    def _wrapper_of(self, action: str) -> tuple[str | None, Wrapper | None]:
        """The wrapper name of an action, and the wrapper when it is built and present."""
        known = self.catalog.actions.get(action)
        if known is None:
            return None, None
        built = self.catalog.wrapper_status.get(known.wrapper) == "built"
        return known.wrapper, self.wrappers.get(known.wrapper) if built else None

    def _reserved(self, *actions: str) -> bool:
        return any(matches(pattern, a) for pattern in self.catalog.reserved for a in actions)

    def _static(self, action: str, *, in_scope: bool) -> Classification:
        """The classification from the catalog alone, when no wrapper classes the call."""
        known = self.catalog.actions.get(action)
        cls = None if known is None else known.cls
        return Classification(action, cls, cls, in_scope, 0, 0, (), self._reserved(action))

    def _handle(self, ctx: _Call) -> Answer:
        name, wrapper = self._wrapper_of(ctx.action)
        try:
            ctl = self.control.read(ctx.policy.agent, name)
        except ControlUnavailable:
            return self._refuse(ctx, "CONTROL_UNREACHABLE", alert=True)
        ctl = ControlSnapshot(
            ctl.kill_global, ctl.kill_agent, ctl.wrapper_enabled and bool(wrapper)
        )
        now = self.clock()
        day = self.store.day_counters(ctx.policy.agent, amsterdam_day(now))
        bad_args: WrapperRefusal | None = None
        if wrapper is None or not ctl.wrapper_enabled:
            c = self._static(ctx.action, in_scope=True)
        else:
            try:
                c = wrapper.classify(ctx.action, ctx.args, ctx.policy)
                c = replace(c, reserved=c.reserved or self._reserved(ctx.action, c.action))
            except WrapperRefusal as refusal:
                bad_args, c = refusal, self._static(ctx.action, in_scope=True)
        ctx.action, ctx.cls = c.action, c.effective_cls
        decision = decide(ctx.policy, ctl, ctx.run, c, day, now)
        if bad_args is not None and decision.reason in (None, "LIMIT_RECORDS", "LIMIT_EMAILS"):
            return self._refuse(ctx, bad_args.reason, alert=bad_args.alert)
        if decision.outcome == "refuse":
            return self._refuse(
                ctx, decision.reason or "", alert=decision.alert, end_run=decision.end_run
            )
        assert wrapper is not None  # a decision other than refuse needs a live wrapper
        preview = None
        if decision.outcome in ("propose", "queue"):
            try:
                preview, target = self._preview(wrapper, ctx, c)
            except WrapperRefusal as refusal:
                return self._refuse(ctx, refusal.reason, alert=refusal.alert)
        crossed = self.store.reserve(
            ctx.run.run_id,
            ctx.policy.agent,
            amsterdam_day(now),
            c.records,
            c.email_recipients,
            ctx.policy.limits,
        )
        if crossed is not None:
            return self._refuse(ctx, crossed, end_run=True)
        if not self._write(**self._entry(ctx, "call_start")):
            return self._refuse(ctx, "CONTROL_UNREACHABLE", alert=True, audit_failed=True)
        if decision.outcome == "execute":
            return self._execute(ctx, wrapper, decision)
        assert preview is not None
        if decision.outcome == "propose":
            record_proposal(self.store, ctx.run, ctx.call_id, preview)
            return self._answer(ctx, "proposed")
        confirm_id = new_id("q_")
        self.store.put_confirm(
            ConfirmRecord(
                confirm_id=confirm_id,
                run_id=ctx.run.run_id,
                call_id=ctx.call_id,
                agent=ctx.policy.agent,
                action=ctx.action,
                cls=c.effective_cls or "R2",
                args=ctx.args,
                target=target,
                preview_en=preview.en,
                preview_nl=preview.nl,
                preview_sha256=preview.sha256,
                taint_sources=ctx.run.taint_sources,
                status="pending",
                created_at=now,
                expires_at=now + CONFIRM_EXPIRY,
            )
        )
        return self._answer(ctx, "queued", confirm_id=confirm_id)

    def _preview(
        self, wrapper: Wrapper, ctx: _Call, c: Classification
    ) -> tuple[Preview, dict[str, Any]]:
        target = wrapper.target(c.action, ctx.args, ctx.policy)
        text = wrapper.agent_text(c.action, ctx.args)
        if any(len(each) > MAX_PREVIEW_CHARS for each in text.values()):
            raise WrapperRefusal("BAD_ARGS")
        return build_preview(c.action, ctx.args, target, text, ctx.run.taint_sources), target

    def _execute(self, ctx: _Call, wrapper: Wrapper, decision: Decision) -> Answer:
        try:
            done = wrapper.execute(
                ctx.action,
                ctx.args,
                ctx.policy,
                ctx.run,
                ctx.call_id,
                snapshot=decision.snapshot,
                expect_target=None,
            )
        except WrapperRefusal as refusal:
            return self._refuse(ctx, refusal.reason, alert=refusal.alert)
        except WrapperFailure:
            return self._answer(ctx, "failed", alert=True)
        if done.taint_sources:
            mark_tainted(self.store, ctx.run.run_id, done.taint_sources)
            ctx.run = replace(
                ctx.run,
                tainted=True,
                taint_sources=tuple(dict.fromkeys(ctx.run.taint_sources + done.taint_sources)),
            )
        return self._answer(ctx, "executed", done=done)

    def _entry(self, ctx: _Call, event: str, **fields: Any) -> dict[str, Any]:
        return {
            "event": event,
            **self._context(ctx.policy, ctx.run, ctx.caller),
            "call_id": ctx.call_id or None,
            "action": ctx.action,
            "class_": ctx.cls,
            "args_sha256": ctx.args_hash,
            **fields,
        }

    def _answer(
        self,
        ctx: _Call,
        outcome: str,
        *,
        done: Executed | None = None,
        confirm_id: str | None = None,
        alert: bool = False,
    ) -> Answer:
        result = None if done is None else done.result
        approver = "policy" if outcome == "executed" else "none"
        written = self._write(
            **self._entry(
                ctx,
                "call",
                outcome=outcome,
                approver=approver,
                snapshot=None if done is None else done.snapshot,
                confirm_id=confirm_id,
                alert=alert,
            )
        )
        if not written:
            self._unreachable(
                written=False, run_id=ctx.run.run_id, call_id=ctx.call_id, agent=ctx.policy.agent
            )
        kept = None if ctx.cls == "R0" else result  # no content in the working store (R171)
        stored = StoredCall(ctx.call_id, outcome, None, kept, ctx.cls, confirm_id, ctx.run.tainted)
        meta = self._meta(ctx, outcome, done, confirm_id)
        self.store.put_call(ctx.run.run_id, ctx.request_id, stored, meta)
        return Answer(200, self._call_body(replace(stored, result=result)))

    def _meta(
        self, ctx: _Call, outcome: str, done: Executed | None, confirm_id: str | None
    ) -> dict[str, Any]:
        """The rest of `calls/{call_id}` (section 5): IDs, classes, hashes and times; no content."""
        return {
            "action": ctx.action,
            "class": ctx.cls,
            "args_sha256": ctx.args_hash,
            "snapshot": None if done is None else done.snapshot,
            "confirm_id": confirm_id,
            "at": self.clock(),
            "outcome": outcome,
        }

    def _refuse(
        self,
        ctx: _Call,
        reason: str,
        *,
        alert: bool = False,
        end_run: bool = False,
        audit_failed: bool = False,
    ) -> Answer:
        stop_reason = reason
        if reason in POLICY_REFUSALS:
            if self.store.count_refusal(ctx.run.run_id) >= REFUSALS_BEFORE_STOP:
                alert = end_run = True
                stop_reason = "TOO_MANY_REFUSALS"
        if end_run and ctx.run.status == "open":
            self.store.update_run(ctx.run.run_id, status="stopped", stop_reason=stop_reason)
        written = self._write(
            **self._entry(
                ctx, "call", outcome="refused", reason=reason, approver="none", alert=alert
            )
        )
        if reason == "CONTROL_UNREACHABLE" or not written:
            self._unreachable(
                written=written and not audit_failed,
                run_id=ctx.run.run_id,
                call_id=ctx.call_id,
                agent=ctx.policy.agent,
            )
        stored = StoredCall(ctx.call_id, "refused", reason, None, ctx.cls, None, ctx.run.tainted)
        meta = self._meta(ctx, "refused", None, None)
        self.store.put_call(ctx.run.run_id, ctx.request_id, stored, meta)
        return Answer(_STATUS.get(reason, 200), self._call_body(stored))

    @staticmethod
    def _call_body(call: StoredCall) -> dict[str, Any]:
        return {
            "call_id": call.call_id,
            "outcome": call.outcome,
            "class": call.cls,
            "reason": call.reason,
            "result": call.result,
            "confirm_id": call.confirm_id,
            "tainted": call.tainted,
        }

    # --- GET /v1/runs/{run_id}/calls/{call_id}

    def get_call(self, caller: Caller, run_id: str, call_id: str) -> Answer:
        policy = self.policies.for_principal(caller.email)
        if policy is None:
            return self._no_policy(caller, "call")
        run = self.store.get_run(run_id)
        if run is None or run.agent != policy.agent:
            return Answer(403, {"error": "not this agent's run"})
        found = self.store.get_call_by_id(call_id)
        if found is None or found[0] != run_id:
            return Answer(404, {"error": "no such call in this run"})
        body = self._call_body(found[1])
        if found[1].confirm_id is not None:
            confirm = self.store.get_confirm(found[1].confirm_id)
            body["status"] = None if confirm is None else confirm.status
        return Answer(200, body)

    # --- POST /v1/runs/{run_id}:end

    def end_run(self, caller: Caller, run_id: str, usage: object, end_reason: object) -> Answer:
        policy = self.policies.for_principal(caller.email)
        if policy is None:
            return self._no_policy(caller, "run_end")
        if end_reason not in END_REASONS:
            return Answer(400, {"error": "end_reason is done, model_refusal, max_turns or error"})
        try:
            used = self._usage(usage)
        except (TypeError, ValueError):
            return Answer(400, {"error": "usage is a list of {model, input_tokens, output_tokens}"})
        run = self.store.get_run(run_id)
        if run is None or run.agent != policy.agent:
            return Answer(409, _refused_body("RUN_CLOSED"))
        was_open = run.status == "open"
        summary, ended = end_run(
            self.store, run_id, used, str(end_reason), self.clock(), self.policies.pricing
        )
        if was_open and ended.shadow:
            count_shadow_run(self.store, policy)
        written = self._write(
            event="run_end",
            **self._context(policy, ended, caller),
            outcome=ended.status,
            reason=ended.stop_reason,
            usage={"models": [asdict(each) for each in used]},
            cost_estimate_eur=summary.cost_estimate_eur,
            end_reason=str(end_reason),
        )
        if not written:
            self._unreachable(written=False, run_id=run_id, call_id=None, agent=policy.agent)
        cost = summary.cost_estimate_eur
        return Answer(
            200,
            {
                "run_id": summary.run_id,
                "calls_by_outcome": summary.calls_by_outcome,
                "records_used": summary.records_used,
                "tainted": summary.tainted,
                "cost_estimate_eur": None if cost is None else str(cost),
            },
        )

    @staticmethod
    def _usage(usage: object) -> list[Usage]:
        if not isinstance(usage, list):
            raise TypeError("usage is a list")
        used = []
        for each in usage:
            if not isinstance(each, dict) or set(each) != _USAGE_FIELDS:
                raise ValueError("each usage is {model, input_tokens, output_tokens}")
            used.append(Usage(each["model"], each["input_tokens"], each["output_tokens"]))
        return used

    # --- the control API (caller must be control-ui)

    def reload(self, caller: Caller) -> Answer:
        if caller.kind != "control":
            return Answer(403, {"error": "control API"})
        self.policies.refresh(self.clock(), force=True)
        return Answer(200, {"reloaded": True})

    def apply_confirm(self, caller: Caller, confirm_id: str) -> Answer:
        """`:apply`: read the decision in control, re-check, then execute or close (section 7)."""
        if caller.kind != "control":
            return Answer(403, {"error": "control API"})
        confirm = self.store.get_confirm(confirm_id)
        if confirm is None:
            return Answer(404, {"error": "no such confirm"})
        if confirm.status != "pending":
            return Answer(200, _refused_body("CONFIRM_CLOSED"))
        now = self.clock()
        run = self.store.get_run(confirm.run_id)
        policy = self.policies.for_agent(confirm.agent)
        context = self._context(policy, run, caller) | {
            "agent": confirm.agent,
            "run_id": confirm.run_id,
            "call_id": confirm.call_id,
            "action": confirm.action,
            "class_": confirm.cls,
            "confirm_id": confirm_id,
            "args_sha256": args_sha256(confirm.args),
        }
        if now >= confirm.expires_at:
            self.store.close_confirm(confirm_id, ("pending",), "expired", now)
            self._write(event="decision", **context, outcome="expired", approver="none")
            return Answer(200, {"outcome": "expired", "reason": None})
        try:
            decision = self.control.decision(confirm_id)
        except ControlUnavailable:
            self._unreachable(written=True, run_id=confirm.run_id, call_id=confirm.call_id,
                              agent=confirm.agent)  # fmt: skip
            return Answer(503, _refused_body("CONTROL_UNREACHABLE"))
        if decision is None:
            return Answer(200, _refused_body("NO_DECISION"))
        if decision.preview_sha256 != confirm.preview_sha256:
            self._write(event="decision", **context, outcome="refused",
                        reason="PREVIEW_MISMATCH", approver="none", alert=True)  # fmt: skip
            return Answer(200, _refused_body("PREVIEW_MISMATCH"))
        if decision.decision == "reject":
            self.store.close_confirm(confirm_id, ("pending",), "rejected", now)
            self._write(event="decision", **context, outcome="rejected", approver=decision.by)
            self._close_call(confirm, "refused", None)
            return Answer(200, {"outcome": "rejected", "reason": None})
        refusal = self._recheck(confirm, policy)
        if refusal is not None:
            if refusal == "CONTROL_UNREACHABLE":
                self._unreachable(written=True, run_id=confirm.run_id, call_id=confirm.call_id,
                                  agent=confirm.agent)  # fmt: skip
                return Answer(503, _refused_body(refusal))
            self.store.close_confirm(confirm_id, ("pending",), "failed", now)
            self._write(event="decision", **context, outcome="refused", reason=refusal,
                        approver=decision.by)  # fmt: skip
            self._close_call(confirm, "refused", refusal)
            return Answer(200, _refused_body(refusal))
        if not self._write(event="decision", **context, outcome="approved", approver=decision.by):
            self._unreachable(written=False, run_id=confirm.run_id, call_id=confirm.call_id,
                              agent=confirm.agent)  # fmt: skip
            return Answer(503, _refused_body("CONTROL_UNREACHABLE"))
        if not self.store.close_confirm(confirm_id, ("pending",), "approved", now):
            return Answer(200, _refused_body("CONFIRM_CLOSED"))
        assert policy is not None and run is not None  # _recheck refuses without them
        _, wrapper = self._wrapper_of(confirm.action)
        assert wrapper is not None
        try:
            done = wrapper.execute(
                confirm.action,
                confirm.args,
                policy,
                run,
                confirm.call_id,
                snapshot=confirm.cls != "R0",
                expect_target=confirm.target,
            )
        except WrapperRefusal as refused:
            self.store.close_confirm(confirm_id, ("approved",), "failed", now)
            self._write(event="call", **context, outcome="refused", reason=refused.reason,
                        approver=decision.by, alert=refused.alert)  # fmt: skip
            self._close_call(confirm, "refused", refused.reason)
            return Answer(200, _refused_body(refused.reason))
        except WrapperFailure:
            self.store.close_confirm(confirm_id, ("approved",), "failed", now)
            self._write(event="call", **context, outcome="failed", approver=decision.by,
                        alert=True)  # fmt: skip
            self._close_call(confirm, "failed", None)
            return Answer(200, {"outcome": "failed", "reason": None})
        self.store.close_confirm(confirm_id, ("approved",), "executed", now)
        written = self._write(
            event="call",
            **context,
            outcome="executed",
            approver=decision.by,
            snapshot=done.snapshot,
        )
        if not written:
            self._unreachable(written=False, run_id=confirm.run_id, call_id=confirm.call_id,
                              agent=confirm.agent)  # fmt: skip
        self._close_call(confirm, "executed", None, done.result)
        return Answer(200, {"outcome": "executed", "reason": None, "result": done.result})

    def _recheck(self, confirm: ConfirmRecord, policy: Policy | None) -> str | None:
        """The reason the approved confirm may not execute now, or None (section 7, step 4)."""
        name, wrapper = self._wrapper_of(confirm.action)
        try:
            ctl = self.control.read(confirm.agent, name)
        except ControlUnavailable:
            return "CONTROL_UNREACHABLE"
        if ctl.kill_global or ctl.kill_agent:
            return "KILL_SWITCH"
        if policy is None or confirm.action not in policy.tools:
            return "NOT_GRANTED"
        if self.store.get_run(confirm.run_id) is None:
            return "RUN_CLOSED"
        if wrapper is None or not ctl.wrapper_enabled:
            return "WRAPPER_DISABLED"
        try:
            c = wrapper.classify(confirm.action, confirm.args, policy)
            if not c.in_scope:
                return "OUT_OF_SCOPE"
            if c.effective_cls is None or rank(c.effective_cls) > rank(policy.max_class):
                return "ABOVE_MAX_CLASS"
            if wrapper.target(confirm.action, confirm.args, policy) != confirm.target:
                return "STALE_TARGET"
        except WrapperRefusal as refusal:
            return refusal.reason
        return None

    def _close_call(
        self,
        confirm: ConfirmRecord,
        outcome: str,
        reason: str | None,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Give the queued call its final answer, for `GET .../calls/{call_id}`."""
        found = self.store.get_call_by_id(confirm.call_id)
        if found is not None:
            kept = None if confirm.cls == "R0" else result
            self.store.update_call(
                confirm.call_id,
                replace(found[1], outcome=outcome, reason=reason, result=kept),
            )
