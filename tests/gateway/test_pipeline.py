"""The call pipeline (plan Tasks 3.4, 3.6, 3.7, 3.8; gateway-design sections 4 to 8; G-1 to G-10).

`Gateway` is what the HTTP layer calls: it maps the caller to a policy, then handles the run, the
call and the confirm with the store, control, the audit log and the wrappers. Here everything
around it is a stand-in (tests/gateway/fakes.py), so each test sees exactly what reached the
wrapper ("the fake Drive receives nothing"), what reached the audit log, and in which order.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from aiven.gateway.control import ControlDecision, Signoff
from aiven.gateway.pipeline import Answer, Gateway
from aiven.gateway.pricing import Pricing
from aiven.gateway.types import Caller
from aiven.policy.model import Limits, Policy, Scope
from tests.gateway.fakes import FakeAudit, FakeControl, FakePolicies, FakeStore, FakeWrapper
from tests.support.rules import catalog_with

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
CATALOG = catalog_with(drive="built")  # Email stays planned (G-10)
AGENT = "invoice-reminder"
PRINCIPAL = "agent-invoice-reminder@aiven-agents-test.iam.gserviceaccount.com"
POLICY = Policy(
    agent=AGENT,
    version=1,
    principal=PRINCIPAL,
    max_class="R2",
    tools=("drive.read", "drive.create", "drive.update", "gmail.send"),
    forbidden=("payments.*", "drive.delete", "drive.share", "gmail.send_bulk"),
    untrusted_input="strict",
    limits=Limits(
        emails_per_day=3, records_per_run=3, spend_eur_per_run=0, max_runtime_s=300, runs_per_day=5
    ),
    scope=Scope("F" * 20, None, ("a@aivenstudios.com",)),
    shadow_min_runs=10,
    sha256="sha256:" + "1" * 64,
)
SIGNED_OFF = Signoff(POLICY.tools, "R2", POLICY.sha256, 10, "m@aivenstudios.com", T0)
AGENT_CALLER = Caller(PRINCIPAL, "agent")
CONTROL_UI = Caller("control-ui@aiven-control-test.iam.gserviceaccount.com", "control")
STRANGER = Caller("agent-other@aiven-agents-test.iam.gserviceaccount.com", "agent")


class World:
    """A gateway on stand-ins, with a clock the test moves."""

    def __init__(self, policy: Policy = POLICY, *, signed_off: bool = True):
        self.now = T0
        self.store = FakeStore(clock=lambda: self.now)
        self.control = FakeControl()
        self.control.enabled["drive"] = [AGENT]
        if signed_off:
            self.control.signoffs[AGENT] = SIGNED_OFF
        self.audit = FakeAudit()
        pricing = Pricing.load(
            b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels:\n"
            b"  m: {input_per_million: '1', output_per_million: '2'}\n"
        )
        self.policies = FakePolicies(CATALOG, policy, pricing=pricing)
        self.drive = FakeWrapper("drive", CATALOG)
        self.drive.audit = self.audit
        self.gateway = Gateway(
            store=self.store,
            control=self.control,
            audit=self.audit,
            policies=self.policies,
            wrappers={"drive": self.drive},
            clock=lambda: self.now,
        )
        self.requests = 0

    def start(self, caller: Caller = AGENT_CALLER) -> str:
        answer = self.gateway.start_run(caller)
        assert answer.status == 200 and answer.body["outcome"] == "started", answer
        return answer.body["run_id"]

    def call(self, run_id, action="drive.read", args=None, request_id=None, caller=AGENT_CALLER):
        self.requests += 1
        request = request_id or f"q{self.requests}"
        return self.gateway.call(caller, run_id, action, dict(args or {}), request)


@pytest.fixture
def world() -> World:
    return World()


def body(answer: Answer) -> tuple:
    return answer.status, answer.body.get("outcome"), answer.body.get("reason")


# --- identity (validator-spec 4 step 2; AT-BYP-4)


def test_unmapped_principal_no_policy_alert(world):
    run_id = world.start()
    for answer in (
        world.gateway.me(STRANGER),
        world.gateway.start_run(STRANGER),
        world.call(run_id, caller=STRANGER),
    ):
        assert body(answer) == (403, "refused", "NO_POLICY")
    refusals = [entry for entry in world.audit.entries if entry.reason == "NO_POLICY"]
    assert len(refusals) == 3 and all(entry.alert for entry in refusals)
    assert world.drive.executed == []


def test_another_agents_run_is_closed_and_alerts(world):
    other = replace(
        POLICY, agent="other-agent", principal=STRANGER.email, sha256="sha256:" + "4" * 64
    )
    world.policies.policies["other-agent"] = other
    run_id = world.start()
    answer = world.call(run_id, caller=STRANGER)
    assert body(answer) == (409, "refused", "RUN_CLOSED")
    assert world.audit.entries[-1].alert is True and world.drive.executed == []


def test_a_run_that_does_not_exist_is_closed(world):
    assert body(world.call("r_nothing")) == (409, "refused", "RUN_CLOSED")


# --- the reading order through the pipeline (G-1)


def test_kill_switch_beats_forbidden_and_nothing_reaches_the_wrapper(world):
    run_id = world.start()
    world.control.kill_global = True
    answer = world.call(run_id, "drive.update", {"trashed": True})
    assert body(answer) == (200, "refused", "KILL_SWITCH")
    assert world.drive.executed == []


def test_smuggled_trash_is_forbidden_and_alerts(world):
    run_id = world.start()
    answer = world.call(run_id, "drive.update", {"trashed": True})
    assert body(answer) == (200, "refused", "FORBIDDEN")
    call = world.audit.of("call")[-1]
    assert (call.action, call.alert, call.outcome) == ("drive.delete", True, "refused")


def test_bad_args_come_after_the_earlier_steps(world):
    run_id = world.start()
    assert body(world.call(run_id, "drive.read", {"bad": 1})) == (200, "refused", "BAD_ARGS")
    world.control.kill_global = True
    assert body(world.call(run_id, "drive.read", {"bad": 1})) == (200, "refused", "KILL_SWITCH")
    world.control.kill_global = False
    assert body(world.call(run_id, "sheets.read", {"bad": 1})) == (200, "refused", "NOT_GRANTED")


def test_reserved_namespace_is_r4_with_alert(world):
    # AT-SELF-1: whatever the policy says, these are R4.
    run_id = world.start()
    for action in ("policy.write", "iam.grant", "audit.delete", "killswitch.off", "secrets.get",
                   "agentbuilder.permissions"):  # fmt: skip
        answer = world.call(run_id, action)
        assert body(answer)[2] == "RESERVED_R4" or body(answer)[2] == "RUN_CLOSED"
    first = world.audit.of("call")[0]
    assert first.reason == "RESERVED_R4" and first.alert is True


# --- fail closed (G-4, G-5) and the fallback line


def test_audit_failure_refuses_and_never_executes(world, capsys):
    run_id = world.start()
    world.audit.fail_on = {"call_start"}
    answer = world.call(run_id, "drive.read")
    assert body(answer) == (503, "refused", "CONTROL_UNREACHABLE")
    assert world.drive.executed == []
    line = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert line["reason"] == "CONTROL_UNREACHABLE" and line["audit_write_failed"] is True


def test_audit_write_failure_prints_the_fallback_line_and_refuses(world, capsys):
    run_id = world.start()
    world.audit.fail_on = {"*"}
    answer = world.call(run_id, "drive.update", {"content": "x"})
    assert body(answer)[0] == 503 and world.drive.executed == []
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines and all(line["alert"] is True for line in lines)


def test_control_failure_503_and_never_executes(world, capsys):
    run_id = world.start()
    world.control.down = True
    answer = world.call(run_id)
    assert body(answer) == (503, "refused", "CONTROL_UNREACHABLE")
    assert world.drive.executed == []
    line = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert line == {
        "severity": "ALERT",
        "message": "gateway fails closed",
        "reason": "CONTROL_UNREACHABLE",
        "alert": True,
        "audit_write_failed": False,
        "run_id": run_id,
        "call_id": answer.body["call_id"],
        "agent": AGENT,
    }
    entry = world.audit.of("call")[-1]
    assert entry.reason == "CONTROL_UNREACHABLE" and entry.alert is True


def test_control_failure_at_run_start_is_503(world):
    world.control.down = True
    assert body(world.gateway.start_run(AGENT_CALLER)) == (503, "refused", "CONTROL_UNREACHABLE")


def test_run_start_without_its_audit_entry_is_refused_and_the_run_stopped(world):
    world.audit.fail_on = {"run_start"}
    answer = world.gateway.start_run(AGENT_CALLER)
    assert body(answer) == (503, "refused", "CONTROL_UNREACHABLE")
    (run,) = [world.store.get_run(doc) for doc in world.store._docs["runs"]]
    assert (run.status, run.stop_reason) == ("stopped", "CONTROL_UNREACHABLE")


def test_kill_switch_read_on_every_call(world):
    run_id = world.start()
    before = world.control.reads
    for _ in range(3):
        world.call(run_id)
    assert world.control.reads - before == 3


def test_call_start_written_before_execute(world):
    run_id = world.start()
    world.call(run_id, "drive.update", {"content": "x"})
    events = world.audit.events()
    assert events[-2:] == ["call_start", "call"]
    # When the wrapper ran, the audit log held run_start and call_start already.
    assert world.drive.audit_seen == [2]


# --- what is executed, and what is logged


def test_r0_executes_and_logs_with_the_policy_as_approver(world):
    run_id = world.start()
    answer = world.call(run_id, "drive.read", {"file_id": "f1"})
    assert body(answer) == (200, "executed", None)
    assert answer.body["class"] == "R0" and answer.body["result"] == {"text": "what was read"}
    entry = world.audit.of("call")[-1]
    assert (entry.outcome, entry.approver, entry.class_) == ("executed", "policy", "R0")
    assert entry.policy_hash == POLICY.sha256 and entry.catalog_hash == CATALOG.sha256
    assert entry.args_sha256 and len(entry.args_sha256) == 64
    assert entry.actor == PRINCIPAL and entry.snapshot is None


def test_r1_takes_its_snapshot_and_logs_the_path(world):
    run_id = world.start()
    answer = world.call(run_id, "drive.update", {"content": "new"})
    assert body(answer) == (200, "executed", None)
    assert world.drive.executed == [("drive.update", {"content": "new"}, True)]
    assert world.audit.of("call")[-1].snapshot.startswith("gs://ctl-snapshots/invoice-reminder/")


def test_a_failed_snapshot_writes_nothing_and_alerts(world):
    run_id = world.start()
    world.drive.refuse_with = "SNAPSHOT_FAILED"
    answer = world.call(run_id, "drive.update", {"content": "new"})
    assert body(answer) == (200, "refused", "SNAPSHOT_FAILED")
    assert world.drive.executed == [] and world.audit.of("call")[-1].alert is True


def test_an_unknown_outcome_is_failed_alerted_and_never_retried(world):
    # Review focus 2 (the Drive half is Task 4.3): no retry, marked failed, an alert.
    run_id = world.start()
    world.drive.fail = True
    first = world.call(run_id, "drive.update", {"content": "x"}, request_id="same")
    again = world.call(run_id, "drive.update", {"content": "x"}, request_id="same")
    assert body(first) == body(again) == (200, "failed", None)
    assert len(world.drive.executed) == 1
    assert world.audit.of("call")[-1].alert is True


def test_audit_entries_hold_ids_and_hashes_only(world):
    run_id = world.start()
    world.call(run_id, "drive.update", {"content": "a secret plan"})
    for entry in world.audit.entries:
        assert "a secret plan" not in json.dumps(entry.payload(), default=str)


# --- idempotency (G-3)


def test_same_request_id_executes_once_through_the_pipeline(world):
    run_id = world.start()
    first = world.call(run_id, "drive.update", {"content": "x"}, request_id="r-1")
    again = world.call(run_id, "drive.update", {"content": "x"}, request_id="r-1")
    assert first == again
    assert len(world.drive.executed) == 1 and len(world.audit.of("call")) == 1


def test_a_read_is_not_stored_so_its_retry_has_no_result(world):
    run_id = world.start()
    first = world.call(run_id, "drive.read", request_id="r-1")
    again = world.call(run_id, "drive.read", request_id="r-1")
    assert first.body["result"] == {"text": "what was read"}
    assert again.body["result"] is None and again.body["outcome"] == "executed"
    assert len(world.drive.executed) == 1


def test_a_request_still_in_flight_is_409(world):
    run_id = world.start()
    world.store.claim_call(run_id, "in-flight")
    answer = world.call(run_id, request_id="in-flight")
    assert answer.status == 409 and answer.body["reason"] == "IN_PROGRESS"


# --- limits and the probing stop (G-2, G-6)


def test_each_limit_refuses_and_ends_run(world):
    run_id = world.start()
    assert body(world.call(run_id, "drive.update", {"records": 3})) == (200, "executed", None)
    over = world.call(run_id, "drive.update", {"records": 1})
    assert body(over) == (200, "refused", "LIMIT_RECORDS")
    assert world.store.get_run(run_id).status == "stopped"
    assert body(world.call(run_id)) == (409, "refused", "RUN_CLOSED")


def test_the_deadline_ends_the_run(world):
    run_id = world.start()
    world.now += timedelta(seconds=301)
    assert body(world.call(run_id)) == (200, "refused", "LIMIT_RUNTIME")
    assert world.store.get_run(run_id).stop_reason == "LIMIT_RUNTIME"


def test_three_policy_refusals_end_the_run_and_alert(world):
    run_id = world.start()
    reasons = [body(world.call(run_id, "sheets.read"))[2] for _ in range(3)]
    assert reasons == ["NOT_GRANTED"] * 3
    run = world.store.get_run(run_id)
    assert (run.status, run.stop_reason, run.refusals) == ("stopped", "TOO_MANY_REFUSALS", 3)
    assert world.audit.of("call")[-1].alert is True
    assert body(world.call(run_id)) == (409, "refused", "RUN_CLOSED")


def test_runs_per_day_through_the_pipeline(world):
    for _ in range(5):
        world.start()
    assert body(world.gateway.start_run(AGENT_CALLER)) == (200, "refused", "LIMIT_RUNS")


def test_a_policy_change_closes_the_runs_of_the_old_one(world):
    run_id = world.start()
    world.policies.policies[AGENT] = replace(POLICY, version=2, sha256="sha256:" + "5" * 64)
    assert body(world.call(run_id)) == (409, "refused", "RUN_CLOSED")
    assert world.store.get_run(run_id).stop_reason == "POLICY_CHANGED"


# --- taint and untrusted input (G-8, G-9)


def test_a_read_of_untrusted_files_taints_the_run(world):
    run_id = world.start()
    answer = world.call(run_id, "drive.read", {"taint": ["f7"]})
    assert answer.body["tainted"] is True
    assert world.store.get_run(run_id).taint_sources == ("f7",)


def test_a_clean_run_stays_clean(world):
    run_id = world.start()
    world.call(run_id, "drive.read")
    assert world.store.get_run(run_id).tainted is False


def test_strict_queues_r1_in_a_tainted_run(world):
    run_id = world.start()
    world.call(run_id, "drive.read", {"taint": ["f7"]})
    answer = world.call(run_id, "drive.update", {"content": "x"})
    assert body(answer) == (200, "queued", None) and answer.body["confirm_id"]
    assert [each[0] for each in world.drive.executed] == ["drive.read"]


def test_taint_mode_executes_r1_in_a_tainted_run():
    world = World(replace(POLICY, untrusted_input="taint"))
    run_id = world.start()
    world.call(run_id, "drive.read", {"taint": ["f7"]})
    assert body(world.call(run_id, "drive.update", {"content": "x"})) == (200, "executed", None)


# --- wrappers that are not live (G-10)


def test_email_wrapper_disabled_refuses_and_reaches_nothing(world):
    run_id = world.start()
    answer = world.call(run_id, "gmail.send", {"recipients": 1})
    assert body(answer) == (200, "refused", "WRAPPER_DISABLED")
    assert world.drive.executed == []


def test_a_wrapper_switched_off_in_control_refuses(world):
    run_id = world.start()
    world.control.enabled["drive"] = []
    assert body(world.call(run_id)) == (200, "refused", "WRAPPER_DISABLED")


# --- shadow mode (SH-1, SH-4)


def test_a_new_agent_proposes_and_executes_only_reads():
    world = World(signed_off=False)
    run_id = world.start()
    read = world.call(run_id, "drive.read")
    write = world.call(run_id, "drive.update", {"content": "x"})
    assert body(read)[1] == "executed" and body(write) == (200, "proposed", None)
    assert [each[0] for each in world.drive.executed] == ["drive.read"]
    proposal = world.store.raw("proposals", write.body["call_id"])
    assert proposal["preview"]["sha256"]
    assert world.audit.of("call")[-1].approver == "none"


def test_proposals_count_toward_limits():
    # SH-4: a proposal takes its records, so shadow runs show where a limit would stop the agent.
    world = World(signed_off=False)
    run_id = world.start()
    assert body(world.call(run_id, "drive.update", {"records": 3}))[1] == "proposed"
    assert body(world.call(run_id, "drive.update", {"records": 1}))[2] == "LIMIT_RECORDS"


def test_a_shadow_run_is_counted_when_it_ends():
    world = World(signed_off=False)
    run_id = world.start()
    world.gateway.end_run(AGENT_CALLER, run_id, [], "done")
    world.gateway.end_run(AGENT_CALLER, run_id, [], "done")  # once only
    assert world.store.get_shadow(AGENT).runs == 1


# --- the end of a run (CR-1)


def test_run_end_logs_usage_cost_and_reason(world):
    run_id = world.start()
    world.call(run_id, "drive.update", {"content": "x"})
    usage = [{"model": "m", "input_tokens": 1_000_000, "output_tokens": 0}]
    answer = world.gateway.end_run(AGENT_CALLER, run_id, usage, "model_refusal")
    assert answer.status == 200
    assert answer.body == {
        "run_id": run_id,
        "calls_by_outcome": {"executed": 1},
        "records_used": 1,
        "tainted": False,
        "cost_estimate_eur": "1",
    }
    entry = world.audit.of("run_end")[-1]
    assert entry.end_reason == "model_refusal" and entry.cost_estimate_eur == Decimal("1")
    assert entry.usage == {"models": usage}


@pytest.mark.parametrize(
    "usage",
    [
        [{"model": "m", "input_tokens": -1, "output_tokens": 0}],
        [{"model": "m", "input_tokens": 1}],
        [{"model": "m", "input_tokens": 1, "output_tokens": 0, "extra": 1}],
        "not a list",
    ],
)
def test_usage_of_the_wrong_shape_is_400(world, usage):
    run_id = world.start()
    assert world.gateway.end_run(AGENT_CALLER, run_id, usage, "done").status == 400


def test_an_end_reason_outside_the_four_is_400(world):
    run_id = world.start()
    assert world.gateway.end_run(AGENT_CALLER, run_id, [], "bored").status == 400


# --- /v1/me and the call status


def test_me_shows_the_active_policy(world):
    answer = world.gateway.me(AGENT_CALLER)
    assert answer.status == 200
    assert answer.body["agent"] == AGENT and answer.body["policy_hash"] == POLICY.sha256
    assert answer.body["catalog_hash"] == CATALOG.sha256 and answer.body["version"] == 1
    assert {"action": "gmail.send", "class": "R2"} in answer.body["tools"]
    assert answer.body["shadow"] is False and answer.body["kill_switch"] is False
    assert answer.body["limits"]["records_per_run"] == 3


def test_a_call_status_is_given_to_its_own_agent_only(world):
    run_id = world.start()
    answer = world.call(run_id, "gmail.send")  # refused: wrapper disabled
    call_id = answer.body["call_id"]
    status = world.gateway.get_call(AGENT_CALLER, run_id, call_id)
    assert status.status == 200 and status.body["outcome"] == "refused"
    assert world.gateway.get_call(AGENT_CALLER, run_id, "c_" + "0" * 32).status == 404
    assert world.gateway.get_call(STRANGER, run_id, call_id).status == 403


# --- the R2 confirm flow (G-7, KS-3, AT-SELF-3)


def queued(world) -> tuple[str, dict]:
    run_id = world.start()
    answer = world.call(run_id, "drive.update", {"content": "x", "shared": True})
    assert body(answer) == (200, "queued", None)
    return run_id, answer.body


def decide_on(world, confirm_id, decision="approve", sha=None):
    confirm = world.store.get_confirm(confirm_id)
    world.control.decisions[confirm_id] = ControlDecision(
        decision, sha or confirm.preview_sha256, "m@aivenstudios.com", world.now
    )


def apply(world, confirm_id, caller=CONTROL_UI) -> Answer:
    return world.gateway.apply_confirm(caller, confirm_id)


def test_an_approved_confirm_executes_with_its_approver(world):
    run_id, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    applied = apply(world, answer["confirm_id"])
    assert body(applied) == (200, "executed", None)
    assert world.drive.executed == [("drive.update", {"content": "x", "shared": True}, True)]
    call = world.audit.of("call")[-1]
    assert (call.approver, call.outcome, call.confirm_id) == (
        "m@aivenstudios.com",
        "executed",
        answer["confirm_id"],
    )
    assert world.audit.of("decision")[-1].approver == "m@aivenstudios.com"
    status = world.gateway.get_call(AGENT_CALLER, run_id, answer["call_id"])
    assert status.body["outcome"] == "executed" and status.body["status"] == "executed"
    assert body(apply(world, answer["confirm_id"]))[2] == "CONFIRM_CLOSED"  # once only


def test_a_rejected_confirm_never_executes(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"], "reject")
    assert body(apply(world, answer["confirm_id"])) == (200, "rejected", None)
    assert world.drive.executed == []
    assert world.store.get_confirm(answer["confirm_id"]).status == "rejected"


def test_hash_mismatch_refused(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"], sha="f" * 64)
    assert body(apply(world, answer["confirm_id"]))[2] == "PREVIEW_MISMATCH"
    assert world.drive.executed == []


def test_changed_target_stale(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    world.drive.revision = "2"
    assert body(apply(world, answer["confirm_id"])) == (200, "refused", "STALE_TARGET")
    assert world.drive.executed == []


def test_expired_after_24h(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    world.now += timedelta(hours=24, seconds=1)
    assert body(apply(world, answer["confirm_id"])) == (200, "expired", None)
    assert world.store.get_confirm(answer["confirm_id"]).status == "expired"
    assert world.drive.executed == []


def test_kill_switch_at_apply_refused(world):
    # G-7, KS-3: queue an R2, flip the switch, then approve.
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    world.control.killed.add(AGENT)
    assert body(apply(world, answer["confirm_id"])) == (200, "refused", "KILL_SWITCH")
    assert world.drive.executed == []


def test_decision_must_exist_in_control(world):
    # AT-SELF-3: no decision in control, no execution, whoever calls.
    _, answer = queued(world)
    assert body(apply(world, answer["confirm_id"]))[2] == "NO_DECISION"
    assert world.drive.executed == []


def test_control_routes_reject_agents(world):
    # AT-BYP-2 and AT-SELF-3: an agent can neither apply a confirm nor reload policies.
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    assert apply(world, answer["confirm_id"], caller=AGENT_CALLER).status == 403
    assert world.gateway.reload(AGENT_CALLER).status == 403
    assert world.drive.executed == []


def test_a_tool_no_longer_granted_is_refused_at_apply(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    world.policies.policies[AGENT] = replace(POLICY, tools=("drive.read",))
    assert body(apply(world, answer["confirm_id"]))[2] == "NOT_GRANTED"


def test_out_of_scope_at_apply_is_refused(world):
    run_id = world.start()
    answer = world.call(run_id, "drive.update", {"content": "x", "shared": True})
    confirm_id = answer.body["confirm_id"]
    decide_on(world, confirm_id)
    world.drive.classify = lambda action, args, policy: replace(
        FakeWrapper("drive", CATALOG).classify(action, args, policy), in_scope=False
    )
    assert body(apply(world, confirm_id))[2] == "OUT_OF_SCOPE"


def test_control_down_at_apply_is_503(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    world.control.down = True
    assert apply(world, answer["confirm_id"]).status == 503
    assert world.drive.executed == []


def test_reload_by_the_control_ui_refreshes_now(world):
    assert world.gateway.reload(CONTROL_UI).status == 200
    assert world.policies.refreshed == [(T0, True)]


def test_a_preview_too_long_to_read_is_refused():
    world = World()
    run_id = world.start()
    long = "x" * 50_001
    answer = world.call(run_id, "drive.update", {"content": long, "shared": True})
    assert body(answer) == (200, "refused", "BAD_ARGS")


# --- the failure paths (each one refuses, or alerts, and says so)


def test_me_with_control_down_is_503(world):
    world.control.down = True
    assert world.gateway.me(AGENT_CALLER).status == 503


def test_a_run_does_not_start_under_a_kill_switch(world):
    world.control.killed.add(AGENT)
    assert body(world.gateway.start_run(AGENT_CALLER)) == (200, "refused", "KILL_SWITCH")


@pytest.mark.parametrize("action", ["Drive.read", "drive", "drive.read; rm", "a." + "b" * 70])
def test_an_action_that_is_no_action_id_is_400(world, action):
    run_id = world.start()
    assert world.call(run_id, action).status == 400
    assert world.drive.executed == []


def test_a_reservation_lost_to_a_parallel_call_refuses_and_ends_the_run(world, monkeypatch):
    run_id = world.start()
    monkeypatch.setattr(world.store, "reserve", lambda *args: "LIMIT_RECORDS")
    assert body(world.call(run_id, "drive.update", {"content": "x"})) == (
        200,
        "refused",
        "LIMIT_RECORDS",
    )
    assert world.drive.executed == [] and world.store.get_run(run_id).status == "stopped"


def test_a_call_entry_that_fails_after_execution_alerts_by_the_line(world, capsys):
    run_id = world.start()
    world.audit.fail_on = {"call"}
    answer = world.call(run_id, "drive.update", {"content": "x"})
    assert body(answer) == (200, "executed", None)
    line = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert line["audit_write_failed"] is True and line["call_id"] == answer.body["call_id"]


def test_a_call_status_of_another_agents_run_is_403(world):
    other = replace(POLICY, agent="other-agent", principal=STRANGER.email)
    world.policies.policies["other-agent"] = other
    run_id = world.start()
    call_id = world.call(run_id).body["call_id"]
    assert world.gateway.get_call(STRANGER, run_id, call_id).status == 403


def test_ending_runs_that_are_not_yours(world):
    run_id = world.start()
    other = replace(POLICY, agent="other-agent", principal=STRANGER.email)
    assert body(world.gateway.end_run(STRANGER, run_id, [], "done"))[2] == "NO_POLICY"
    world.policies.policies["other-agent"] = other
    assert body(world.gateway.end_run(STRANGER, run_id, [], "done")) == (
        409,
        "refused",
        "RUN_CLOSED",
    )


def test_a_run_end_entry_that_fails_alerts_by_the_line(world, capsys):
    run_id = world.start()
    world.audit.fail_on = {"run_end"}
    assert world.gateway.end_run(AGENT_CALLER, run_id, [], "done").status == 200
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["audit_write_failed"] is True


def test_an_unknown_confirm_is_404(world):
    assert apply(world, "q_none").status == 404


def test_a_decision_entry_that_fails_stops_the_apply(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    world.audit.fail_on = {"decision"}
    assert apply(world, answer["confirm_id"]).status == 503
    assert world.drive.executed == []
    assert world.store.get_confirm(answer["confirm_id"]).status == "pending"


def test_an_apply_that_loses_the_race_executes_nothing(world, monkeypatch):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    monkeypatch.setattr(world.store, "close_confirm", lambda *args: False)
    assert body(apply(world, answer["confirm_id"]))[2] == "CONFIRM_CLOSED"
    assert world.drive.executed == []


@pytest.mark.parametrize(("hook", "outcome"), [("refuse", "refused"), ("fail", "failed")])
def test_an_apply_whose_write_does_not_happen(world, hook, outcome):
    run_id, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    if hook == "refuse":
        world.drive.refuse_with = "SNAPSHOT_FAILED"
    else:
        world.drive.fail = True
    assert body(apply(world, answer["confirm_id"]))[1] == outcome
    assert world.store.get_confirm(answer["confirm_id"]).status == "failed"
    status = world.gateway.get_call(AGENT_CALLER, run_id, answer["call_id"])
    assert status.body["outcome"] == outcome and status.body["status"] == "failed"
    assert world.audit.of("call")[-1].alert is True


def test_a_call_entry_that_fails_after_apply_alerts_by_the_line(world, capsys):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])
    world.audit.fail_on = {"call"}
    assert body(apply(world, answer["confirm_id"]))[1] == "executed"
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["audit_write_failed"] is True


def test_control_down_at_the_recheck_is_503(world, monkeypatch):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"])

    def down(*args):
        from aiven.gateway.control import ControlUnavailable

        raise ControlUnavailable("control could not be read (Stand-in)")

    monkeypatch.setattr(world.control, "read", down)
    assert apply(world, answer["confirm_id"]).status == 503
    assert world.store.get_confirm(answer["confirm_id"]).status == "pending"


def test_rechecks_at_apply(world):
    cases = {
        "RUN_CLOSED": lambda: world.store._docs["runs"].clear(),
        "WRAPPER_DISABLED": lambda: world.control.enabled.update(drive=[]),
        "ABOVE_MAX_CLASS": lambda: world.policies.policies.update(
            {AGENT: replace(POLICY, max_class="R1")}
        ),
        "BAD_ARGS": lambda: setattr(world.drive, "classify", _bad_args),
        "NOT_GRANTED": lambda: world.policies.policies.clear(),
    }
    for reason, change in cases.items():
        _, answer = queued(world)
        decide_on(world, answer["confirm_id"])
        change()
        assert body(apply(world, answer["confirm_id"])) == (200, "refused", reason), reason
        world.__init__()
    assert world.drive.executed == []


def _bad_args(action, args, policy):
    from aiven.gateway.wrapper import WrapperRefusal

    raise WrapperRefusal("BAD_ARGS")


def test_a_queued_call_that_is_gone_from_the_store_still_closes(world):
    _, answer = queued(world)
    decide_on(world, answer["confirm_id"], "reject")
    world.store._docs["calls"].clear()
    assert body(apply(world, answer["confirm_id"]))[1] == "rejected"


def test_a_wrapper_cannot_class_a_call_out_of_a_reserved_namespace(world, monkeypatch):
    # The pipeline judges reserved namespaces on the requested and the classified action.
    run_id = world.start()
    real = world.drive.classify
    monkeypatch.setattr(
        world.drive,
        "classify",
        lambda action, args, policy: replace(real("drive.read", args, policy), action="iam.grant"),
    )
    assert body(world.call(run_id, "drive.read"))[2] == "RESERVED_R4"
    assert world.drive.executed == []
