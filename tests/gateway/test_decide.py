"""The decision function (plan Task 3.2; validator-spec section 4, gateway-design section 6).

`decide` is pure: a policy, the control switches, the run, the classified call, the day's counters
and the time go in, one Decision comes out. The first matching step wins (G-1). The table holds one
case per branch; the named tests hold the rules that the plan names.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from aiven.gateway.decide import (
    POLICY_REFUSALS,
    Classification,
    ControlSnapshot,
    Decision,
    decide,
)
from aiven.gateway.types import DayCounters, RunState
from aiven.policy.model import Limits, Policy, Scope

NOW = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)

POLICY = Policy(
    agent="invoice-reminder",
    version=1,
    principal="agent-invoice-reminder@aiven-agents-test.iam.gserviceaccount.com",
    max_class="R2",
    tools=("drive.read", "drive.update", "gmail.send"),
    forbidden=("payments.*", "drive.delete", "drive.share", "gmail.send_bulk"),
    untrusted_input="strict",
    limits=Limits(
        emails_per_day=5, records_per_run=10, spend_eur_per_run=0, max_runtime_s=300, runs_per_day=3
    ),
    scope=Scope(drive_folder_id="F" * 20, drive_folder_path=None, email_to=("a@aivenstudios.com",)),
    shadow_min_runs=10,
    sha256="sha256:" + "1" * 64,
)
CTL = ControlSnapshot(kill_global=False, kill_agent=False, wrapper_enabled=True)
RUN = RunState(
    run_id="r_1",
    agent="invoice-reminder",
    policy_sha256=POLICY.sha256,
    catalog_sha256="sha256:" + "2" * 64,
    started_at=NOW - timedelta(seconds=10),
    deadline=NOW + timedelta(seconds=290),
    status="open",
    stop_reason=None,
    shadow=False,
    tainted=False,
    taint_sources=(),
    records_used=0,
    refusals=0,
)
DAY = DayCounters(runs=1, email_recipients=0)


def call(action="drive.read", cls="R0", effective=None, **changes) -> Classification:
    values = dict(
        action=action,
        cls=cls,
        effective_cls=effective or cls,
        in_scope=True,
        records=1,
        email_recipients=0,
        taint_sources=(),
        reserved=False,
    )
    values.update(changes)
    return Classification(**values)


def run_with(**changes) -> RunState:
    return replace(RUN, **changes)


def refused(reason, cls="R0", *, alert=False, end_run=False) -> Decision:
    return Decision("refuse", reason, cls, alert, end_run, False)


# One case per branch, in the order of the steps. (name, policy, ctl, run, call, day, decision)
CASES = [
    ("kill switch, global", POLICY, replace(CTL, kill_global=True), RUN, call(), DAY,
     refused("KILL_SWITCH")),
    ("kill switch, agent", POLICY, replace(CTL, kill_agent=True), RUN, call(), DAY,
     refused("KILL_SWITCH")),
    ("run ended", POLICY, CTL, run_with(status="ended"), call(), DAY, refused("RUN_CLOSED")),
    ("run stopped", POLICY, CTL, run_with(status="stopped"), call(), DAY, refused("RUN_CLOSED")),
    ("past the deadline", POLICY, CTL, run_with(deadline=NOW), call(), DAY,
     refused("LIMIT_RUNTIME", end_run=True)),
    ("reserved namespace", POLICY, CTL, RUN, call("policy.write", None, reserved=True), DAY,
     refused("RESERVED_R4", None, alert=True)),
    ("reserved class R4", POLICY, CTL, RUN, call("drive.read", "R4"), DAY,
     refused("RESERVED_R4", "R4", alert=True)),
    ("forbidden by the file", replace(POLICY, forbidden=("drive.read",)), CTL, RUN, call(), DAY,
     refused("FORBIDDEN", alert=True)),
    ("forbidden by the baseline", replace(POLICY, forbidden=()), CTL, RUN,
     call("drive.delete", "R3"), DAY, refused("FORBIDDEN", "R3", alert=True)),
    ("forbidden by a wildcard", POLICY, CTL, RUN, call("payments.pay", None), DAY,
     refused("FORBIDDEN", None, alert=True)),
    ("not granted", POLICY, CTL, RUN, call("sheets.read"), DAY, refused("NOT_GRANTED")),
    ("not in the catalog", POLICY, CTL, RUN, call("drive.frobnicate", None), DAY,
     refused("NOT_GRANTED", None)),
    ("wrapper off", POLICY, replace(CTL, wrapper_enabled=False), RUN, call(), DAY,
     refused("WRAPPER_DISABLED")),
    ("R3", replace(POLICY, tools=("drive.move",)), CTL, RUN, call("drive.move", "R3"), DAY,
     refused("R3_DISABLED", "R3")),
    ("above max_class", replace(POLICY, max_class="R0"), CTL, RUN,
     call("drive.update", "R1"), DAY, refused("ABOVE_MAX_CLASS", "R1")),
    ("out of scope", POLICY, CTL, RUN, call(in_scope=False), DAY, refused("OUT_OF_SCOPE")),
    ("over records", POLICY, CTL, run_with(records_used=10), call(), DAY,
     refused("LIMIT_RECORDS", end_run=True)),
    ("exactly at records", POLICY, CTL, run_with(records_used=9), call(), DAY,
     Decision("execute", None, "R0", False, False, False)),
    ("over emails", POLICY, CTL, RUN, call("gmail.send", "R2", email_recipients=2),
     DayCounters(1, 4), refused("LIMIT_EMAILS", "R2", end_run=True)),
    ("shadow R1", POLICY, CTL, run_with(shadow=True), call("drive.update", "R1"), DAY,
     Decision("propose", None, "R1", False, False, False)),
    ("shadow R2", POLICY, CTL, run_with(shadow=True), call("gmail.send", "R2"), DAY,
     Decision("propose", None, "R2", False, False, False)),
    ("shadow R0", POLICY, CTL, run_with(shadow=True), call(), DAY,
     Decision("execute", None, "R0", False, False, False)),
    ("R0", POLICY, CTL, RUN, call(), DAY, Decision("execute", None, "R0", False, False, False)),
    ("R1 clean", POLICY, CTL, RUN, call("drive.update", "R1"), DAY,
     Decision("execute", None, "R1", False, False, True)),
    ("R1 strict tainted", POLICY, CTL, run_with(tainted=True), call("drive.update", "R1"), DAY,
     Decision("queue", None, "R1", False, False, False)),
    ("R1 taint mode tainted", replace(POLICY, untrusted_input="taint"), CTL,
     run_with(tainted=True), call("drive.update", "R1"), DAY,
     Decision("execute", None, "R1", False, False, True)),
    ("R2", POLICY, CTL, RUN, call("gmail.send", "R2"), DAY,
     Decision("queue", None, "R2", False, False, False)),
    ("escalated to R2", POLICY, CTL, RUN, call("drive.update", "R1", "R2"), DAY,
     Decision("queue", None, "R2", False, False, False)),
]  # fmt: skip


@pytest.mark.parametrize(
    ("policy", "ctl", "run", "c", "day", "expected"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_each_step_of_the_reading_order(policy, ctl, run, c, day, expected):
    assert decide(policy, ctl, run, c, day, NOW) == expected


def test_first_match_wins():
    # Kill switch and forbidden at once: the kill switch is the earlier step (G-1).
    c = call("drive.delete", "R3")
    both = decide(POLICY, replace(CTL, kill_global=True), RUN, c, DAY, NOW)
    assert both.reason == "KILL_SWITCH" and both.alert is False


def test_forbidden_beats_not_granted():
    c = call("drive.share", "R3")  # neither granted nor allowed
    assert decide(POLICY, CTL, RUN, c, DAY, NOW).reason == "FORBIDDEN"


def test_smuggled_trash_is_forbidden_with_alert():
    # The wrapper classes an update that sets `trashed` as drive.delete (validator-spec 5).
    c = call("drive.delete", "R3")
    assert decide(POLICY, CTL, RUN, c, DAY, NOW) == refused("FORBIDDEN", "R3", alert=True)


def test_shared_file_escalates_to_queue():
    c = call("drive.update", "R1", "R2")
    assert decide(POLICY, CTL, RUN, c, DAY, NOW).outcome == "queue"


def test_escalation_above_max_class_refused():
    policy = replace(POLICY, max_class="R1")
    c = call("drive.update", "R1", "R2")
    assert decide(policy, CTL, RUN, c, DAY, NOW) == refused("ABOVE_MAX_CLASS", "R2")


def test_shadow_proposes_r1_r2_executes_r0():
    shadow = run_with(shadow=True)
    outcomes = [
        decide(POLICY, CTL, shadow, c, DAY, NOW).outcome
        for c in (call(), call("drive.update", "R1"), call("gmail.send", "R2"))
    ]
    assert outcomes == ["execute", "propose", "propose"]


def test_strict_tainted_r1_queues():
    tainted = run_with(tainted=True)
    assert decide(POLICY, CTL, tainted, call("drive.update", "R1"), DAY, NOW).outcome == "queue"


def test_taint_mode_tainted_r1_executes():
    policy = replace(POLICY, untrusted_input="taint")
    decision = decide(policy, CTL, run_with(tainted=True), call("drive.update", "R1"), DAY, NOW)
    assert decision.outcome == "execute" and decision.snapshot is True


@pytest.mark.parametrize("reason", sorted(POLICY_REFUSALS))
def test_third_policy_refusal_ends_run_and_alerts(reason):
    tripping = {
        "FORBIDDEN": (POLICY, call("drive.share", "R3")),
        "RESERVED_R4": (POLICY, call("iam.grant", None, reserved=True)),
        "NOT_GRANTED": (POLICY, call("sheets.read")),
        "R3_DISABLED": (replace(POLICY, tools=("drive.move",)), call("drive.move", "R3")),
        "ABOVE_MAX_CLASS": (replace(POLICY, max_class="R0"), call("drive.update", "R1")),
        "OUT_OF_SCOPE": (POLICY, call(in_scope=False)),
    }
    policy, c = tripping[reason]
    second = decide(policy, CTL, run_with(refusals=1), c, DAY, NOW)
    third = decide(policy, CTL, run_with(refusals=2), c, DAY, NOW)
    assert second.reason == third.reason == reason
    assert second.end_run is False
    assert third.end_run is True and third.alert is True


def test_the_policy_refusals_are_those_of_section_6():
    assert POLICY_REFUSALS == {
        "FORBIDDEN",
        "RESERVED_R4",
        "NOT_GRANTED",
        "R3_DISABLED",
        "ABOVE_MAX_CLASS",
        "OUT_OF_SCOPE",
    }


def test_other_refusals_never_count_toward_the_stop():
    for c, run in [
        (call(in_scope=True), run_with(records_used=10, refusals=2)),  # LIMIT_RECORDS
    ]:
        decision = decide(POLICY, CTL, run, c, DAY, NOW)
        assert decision.reason == "LIMIT_RECORDS" and decision.alert is False
    off = decide(
        POLICY, replace(CTL, wrapper_enabled=False), run_with(refusals=2), call(), DAY, NOW
    )
    assert off == refused("WRAPPER_DISABLED")
