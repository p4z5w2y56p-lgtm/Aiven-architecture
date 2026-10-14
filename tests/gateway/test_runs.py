"""Runs, limits and idempotency (plan Task 3.6; gateway-design sections 4 and 5, tests G-2, G-3).

A day is a calendar day in Europe/Amsterdam (validator-spec 6), taken at the moment of the request
(review focus 3): a run that starts at 23:59 counts for that day, and its call at 00:01 for the
next. The limits that cross between calls of one run are the store's (test_store_contract.py);
here: starting and ending runs, and the stored answer of a request.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from aiven.gateway.pricing import Pricing, Usage
from aiven.gateway.runs import amsterdam_day, end_run, idempotent, new_id, start_run
from aiven.gateway.types import Refusal, RunState, RunSummary, StoredCall
from aiven.policy.model import Limits, Policy, Scope
from tests.gateway.fakes import FakeStore

NOW = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
POLICY = Policy(
    agent="invoice-reminder",
    version=1,
    principal="agent-invoice-reminder@aiven-agents-test.iam.gserviceaccount.com",
    max_class="R1",
    tools=("drive.read",),
    forbidden=("payments.*", "drive.delete", "drive.share", "gmail.send_bulk"),
    untrusted_input="strict",
    limits=Limits(
        emails_per_day=0, records_per_run=10, spend_eur_per_run=0, max_runtime_s=120, runs_per_day=2
    ),
    scope=Scope(drive_folder_id="F" * 20, drive_folder_path=None, email_to=()),
    shadow_min_runs=10,
    sha256="sha256:" + "1" * 64,
)
CATALOG = "sha256:" + "2" * 64


@pytest.mark.parametrize(
    ("utc", "day"),
    [
        (datetime(2026, 10, 14, 21, 59, tzinfo=UTC), "2026-10-14"),  # 23:59 CEST
        (datetime(2026, 10, 14, 22, 1, tzinfo=UTC), "2026-10-15"),  # 00:01 CEST
        # The clocks go back on 2026-10-25 at 03:00 CEST: 23:59 CET is 22:59 UTC.
        (datetime(2026, 10, 24, 21, 59, tzinfo=UTC), "2026-10-24"),
        (datetime(2026, 10, 24, 22, 1, tzinfo=UTC), "2026-10-25"),
        (datetime(2026, 10, 25, 22, 59, tzinfo=UTC), "2026-10-25"),
        (datetime(2026, 10, 25, 23, 1, tzinfo=UTC), "2026-10-26"),
        # The clocks go forward on 2027-03-28 at 02:00 CET.
        (datetime(2027, 3, 27, 22, 59, tzinfo=UTC), "2027-03-27"),
        (datetime(2027, 3, 27, 23, 1, tzinfo=UTC), "2027-03-28"),
        (datetime(2027, 3, 28, 21, 59, tzinfo=UTC), "2027-03-28"),
        (datetime(2027, 3, 28, 22, 1, tzinfo=UTC), "2027-03-29"),
    ],
)
def test_counters_use_amsterdam_date_at_request_time(utc, day):
    assert amsterdam_day(utc) == day


def test_a_time_without_a_zone_is_refused():
    with pytest.raises(ValueError):
        amsterdam_day(datetime(2026, 10, 14, 9, 0))


def test_a_run_starts_with_its_deadline_and_state():
    store = FakeStore()
    run = start_run(store, POLICY, CATALOG, shadow=True, now=NOW)
    assert isinstance(run, RunState)
    assert run.run_id.startswith("r_") and run.agent == "invoice-reminder"
    assert run.deadline == NOW + timedelta(seconds=120)
    assert (run.status, run.shadow, run.tainted, run.records_used, run.refusals) == (
        "open",
        True,
        False,
        0,
        0,
    )
    assert run.policy_sha256 == POLICY.sha256 and run.catalog_sha256 == CATALOG
    assert store.get_run(run.run_id) == run


def test_runs_per_day_limit():
    # G-2: the run that would cross runs_per_day is refused; the next day counts again.
    store = FakeStore()
    started = [start_run(store, POLICY, CATALOG, shadow=False, now=NOW) for _ in range(3)]
    assert [type(each) for each in started] == [RunState, RunState, Refusal]
    assert started[2] == Refusal("LIMIT_RUNS")
    tomorrow = start_run(store, POLICY, CATALOG, shadow=False, now=NOW + timedelta(days=1))
    assert isinstance(tomorrow, RunState)


def test_runs_count_for_the_amsterdam_day_they_start():
    store = FakeStore()
    late = datetime(2026, 10, 14, 21, 59, tzinfo=UTC)  # 23:59 in Amsterdam
    for _ in range(2):
        start_run(store, POLICY, CATALOG, shadow=False, now=late)
    after_midnight = late + timedelta(minutes=2)
    assert isinstance(start_run(store, POLICY, CATALOG, shadow=False, now=after_midnight), RunState)


def test_ids_are_unique_and_never_hold_input():
    ids = {new_id("r_") for _ in range(1000)}
    assert len(ids) == 1000 and all(len(each) == 28 for each in ids)


def test_end_reason_logged_on_run_end():
    store = FakeStore()
    run = start_run(store, POLICY, CATALOG, shadow=False, now=NOW)
    call_id, _ = store.claim_call(run.run_id, "q1")
    store.put_call(run.run_id, "q1", StoredCall(call_id, "executed", None, None), {})
    store.update_run(run.run_id, records_used=3, tainted=True)
    pricing = Pricing.load(
        b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels:\n"
        b"  m: {input_per_million: '1', output_per_million: '2'}\n"
    )
    usage = [Usage("m", 1_000_000, 500_000)]
    summary, ended = end_run(store, run.run_id, usage, "model_refusal", NOW, pricing)
    assert summary == RunSummary(run.run_id, {"executed": 1}, 3, True, Decimal("2"))
    assert ended.status == "ended" and ended.stop_reason is None
    assert store.get_run(run.run_id).status == "ended"


def test_a_stopped_run_keeps_its_stop_reason_when_it_ends():
    store = FakeStore()
    run = start_run(store, POLICY, CATALOG, shadow=False, now=NOW)
    store.update_run(run.run_id, status="stopped", stop_reason="LIMIT_RECORDS")
    _, ended = end_run(store, run.run_id, [], "done", NOW, None)
    assert (ended.status, ended.stop_reason) == ("stopped", "LIMIT_RECORDS")


def test_an_end_reason_outside_the_four_is_refused():
    store = FakeStore()
    run = start_run(store, POLICY, CATALOG, shadow=False, now=NOW)
    with pytest.raises(ValueError):
        end_run(store, run.run_id, [], "because", NOW, None)


def test_same_request_id_executes_once():
    # G-3: the stored answer comes back for the same request_id; another one is new.
    store = FakeStore()
    run = start_run(store, POLICY, CATALOG, shadow=False, now=NOW)
    assert idempotent(store, run.run_id, "q1") is None
    call_id, _ = store.claim_call(run.run_id, "q1")
    answer = StoredCall(call_id, "executed", None, {"file_id": "f9"}, cls="R1")
    store.put_call(run.run_id, "q1", answer, {})
    assert idempotent(store, run.run_id, "q1") == answer
    assert idempotent(store, run.run_id, "q2") is None


def test_no_cost_without_a_price_list():
    store = FakeStore()
    run = start_run(store, POLICY, CATALOG, shadow=False, now=NOW)
    summary, _ = end_run(store, run.run_id, [Usage("m", 1, 1)], "done", NOW, None)
    assert summary.cost_estimate_eur is None
    assert replace(summary, cost_estimate_eur=Decimal(0)).records_used == 0


def test_ending_a_run_that_does_not_exist_raises():
    with pytest.raises(KeyError):
        end_run(FakeStore(), "r_none", [], "done", NOW, None)
