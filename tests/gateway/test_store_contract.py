"""The contract of the gateway's working store (plan Task 3.1, gateway-design section 5).

One suite, two stores: the in-memory fake of tests/gateway/fakes.py, and `FirestoreStore` against
the Firestore emulator. The emulator half runs when FIRESTORE_EMULATOR_HOST is set; CI sets it and
AIVEN_REQUIRE_EMULATOR=1, which turns a skip into a failure (ruling R169). Each test gets a project
of its own in the emulator, so nothing is shared between tests.
"""

import os
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from aiven.gateway.store import call_id_for
from aiven.gateway.types import ConfirmRecord, DayCounters, RunState, ShadowState, StoredCall
from aiven.policy.model import Limits
from aiven.policy.verify import ActiveVersion
from tests.gateway.fakes import FakeStore

NOW = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
TTL = timedelta(days=90)
HASH = "sha256:" + "1" * 64
CATALOG = "sha256:" + "2" * 64
LIMITS = Limits(
    emails_per_day=5, records_per_run=10, spend_eur_per_run=0, max_runtime_s=300, runs_per_day=3
)


class Backend:
    """A store of one kind, and what the tests need around it.

    `store` is the store; `raw(collection, doc_id)` the stored document as a dict, or None; and
    `instance()` another store on the same data, as a second Cloud Run instance would have.
    """

    def __init__(self, kind: str):
        clock = lambda: NOW  # noqa: E731
        if kind == "fake":
            fake = FakeStore(clock=clock)
            self.store, self.raw = fake, fake.raw
            self.instance = lambda: fake  # one process: its lock is the only one
            return
        from google.cloud import firestore

        from aiven.gateway.store_firestore import FirestoreStore

        project = f"test-{uuid.uuid4().hex[:12]}"
        client = firestore.Client(project=project, database="gateway")
        self.store = FirestoreStore(client, clock=clock)

        def raw(collection, doc_id):
            snapshot = client.collection(collection).document(doc_id).get()
            return snapshot.to_dict() if snapshot.exists else None

        self.raw = raw
        self.instance = lambda: FirestoreStore(
            firestore.Client(project=project, database="gateway"), clock=clock
        )

    def __iter__(self):  # store, raw = backend
        return iter((self.store, self.raw))


@pytest.fixture(params=["fake", "firestore"])
def backend(request) -> Backend:
    if request.param == "firestore" and not os.environ.get("FIRESTORE_EMULATOR_HOST"):
        if os.environ.get("AIVEN_REQUIRE_EMULATOR") == "1":
            pytest.fail("AIVEN_REQUIRE_EMULATOR=1, but FIRESTORE_EMULATOR_HOST is not set")
        pytest.skip("the Firestore emulator is not running (FIRESTORE_EMULATOR_HOST)")
    return Backend(request.param)


def in_parallel(work, backend: Backend, count: int) -> list:
    """Run `work(store)` `count` times at once, half on each of two instances (section 13: at
    most two), and give the answers."""
    stores = [backend.store, backend.instance()]
    answers: list = []
    lock = threading.Lock()

    def one(store):
        answer = work(store)
        with lock:
            answers.append(answer)

    threads = [threading.Thread(target=one, args=(stores[n % 2],)) for n in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return answers


def a_run(run_id="r_1", **changes) -> RunState:
    values = dict(
        run_id=run_id,
        agent="invoice-reminder",
        policy_sha256=HASH,
        catalog_sha256=CATALOG,
        started_at=NOW,
        deadline=NOW + timedelta(seconds=300),
        status="open",
        stop_reason=None,
        shadow=False,
        tainted=False,
        taint_sources=(),
        records_used=0,
        refusals=0,
    )
    values.update(changes)
    return RunState(**values)


def a_confirm(confirm_id="q_1", **changes) -> ConfirmRecord:
    values = dict(
        confirm_id=confirm_id,
        run_id="r_1",
        call_id="c_1",
        agent="invoice-reminder",
        action="gmail.send",
        cls="R2",
        args={"draft_id": "d1"},
        target={"draft_id": "d1", "revision": "7"},
        preview_en="Send draft d1",
        preview_nl="Verstuur concept d1",
        preview_sha256="a" * 64,
        taint_sources=(),
        status="pending",
        created_at=NOW,
        expires_at=NOW + timedelta(hours=24),
    )
    values.update(changes)
    return ConfirmRecord(**values)


# --- runs


def test_a_run_reads_back_as_it_was_made(backend):
    store, _ = backend
    run = a_run(taint_sources=("f1",), tainted=True, shadow=True)
    store.create_run(run)
    assert store.get_run("r_1") == run
    assert store.get_run("r_other") is None


def test_every_run_and_call_document_expires_after_90_days(backend):
    store, raw = backend
    store.create_run(a_run())
    call_id, _ = store.claim_call("r_1", "req-1")
    store.put_call("r_1", "req-1", StoredCall(call_id, "executed", None, None, cls="R0"), {})
    store.update_run("r_1", records_used=2)
    assert raw("runs", "r_1")["expire_at"] == NOW + TTL
    assert raw("calls", call_id)["expire_at"] == NOW + TTL


def test_update_run_changes_only_the_fields_given(backend):
    store, _ = backend
    store.create_run(a_run())
    store.update_run("r_1", status="stopped", stop_reason="TOO_MANY_REFUSALS")
    assert store.get_run("r_1") == a_run(status="stopped", stop_reason="TOO_MANY_REFUSALS")


def test_taint_adds_sources_once_each(backend):
    store, _ = backend
    store.create_run(a_run())
    store.taint_run("r_1", ("f1", "f2"))
    store.taint_run("r_1", ("f2", "f3"))
    run = store.get_run("r_1")
    assert run.tainted is True and run.taint_sources == ("f1", "f2", "f3")


def test_refusals_are_counted_one_by_one(backend):
    store, _ = backend
    store.create_run(a_run())
    assert [store.count_refusal("r_1") for _ in range(3)] == [1, 2, 3]
    assert store.get_run("r_1").refusals == 3


# --- the day counters and the limits


def test_runs_per_day_are_reserved_up_to_the_limit(backend):
    store, _ = backend
    assert [store.reserve_run("a", "2026-10-14", 2) for _ in range(3)] == [True, True, False]
    assert store.reserve_run("a", "2026-10-15", 2) is True  # a new day
    assert store.reserve_run("b", "2026-10-14", 2) is True  # another agent
    assert store.day_counters("a", "2026-10-14") == DayCounters(runs=2, email_recipients=0)


def test_reserve_takes_records_and_recipients_within_the_limits(backend):
    store, _ = backend
    store.create_run(a_run())
    assert store.reserve("r_1", "invoice-reminder", "2026-10-14", 6, 2, LIMITS) is None
    assert store.reserve("r_1", "invoice-reminder", "2026-10-14", 4, 3, LIMITS) is None
    assert store.get_run("r_1").records_used == 10
    assert store.day_counters("invoice-reminder", "2026-10-14").email_recipients == 5


def test_reserve_names_the_limit_it_would_cross_and_takes_nothing(backend):
    store, _ = backend
    store.create_run(a_run())
    assert store.reserve("r_1", "invoice-reminder", "2026-10-14", 11, 0, LIMITS) == "LIMIT_RECORDS"
    assert store.reserve("r_1", "invoice-reminder", "2026-10-14", 1, 6, LIMITS) == "LIMIT_EMAILS"
    assert store.get_run("r_1").records_used == 0
    assert store.day_counters("invoice-reminder", "2026-10-14") == DayCounters(0, 0)


def test_parallel_reservations_never_exceed_limit(backend):
    # Review focus 1: 20 reservations at once against a limit of 10; exactly 10 succeed.
    backend.store.create_run(a_run())
    results = in_parallel(
        lambda store: store.reserve("r_1", "invoice-reminder", "2026-10-14", 1, 0, LIMITS),
        backend,
        20,
    )
    assert results.count(None) == 10 and results.count("LIMIT_RECORDS") == 10
    assert backend.store.get_run("r_1").records_used == 10


def test_parallel_run_reservations_never_exceed_runs_per_day(backend):
    results = in_parallel(lambda store: store.reserve_run("a", "d", 3), backend, 12)
    assert results.count(True) == 3
    assert backend.store.day_counters("a", "d").runs == 3


# --- calls and idempotency


def test_the_call_id_is_derived_from_run_and_request():
    first = call_id_for("r_1", "req-1")
    assert first == call_id_for("r_1", "req-1")
    assert first != call_id_for("r_1", "req-2") != call_id_for("r_2", "req-1")
    assert first.startswith("c_") and len(first) == 34
    # The request ID is the agent's text: it never reaches a document ID as it is.
    assert "/" not in call_id_for("r_1", "../../runs/r_9")


def test_the_first_claim_wins_and_a_second_sees_the_call(backend):
    store, _ = backend
    store.create_run(a_run())
    call_id, existing = store.claim_call("r_1", "req-1")
    assert existing is None and call_id == call_id_for("r_1", "req-1")
    again_id, pending = store.claim_call("r_1", "req-1")
    assert again_id == call_id and pending.outcome == "pending"
    done = StoredCall(call_id, "executed", None, {"file_id": "f9"}, cls="R1")
    store.put_call("r_1", "req-1", done, {"action": "drive.create"})
    assert store.claim_call("r_1", "req-1") == (call_id, done)
    assert store.get_call("r_1", "req-1") == done
    assert store.get_call("r_1", "req-2") is None


def test_parallel_claims_of_one_request_give_one_winner(backend):
    backend.store.create_run(a_run())
    claims = in_parallel(lambda store: store.claim_call("r_1", "same")[1], backend, 10)
    assert claims.count(None) == 1


def test_calls_are_counted_by_outcome(backend):
    store, _ = backend
    store.create_run(a_run())
    for request, outcome in [("a", "executed"), ("b", "executed"), ("c", "refused")]:
        call_id, _ = store.claim_call("r_1", request)
        store.put_call("r_1", request, StoredCall(call_id, outcome, None, None), {})
    store.claim_call("r_1", "d")  # still pending: not counted
    store.create_run(a_run("r_2"))
    other, _ = store.claim_call("r_2", "a")
    store.put_call("r_2", "a", StoredCall(other, "refused", "NOT_GRANTED", None), {})
    assert store.calls_by_outcome("r_1") == {"executed": 2, "refused": 1}


# --- confirms, proposals, shadow and the active version


def test_a_confirm_reads_back_and_closes_once(backend):
    store, raw = backend
    store.put_confirm(a_confirm())
    assert store.get_confirm("q_1") == a_confirm()
    assert store.close_confirm("q_1", ("pending",), "executed", NOW) is True
    assert store.close_confirm("q_1", ("pending",), "executed", NOW) is False
    assert store.get_confirm("q_1").status == "executed"
    # Args and previews are erased 7 days after the confirm closes (section 5).
    assert raw("confirms", "q_1")["erase_at"] == NOW + timedelta(days=7)
    assert store.get_confirm("q_other") is None


def test_parallel_closes_of_one_confirm_give_one_winner(backend):
    backend.store.put_confirm(a_confirm())
    results = in_parallel(
        lambda store: store.close_confirm("q_1", ("pending",), "approved", NOW), backend, 8
    )
    assert results.count(True) == 1


def test_a_proposal_is_kept(backend):
    store, raw = backend
    store.put_proposal("c_1", "r_1", "invoice-reminder", {"en": "x", "nl": "y", "sha256": "z"})
    kept = raw("proposals", "c_1")
    assert kept["run_id"] == "r_1" and kept["agent"] == "invoice-reminder"
    assert kept["preview"] == {"en": "x", "nl": "y", "sha256": "z"}


def test_shadow_runs_are_counted_with_the_capability_they_cover(backend):
    store, _ = backend
    assert store.get_shadow("a") is None
    assert store.inc_shadow_runs("a", ("drive.read",), "R1") == 1
    assert store.inc_shadow_runs("a", ("drive.read", "drive.create"), "R1") == 2
    assert store.get_shadow("a") == ShadowState(2, ("drive.read", "drive.create"), "R1")


def test_the_active_version_only_goes_up(backend):
    store, _ = backend
    assert store.get_active("a") is None
    v2 = ActiveVersion(2, "sha256:" + "b" * 64)
    assert store.set_active("a", v2) is True
    assert store.set_active("a", ActiveVersion(1, "sha256:" + "c" * 64)) is False
    assert store.set_active("a", ActiveVersion(2, "sha256:" + "d" * 64)) is False
    assert store.set_active("a", v2) is True  # the same version again
    assert store.get_active("a") == v2
    v3 = ActiveVersion(3, "sha256:" + "e" * 64)
    assert store.set_active("a", v3) is True and store.get_active("a") == v3
