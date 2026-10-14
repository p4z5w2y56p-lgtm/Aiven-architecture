"""Control reads (plan Task 3.4; gateway-design sections 5 and 8; M3 flag #1).

`FirestoreControl` reads Firestore `control` (switches, decisions, sign-offs, taint clears) and
`releases` (the published version of each agent) of the control project, on every call, directly.
Anything that goes wrong is `ControlUnavailable`, and the gateway refuses (fail closed): an error,
a document of the wrong shape, a switch that is not true or false. A switch that does not exist is
off; a wrapper without a document is switched on for nobody.

These tests need the Firestore emulator (FIRESTORE_EMULATOR_HOST), as the store's do.
"""

import json
import os
import uuid
from datetime import UTC, datetime

import pytest

from aiven.gateway.control import (
    ControlUnavailable,
    FirestoreControl,
    PolicyVersion,
    fail_closed_line,
)
from aiven.gateway.decide import ControlSnapshot
from aiven.gateway.runs import new_id
from aiven.gateway.store import call_id_for
from tests.support.gen import valid_iban

AT = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
HASH = "sha256:" + "3" * 64


@pytest.fixture
def emulator():
    if not os.environ.get("FIRESTORE_EMULATOR_HOST"):
        if os.environ.get("AIVEN_REQUIRE_EMULATOR") == "1":
            pytest.fail("AIVEN_REQUIRE_EMULATOR=1, but FIRESTORE_EMULATOR_HOST is not set")
        pytest.skip("the Firestore emulator is not running (FIRESTORE_EMULATOR_HOST)")
    from google.cloud import firestore

    project = f"ctl-{uuid.uuid4().hex[:12]}"
    control = firestore.Client(project=project, database="control")
    releases = firestore.Client(project=project, database="releases")
    return control, releases, FirestoreControl(control, releases)


def put(client, path, doc):
    collection, doc_id = path.split("/")
    client.collection(collection).document(doc_id).set(doc)


def test_nothing_set_means_switches_off_and_wrappers_off(emulator):
    _, _, control = emulator
    assert control.read("a", "drive") == ControlSnapshot(False, False, False)
    assert control.read("a", None) == ControlSnapshot(False, False, False)


def test_the_switches_and_the_wrapper_list_are_read(emulator):
    ctl, _, control = emulator
    put(ctl, "killswitch/global", {"on": True, "by": "m", "at": AT, "reason": "x"})
    put(ctl, "killswitch_agents/a", {"on": True, "by": "m", "at": AT, "reason": "x"})
    put(ctl, "wrappers/drive", {"enabled_for": ["a", "b"], "by": "m", "at": AT})
    assert control.read("a", "drive") == ControlSnapshot(True, True, True)
    assert control.read("c", "drive") == ControlSnapshot(True, False, False)
    assert control.read("a", "email") == ControlSnapshot(True, True, False)
    assert control.wrapper_live("drive", "b") is True
    assert control.wrapper_live("drive", "c") is False


@pytest.mark.parametrize(
    ("path", "doc"),
    [
        ("killswitch/global", {"on": "yes"}),
        ("killswitch/global", {"by": "m"}),
        ("killswitch_agents/a", {"on": 1}),
        ("wrappers/drive", {"enabled_for": "a"}),
        ("wrappers/drive", {"enabled_for": ["a", 3]}),
    ],
)
def test_a_document_of_the_wrong_shape_is_unavailable(emulator, path, doc):
    ctl, _, control = emulator
    put(ctl, path, doc)
    with pytest.raises(ControlUnavailable):
        control.read("a", "drive")


def test_any_error_is_unavailable_and_says_only_its_class():
    class Broken:
        def collection(self, name):
            raise RuntimeError("secret detail of the error")

    control = FirestoreControl(Broken(), Broken())
    for read in (
        lambda: control.read("a", "drive"),
        lambda: control.policy_version("a"),
        lambda: control.policy_versions(),
        lambda: control.decision("q_1"),
        lambda: control.signoff("a"),
        lambda: control.taint_cleared("f1", "7"),
        lambda: control.wrapper_live("drive", "a"),
    ):
        with pytest.raises(ControlUnavailable) as raised:
            read()
        assert "secret" not in str(raised.value) and "RuntimeError" in str(raised.value)


# --- the published version (flag #1)


def test_the_published_version_is_read_from_releases(emulator):
    _, rel, control = emulator
    assert control.policy_version("a") is None  # not published: no policy, not "new agent"
    put(rel, "policy_versions/a", {"version": 3, "sha256": HASH, "by": "m", "at": AT})
    put(rel, "policy_versions/b", {"version": 1, "sha256": HASH, "by": "m", "at": AT})
    assert control.policy_version("a") == PolicyVersion(3, HASH, "m", AT)
    assert control.policy_versions() == {
        "a": PolicyVersion(3, HASH, "m", AT),
        "b": PolicyVersion(1, HASH, "m", AT),
    }


@pytest.mark.parametrize(
    "doc",
    [
        {"version": "3", "sha256": HASH, "by": "m", "at": AT},
        {"version": 0, "sha256": HASH, "by": "m", "at": AT},
        {"version": True, "sha256": HASH, "by": "m", "at": AT},
        {"version": 3, "sha256": "sha256:short", "by": "m", "at": AT},
        {"version": 3, "by": "m", "at": AT},
    ],
)
def test_a_record_that_cannot_be_read_is_unavailable_never_none(emulator, doc):
    _, rel, control = emulator
    put(rel, "policy_versions/a", doc)
    with pytest.raises(ControlUnavailable):
        control.policy_version("a")
    with pytest.raises(ControlUnavailable):
        control.policy_versions()


# --- decisions, sign-offs, taint clears


def test_a_decision_is_read_with_its_hash_and_approver(emulator):
    ctl, _, control = emulator
    assert control.decision("q_1") is None
    put(
        ctl,
        "decisions/q_1",
        {"decision": "approve", "preview_sha256": "a" * 64, "by": "m@x", "at": AT},
    )
    decision = control.decision("q_1")
    assert (decision.decision, decision.preview_sha256, decision.by) == ("approve", "a" * 64, "m@x")
    put(
        ctl, "decisions/q_2", {"decision": "maybe", "preview_sha256": "a" * 64, "by": "m", "at": AT}
    )
    with pytest.raises(ControlUnavailable):
        control.decision("q_2")


def test_a_signoff_is_read(emulator):
    ctl, _, control = emulator
    assert control.signoff("a") is None
    put(ctl, "signoffs/a", {"tools": ["drive.read"], "max_class": "R1", "policy_hash": HASH,
                            "shadow_runs_seen": 10, "by": "m", "at": AT})  # fmt: skip
    signoff = control.signoff("a")
    assert signoff.tools == ("drive.read",) and signoff.max_class == "R1"
    put(ctl, "signoffs/b", {"tools": "drive.read", "max_class": "R1"})
    with pytest.raises(ControlUnavailable):
        control.signoff("b")


def test_a_taint_clear_covers_one_file_version_only(emulator):
    ctl, _, control = emulator
    assert control.taint_cleared("f1", "7") is False
    put(ctl, "taint_clears/f1", {"revision": "7", "by": "m", "at": AT})
    assert control.taint_cleared("f1", "7") is True
    assert control.taint_cleared("f1", "8") is False


# --- the fail-closed line (the fallback alert)


def test_control_unreachable_prints_the_fallback_line(capsys):
    fail_closed_line(
        "CONTROL_UNREACHABLE", run_id="r_1", call_id="c_1", agent="a", audit_write_failed=False
    )
    (line,) = capsys.readouterr().out.splitlines()
    assert json.loads(line) == {
        "severity": "ALERT",
        "message": "gateway fails closed",
        "reason": "CONTROL_UNREACHABLE",
        "alert": True,
        "audit_write_failed": False,
        "run_id": "r_1",
        "call_id": "c_1",
        "agent": "a",
    }


def test_fallback_line_holds_no_content(capsys):
    iban = valid_iban()
    fail_closed_line(
        "CONTROL_UNREACHABLE",
        run_id=f"r_1\nIBAN {iban}",
        call_id=None,
        agent="a" * 500,
        audit_write_failed=True,
    )
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 1
    line = json.loads(out)
    assert iban not in out
    assert len(line["agent"]) <= 120 and line["call_id"] is None


def test_the_fallback_line_shows_the_gateways_own_ids_as_they_are(capsys):
    # A run or call ID is hex, which safe_text may take for a digest and hide; the line needs it.
    for _ in range(200):
        call_id = call_id_for(new_id("r_"), "q")
        fail_closed_line(
            "CONTROL_UNREACHABLE",
            run_id="r_" + "0" * 26,
            call_id=call_id,
            agent="invoice-reminder",
            audit_write_failed=False,
        )
        line = json.loads(capsys.readouterr().out)
        assert (line["call_id"], line["agent"]) == (call_id, "invoice-reminder")
