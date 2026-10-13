"""The audit log writer (gateway-design section 5; ruling R107).

The gateway, the control UI and both functions write the audit log through `AuditLog`. The tests
run on a stand-in for the Cloud Logging client: nothing here reaches Google.
"""

import json
import re
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from aiven.common import audit
from aiven.common.audit import AUDIT_LOG, EVENTS, AuditEntry, AuditLog, AuditWriteFailed
from tests.support import REPO_ROOT
from tests.support.gen import secret_values, valid_card

DESIGN = REPO_ROOT / "docs" / "gateway-design.md"


def design_example() -> dict:
    """The example entry of gateway-design section 5, as JSON."""
    text = DESIGN.read_text(encoding="utf-8")
    section = text.split("### Audit entry", 1)[1]
    (example,) = re.findall(r"```json\n(.*?)\n```", section, re.DOTALL)[:1]
    return json.loads(example)


def test_the_events_are_those_of_gateway_design_section_5():
    text = DESIGN.read_text(encoding="utf-8")
    (line,) = [line for line in text.splitlines() if line.startswith("- `event` is one of")]
    assert set(EVENTS) == set(re.findall(r"`([a-z_]+)`", line)) - {"event"}


def test_an_entry_has_exactly_the_fields_of_the_example_in_gateway_design():
    example = design_example()
    entry = AuditEntry(event="call", class_="R1", outcome="executed", approver="policy")
    assert list(entry.payload()) == list(example)


def test_the_example_itself_round_trips():
    example = design_example()
    fields = {("class_" if name == "class" else name): value for name, value in example.items()}
    assert AuditEntry(**fields).payload() == example


def test_audit_entry_rejects_extra_fields():
    with pytest.raises(ValueError, match="no field file_name"):
        AuditEntry(event="call", file_name="invoices.xlsx")


def test_an_unknown_field_is_named_without_repeating_a_secret():
    key = secret_values()["AWS access key"][0]
    with pytest.raises(ValueError) as caught:
        AuditEntry(event="call", **{key: "x"})
    assert key not in str(caught.value)


@pytest.mark.parametrize(
    ("fields", "problem"),
    [
        ({"event": "deleted"}, "event"),
        ({"event": "call", "ts": "2026-10-12 09:15:02"}, "ts"),
        ({"event": "call", "ts": "2026-10-12T09:15:02Z"}, "ts"),
        ({"event": "call", "class_": "R5"}, "class"),
        ({"event": "call", "alert": 1}, "alert"),
        ({"event": "call", "tainted": "no"}, "tainted"),
        ({"event": "call", "taint_sources": "file-1"}, "taint_sources"),
        ({"event": "call", "taint_sources": ["file-1", 2]}, "taint_sources"),
        ({"event": "call", "agent": 7}, "agent"),
        ({"event": "call", "usage": {"model": "m"}}, "run_end"),
        ({"event": "call", "end_reason": "done"}, "run_end"),
        ({"event": "call", "cost_estimate_eur": Decimal("0.01")}, "run_end"),
        ({"event": "run_end", "cost_estimate_eur": 0.01}, "cost_estimate_eur"),
        ({"event": "run_end", "usage": ["model"]}, "usage"),
        ({"event": "control", "note": 5}, "note"),
    ],
)
def test_a_field_of_the_wrong_kind_is_refused(fields, problem):
    with pytest.raises(ValueError, match=problem):
        AuditEntry(**fields)


def test_run_end_carries_usage_cost_and_end_reason():
    entry = AuditEntry(
        event="run_end",
        usage={"model": "gemini", "input_tokens": 1200, "output_tokens": 80},
        cost_estimate_eur=Decimal("0.0042"),
        end_reason="model_refusal",
    )
    payload = entry.payload()
    assert payload["usage"] == {"model": "gemini", "input_tokens": 1200, "output_tokens": 80}
    assert payload["cost_estimate_eur"] == 0.0042
    assert payload["end_reason"] == "model_refusal"
    assert "note" not in payload


def test_a_note_is_written_when_there_is_one():
    entry = AuditEntry(event="control", alert=True, note="Google Cloud credit expires soon.")
    assert entry.payload()["note"] == "Google Cloud credit expires soon."
    assert "usage" not in entry.payload()


@pytest.mark.parametrize("secret", [secret_values()["AWS access key"][0], valid_card()])
def test_a_note_that_holds_a_secret_is_refused_without_repeating_it(secret):
    with pytest.raises(ValueError, match="note") as caught:
        AuditEntry(event="control", note=f"stopped by {secret}")
    assert secret not in str(caught.value)


def test_the_time_is_now_in_utc_to_the_millisecond():
    before = datetime.now(UTC).replace(microsecond=0)
    entry = AuditEntry(event="control")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", entry.ts)
    written = datetime.strptime(entry.ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    assert before <= written <= datetime.now(UTC)


def test_an_entry_is_frozen_and_its_sources_are_a_tuple():
    entry = AuditEntry(event="call", taint_sources=["file-1", "file-2"])
    assert entry.taint_sources == ("file-1", "file-2")
    assert entry.payload()["taint_sources"] == ["file-1", "file-2"]
    with pytest.raises(AttributeError):
        entry.alert = True


# --- the writer


class FakeLogger:
    def __init__(self, calls: list, fail: Exception | None) -> None:
        self.calls, self.fail = calls, fail

    def log_struct(self, payload: dict, severity: str) -> None:
        if self.fail is not None:
            raise self.fail
        self.calls.append((payload, severity))


class FakeClient:
    """A Cloud Logging client that keeps what it is given."""

    def __init__(self, fail: Exception | None = None) -> None:
        self.calls: list = []
        self.names: list = []
        self.fail = fail

    def logger(self, name: str) -> FakeLogger:
        self.names.append(name)
        return FakeLogger(self.calls, self.fail)


def test_write_puts_one_entry_in_log_aiven_audit():
    client = FakeClient()
    entry = AuditEntry(event="budget_stop", alert=True, note="Billing unlinked.")
    AuditLog("aiven-control-test", client=client).write(entry)
    assert client.names == [AUDIT_LOG] == ["aiven-audit"]
    assert client.calls == [(entry.payload(), "ALERT")]


def test_an_entry_without_alert_is_info():
    client = FakeClient()
    AuditLog("aiven-control-test", client=client).write(AuditEntry(event="control"))
    assert [severity for _, severity in client.calls] == ["INFO"]


def test_write_failure_raises():
    client = FakeClient(fail=RuntimeError("the service is unavailable"))
    with pytest.raises(AuditWriteFailed, match="RuntimeError"):
        AuditLog("aiven-control-test", client=client).write(AuditEntry(event="control"))


def test_a_client_that_cannot_be_made_is_a_write_failure(monkeypatch):
    def no_client(project):
        raise OSError("no credentials")

    monkeypatch.setattr(audit, "_logging_client", no_client)
    with pytest.raises(AuditWriteFailed, match="OSError"):
        AuditLog("aiven-control-test").write(AuditEntry(event="control"))


def test_the_client_is_made_once_and_for_the_control_project(monkeypatch):
    made: list = []

    def client_for(project):
        made.append(project)
        return FakeClient()

    monkeypatch.setattr(audit, "_logging_client", client_for)
    log = AuditLog("aiven-control-test")
    log.write(AuditEntry(event="control"))
    log.write(AuditEntry(event="control"))
    assert made == ["aiven-control-test"]


@pytest.mark.parametrize("project", ["", "Aiven-Control", "x", "aiven-control-"])
def test_the_project_must_be_a_project_id(project):
    with pytest.raises(ValueError, match="project"):
        AuditLog(project, client=FakeClient())


def test_terraform_routes_the_same_log_to_the_audit_bucket():
    stores = (REPO_ROOT / "infra" / "terraform" / "modules" / "control" / "stores.tf").read_text()
    assert f'logs/{AUDIT_LOG}\\""' in stores


def test_an_entry_needs_its_event():
    with pytest.raises(ValueError, match="event"):
        AuditEntry(alert=True)


def test_the_real_client_is_made_for_the_control_project(monkeypatch):
    from google.cloud import logging as cloud_logging

    made: list = []
    monkeypatch.setattr(cloud_logging, "Client", lambda project: made.append(project) or "client")
    assert audit._logging_client("aiven-control-test") == "client"
    assert made == ["aiven-control-test"]
