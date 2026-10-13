"""The budget stop (gateway-design section 9, runbook budget-stop.md; ruling R108).

Every test runs on stand-ins for Cloud Billing and the audit log: nothing here reaches Google. The
notifications have the fields that Cloud Billing sends to the topic of a budget.
"""

import base64
import json
from decimal import Decimal
from types import SimpleNamespace

import pytest

from aiven.common.audit import AuditWriteFailed
from aiven.functions import budget_stop
from aiven.functions.budget_stop import CloudBilling, StopConfig, StopFailed, handle
from tests.support.gen import valid_card

AGENTS, GATEWAY = "aiven-agents-test", "aiven-gateway-test"
CFG = StopConfig(
    projects=(AGENTS, GATEWAY),
    enabled=True,
    currency="EUR",
    actor="budget-stop@aiven-control-test.iam.gserviceaccount.com",
)


class FakeBilling:
    """Billing per project; `fail` names the projects whose calls raise."""

    def __init__(self, enabled: dict[str, bool] | None = None, fail: set[str] = frozenset()):
        self.enabled = dict(enabled or {AGENTS: True, GATEWAY: True})
        self.fail = set(fail)
        self.unlinked: list[str] = []

    def billing_enabled(self, project: str) -> bool:
        return self.enabled[project]

    def unlink(self, project: str) -> None:
        if project in self.fail:
            raise RuntimeError("the billing API is unavailable")
        self.unlinked.append(project)
        self.enabled[project] = False


class FakeAudit:
    def __init__(self, fail: bool = False) -> None:
        self.entries: list = []
        self.fail = fail

    def write(self, entry) -> None:
        if self.fail:
            raise AuditWriteFailed("the audit log did not take the entry (RuntimeError)")
        self.entries.append(entry)


def notification(cost="25.00", budget="25", name="aiven-stop", currency="EUR") -> dict:
    """A notification as Cloud Billing sends it, with its amounts read as Decimals."""
    return {
        "budgetDisplayName": name,
        "alertThresholdExceeded": 1.0,
        "costAmount": Decimal(cost),
        "costIntervalStart": "2026-10-01T07:00:00Z",
        "budgetAmount": Decimal(budget),
        "budgetAmountType": "SPECIFIED_AMOUNT",
        "currencyCode": currency,
    }


def log_lines(capsys) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


# --- what it does (BD-1, BD-2)


def test_below_amount_does_nothing():
    billing, audit = FakeBilling(), FakeAudit()
    assert handle(notification(cost="24.99"), CFG, billing, audit) == "below"
    assert billing.unlinked == [] and audit.entries == []


def test_other_budget_ignored():
    billing, audit = FakeBilling(), FakeAudit()
    assert handle(
        notification(cost="30", budget="10", name="aiven-alert"), CFG, billing, audit
    ) == ("ignored")
    assert billing.unlinked == [] and audit.entries == []


@pytest.mark.parametrize("cost", ["25.00", "25", "31.50", "1000"])
def test_at_amount_unlinks_each_project(cost):
    billing, audit = FakeBilling(), FakeAudit()
    assert handle(notification(cost=cost), CFG, billing, audit) == "stopped"
    assert billing.unlinked == [AGENTS, GATEWAY]
    assert billing.enabled == {AGENTS: False, GATEWAY: False}


def test_duplicate_notification_is_idempotent():
    billing, audit = FakeBilling(), FakeAudit()
    assert handle(notification(), CFG, billing, audit) == "stopped"
    assert handle(notification(), CFG, billing, audit) == "already_stopped"
    assert handle(notification(cost="40"), CFG, billing, audit) == "already_stopped"
    assert billing.unlinked == [AGENTS, GATEWAY]
    assert len(audit.entries) == 1


def test_a_project_that_was_stopped_before_is_left_alone():
    billing, audit = FakeBilling({AGENTS: False, GATEWAY: True}), FakeAudit()
    assert handle(notification(), CFG, billing, audit) == "stopped"
    assert billing.unlinked == [GATEWAY]
    assert "1 of 2 projects" in audit.entries[0].note


def test_disabled_does_nothing():
    billing, audit = FakeBilling(), FakeAudit()
    cfg = StopConfig(projects=CFG.projects, enabled=False, currency="EUR")
    assert handle(notification(cost="30"), cfg, billing, audit) == "disabled"
    assert handle(notification(cost="24.99"), cfg, billing, audit) == "below"
    assert billing.unlinked == [] and audit.entries == []


def test_stop_writes_budget_stop_entry_with_alert():
    audit = FakeAudit()
    handle(notification(cost="25.03"), CFG, FakeBilling(), audit)
    (entry,) = audit.entries
    assert (entry.event, entry.outcome, entry.reason, entry.alert) == (
        "budget_stop",
        "stopped",
        "BUDGET_EXCEEDED",
        True,
    )
    assert entry.actor == CFG.actor
    assert entry.note == (
        "Budget aiven-stop reached: 25.03 EUR of 25 EUR this month. "
        "Billing was unlinked from 2 of 2 projects; restart with runbook budget-stop.md."
    )


def test_every_notification_logged(capsys):
    billing, audit = FakeBilling(), FakeAudit()
    outcomes = [
        handle(notification(cost="1"), CFG, billing, audit),
        handle(notification(name="aiven-alert"), CFG, billing, audit),
        handle(notification(), CFG, billing, audit),
        handle(notification(), CFG, billing, audit),
        handle({"costAmount": "x"}, CFG, billing, audit),
    ]
    lines = log_lines(capsys)
    assert [line["outcome"] for line in lines] == outcomes
    assert outcomes == ["below", "ignored", "stopped", "already_stopped", "ignored"]
    assert all(line["message"] == "budget notification" for line in lines)
    assert lines[2]["cost"] == "25.00" and lines[2]["budget_amount"] == "25"


# --- what it refuses to act on (fail closed toward stopping only on an unambiguous stop)

MALFORMED = {
    "not-a-mapping": ["aiven-stop"],
    "nothing": None,
    "no-name": {k: v for k, v in notification().items() if k != "budgetDisplayName"},
    "no-cost": {k: v for k, v in notification().items() if k != "costAmount"},
    "no-amount": {k: v for k, v in notification().items() if k != "budgetAmount"},
    "no-currency": {k: v for k, v in notification().items() if k != "currencyCode"},
    "cost-is-text": {**notification(), "costAmount": "25.00"},
    "cost-is-true": {**notification(), "costAmount": True},
    "cost-is-not-a-number": {**notification(), "costAmount": Decimal("NaN")},
    "cost-is-infinite": {**notification(), "costAmount": float("inf")},
    "cost-below-zero": {**notification(), "costAmount": Decimal("-1")},
    "amount-zero": {**notification(), "budgetAmount": Decimal("0")},
    "name-not-text": {**notification(), "budgetDisplayName": 7},
}


@pytest.mark.parametrize("message", MALFORMED.values(), ids=MALFORMED.keys())
def test_a_notification_that_cannot_be_read_is_ignored_with_an_alert(message):
    billing, audit = FakeBilling(), FakeAudit()
    assert handle(message, CFG, billing, audit) == "ignored"
    assert billing.unlinked == []
    (entry,) = audit.entries
    assert (entry.event, entry.outcome, entry.reason, entry.alert) == (
        "budget_stop",
        "ignored",
        "MALFORMED_NOTIFICATION",
        True,
    )


def test_a_notification_in_another_currency_is_ignored_with_an_alert():
    billing, audit = FakeBilling(), FakeAudit()
    assert handle(notification(cost="30", currency="USD"), CFG, billing, audit) == "ignored"
    assert billing.unlinked == []
    (entry,) = audit.entries
    assert (entry.reason, entry.alert) == ("CURRENCY_MISMATCH", True)


def test_a_float_amount_is_read_exactly():
    billing, audit = FakeBilling(), FakeAudit()
    message = {**notification(), "costAmount": 24.99, "budgetAmount": 25}
    assert handle(message, CFG, billing, audit) == "below"


# --- when something fails


def test_a_failed_unlink_writes_an_alert_and_raises_so_pubsub_retries():
    billing, audit = FakeBilling(fail={AGENTS}), FakeAudit()
    with pytest.raises(StopFailed, match="1 of 2"):
        handle(notification(), CFG, billing, audit)
    assert billing.unlinked == [GATEWAY]  # the others are stopped all the same
    (entry,) = audit.entries
    assert (entry.outcome, entry.reason, entry.alert) == ("failed", "UNLINK_FAILED", True)
    # The retry finishes the job.
    billing.fail.clear()
    assert handle(notification(), CFG, billing, audit) == "stopped"
    assert billing.unlinked == [GATEWAY, AGENTS]


def test_a_failed_billing_read_counts_as_a_failed_unlink():
    class Unreadable(FakeBilling):
        def billing_enabled(self, project):
            raise RuntimeError("permission denied")

    audit = FakeAudit()
    with pytest.raises(StopFailed):
        handle(notification(), CFG, Unreadable(), audit)
    assert audit.entries[0].reason == "UNLINK_FAILED"


def test_a_stop_stands_when_the_audit_log_fails_and_its_own_log_raises_the_alert(capsys):
    billing = FakeBilling()
    assert handle(notification(), CFG, billing, FakeAudit(fail=True)) == "stopped"
    assert billing.unlinked == [AGENTS, GATEWAY]
    (line,) = log_lines(capsys)
    assert (line["outcome"], line["alert"], line["audit_write_failed"]) == ("stopped", True, True)
    assert line["severity"] == "ALERT"


def test_a_failed_unlink_raises_even_when_the_audit_log_fails_too(capsys):
    with pytest.raises(StopFailed):
        handle(notification(), CFG, FakeBilling(fail={GATEWAY}), FakeAudit(fail=True))
    (line,) = log_lines(capsys)
    assert line["alert"] is True and line["outcome"] == "failed"


def test_a_log_line_shows_no_more_of_a_name_than_is_safe(capsys):
    key = "AKIA" + "Q" * 16
    handle(notification(name=key), CFG, FakeBilling(), FakeAudit())
    assert key not in capsys.readouterr().out


# --- the configuration, from the environment the function gets from Terraform

ENV = {
    "STOP_PROJECTS": f"{AGENTS},{GATEWAY}",
    "STOP_ENABLED": "true",
    "BUDGET_CURRENCY": "EUR",
    "AUDIT_PROJECT": "aiven-control-test",
    "AUDIT_ACTOR": "budget-stop@aiven-control-test.iam.gserviceaccount.com",
}


def test_the_configuration_comes_from_the_environment():
    cfg = StopConfig.from_env(ENV)
    assert cfg == StopConfig(
        projects=(AGENTS, GATEWAY),
        enabled=True,
        currency="EUR",
        actor="budget-stop@aiven-control-test.iam.gserviceaccount.com",
        audit_project="aiven-control-test",
    )
    assert cfg.budget_name == "aiven-stop"


@pytest.mark.parametrize(
    ("value", "enabled"),
    [("false", False), (" FALSE ", False), ("true", True), ("", True), ("no", True)],
)
def test_only_false_switches_the_stop_off(value, enabled):
    assert StopConfig.from_env({**ENV, "STOP_ENABLED": value}).enabled is enabled


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("STOP_PROJECTS", ""),
        ("STOP_PROJECTS", "aiven-agents-test,"),
        ("STOP_PROJECTS", "Aiven-Agents"),
        ("STOP_PROJECTS", "aiven-agents-test,aiven-agents-test"),
        ("BUDGET_CURRENCY", "GBP"),
        ("BUDGET_CURRENCY", ""),
        ("AUDIT_PROJECT", "Aiven-Control"),
    ],
)
def test_a_configuration_that_makes_no_sense_is_refused(name, value):
    with pytest.raises(ValueError, match=name):
        StopConfig.from_env({**ENV, name: value})


@pytest.mark.parametrize("name", ["STOP_PROJECTS", "BUDGET_CURRENCY", "AUDIT_PROJECT"])
def test_a_missing_setting_is_refused(name):
    with pytest.raises(ValueError, match=name):
        StopConfig.from_env({key: value for key, value in ENV.items() if key != name})


# --- the entry point, as Eventarc calls it


def cloud_event(payload: bytes) -> SimpleNamespace:
    """A CloudEvent of a Pub/Sub message, as Eventarc delivers one."""
    data = {"message": {"data": base64.b64encode(payload).decode(), "messageId": "1"}}
    return SimpleNamespace(data=data)


@pytest.fixture
def wired(monkeypatch):
    """main() with the environment of ENV, and stand-ins for billing and the audit log."""
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    billing, audit = FakeBilling(), FakeAudit()
    projects: list[str] = []
    monkeypatch.setattr(budget_stop, "_billing", lambda: billing)
    monkeypatch.setattr(budget_stop, "_audit", lambda project: projects.append(project) or audit)
    return billing, audit, projects


def test_main_reads_the_pubsub_message_and_stops(wired):
    billing, audit, projects = wired
    message = json.dumps({**notification(), "costAmount": 25.01, "budgetAmount": 25}).encode()
    assert budget_stop.main(cloud_event(message)) == "stopped"
    assert billing.unlinked == [AGENTS, GATEWAY]
    assert projects == ["aiven-control-test"]
    assert audit.entries[0].note.startswith("Budget aiven-stop reached: 25.01 EUR of 25 EUR")


@pytest.mark.parametrize("payload", [b"not json", b"\xff\xfe", b'{"costAmount": 1e400}'])
def test_main_ignores_a_message_it_cannot_read_with_an_alert(wired, payload):
    billing, audit, _ = wired
    assert budget_stop.main(cloud_event(payload)) == "ignored"
    assert billing.unlinked == []
    assert audit.entries[0].reason == "MALFORMED_NOTIFICATION"


def test_main_ignores_an_event_without_a_message_with_an_alert(wired):
    billing, audit, _ = wired
    assert budget_stop.main(SimpleNamespace(data={"subscription": "x"})) == "ignored"
    assert audit.entries[0].reason == "MALFORMED_NOTIFICATION"


# --- Cloud Billing


class FakeBillingClient:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.updates: list = []

    def get_project_billing_info(self, name: str):
        return SimpleNamespace(name=name, billing_enabled=self.enabled)

    def update_project_billing_info(self, name: str, project_billing_info):
        self.updates.append((name, project_billing_info.billing_account_name))


def test_cloud_billing_reads_and_unlinks_by_project_name():
    client = FakeBillingClient(enabled=True)
    billing = CloudBilling(client=client)
    assert billing.billing_enabled(AGENTS) is True
    billing.unlink(AGENTS)
    assert client.updates == [(f"projects/{AGENTS}", "")]


def test_another_budget_is_ignored_by_its_name_even_when_the_rest_cannot_be_read(capsys):
    audit = FakeAudit()
    message = {"budgetDisplayName": "aiven-alert", "costAmount": "x"}
    assert handle(message, CFG, FakeBilling(), audit) == "ignored"
    assert audit.entries == []
    (line,) = log_lines(capsys)
    assert (line["budget"], line["cost"], line["budget_amount"]) == ("aiven-alert", None, None)


def test_the_real_billing_and_audit_log_are_made_without_a_key(monkeypatch):
    from google.cloud import billing_v1

    monkeypatch.setattr(billing_v1, "CloudBillingClient", lambda: FakeBillingClient(enabled=False))
    billing = budget_stop._billing()
    assert isinstance(billing, CloudBilling) and billing.billing_enabled(AGENTS) is False
    log = budget_stop._audit("aiven-control-test")
    assert log.project == "aiven-control-test"


def test_a_failed_unlink_names_the_class_of_its_error_and_nothing_more(capsys):
    class Denied(Exception):
        pass

    class Refusing(FakeBilling):
        def unlink(self, project):
            raise Denied(f"no permission on {project}, token abc123")

    with pytest.raises(StopFailed):
        handle(notification(), CFG, Refusing(), FakeAudit())
    out = capsys.readouterr().out
    (line,) = [json.loads(each) for each in out.splitlines()]
    assert line["errors"] == ["Denied", "Denied"]
    assert "abc123" not in out


def test_a_stop_stands_when_its_note_cannot_be_written(capsys):
    # A cost that reads like a card number makes the entry refuse its note (is_sensitive).
    billing, audit, card = FakeBilling(), FakeAudit(), valid_card()
    assert handle(notification(cost=card), CFG, billing, audit) == "stopped"
    assert billing.unlinked == [AGENTS, GATEWAY] and audit.entries == []
    out = capsys.readouterr().out
    (line,) = [json.loads(each) for each in out.splitlines()]
    assert (line["alert"], line["audit_write_failed"]) == (True, True)
    assert card not in out  # every value from the notification goes through safe_text
