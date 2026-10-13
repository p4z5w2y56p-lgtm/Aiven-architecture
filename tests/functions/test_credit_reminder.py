"""The credit reminder (gateway-design section 14; plan Task 2.4; ruling R109).

The tests run on a stand-in for the audit log: nothing here reaches Google.
"""

import json
from datetime import UTC, date, datetime
from types import SimpleNamespace

import pytest

from aiven.common.audit import AuditWriteFailed
from aiven.functions import credit_reminder
from aiven.functions.credit_reminder import ReminderConfig, remind, reminder_text

CFG = ReminderConfig(
    expiry=date(2027, 1, 4),
    actor="credit-reminder@aiven-control-test.iam.gserviceaccount.com",
    audit_project="aiven-control-test",
)
PLAN_TEXT = (
    "Google Cloud credit expires on 2027-01-04 (\N{EURO SIGN}252.56 at the upgrade). "
    "Check what is left; from then on all usage is billed."
)


class FakeAudit:
    def __init__(self, fail: bool = False) -> None:
        self.entries: list = []
        self.fail = fail

    def write(self, entry) -> None:
        if self.fail:
            raise AuditWriteFailed("the audit log did not take the entry (RuntimeError)")
        self.entries.append(entry)


def log_lines(capsys) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_the_text_is_the_plans():
    assert reminder_text(date(2027, 1, 4)) == PLAN_TEXT


def test_reminder_writes_alert_entry(capsys):
    audit = FakeAudit()
    assert remind(date(2026, 12, 20), CFG, audit) == "reminded"
    (entry,) = audit.entries
    assert (entry.event, entry.reason, entry.alert, entry.note) == (
        "control",
        "CREDIT_EXPIRY",
        True,
        PLAN_TEXT,
    )
    assert entry.actor == CFG.actor
    (line,) = log_lines(capsys)
    assert (line["outcome"], line["alert"]) == ("reminded", False)


@pytest.mark.parametrize("today", [date(2026, 10, 14), date(2026, 12, 20), date(2027, 1, 4)])
def test_it_reminds_up_to_and_on_the_day_the_credit_ends(today):
    # A run by hand before then (gcloud scheduler jobs run credit-reminder) is the test of the
    # email (plan Task 2.4).
    audit = FakeAudit()
    assert remind(today, CFG, audit) == "reminded"
    assert len(audit.entries) == 1


@pytest.mark.parametrize("today", [date(2027, 1, 5), date(2027, 12, 20), date(2030, 12, 20)])
def test_after_the_credit_ended_a_yearly_run_stays_silent(today, capsys):
    audit = FakeAudit()
    assert remind(today, CFG, audit) == "expired"
    assert audit.entries == []
    (line,) = log_lines(capsys)
    assert (line["outcome"], line["alert"]) == ("expired", False)


def test_the_day_is_the_day_in_amsterdam():
    # 23:30 UTC on 4 January is already 5 January in Amsterdam (UTC+1 in winter).
    assert credit_reminder._today(datetime(2027, 1, 4, 23, 30, tzinfo=UTC)) == date(2027, 1, 5)
    assert credit_reminder._today(datetime(2026, 12, 19, 23, 30, tzinfo=UTC)) == date(2026, 12, 20)
    assert isinstance(credit_reminder._today(), date)


def test_a_reminder_the_audit_log_does_not_take_raises():
    with pytest.raises(AuditWriteFailed):
        remind(date(2026, 12, 20), CFG, FakeAudit(fail=True))


# --- the configuration, from the environment the function gets from Terraform

ENV = {
    "CREDIT_EXPIRY": "2027-01-04",
    "AUDIT_PROJECT": "aiven-control-test",
    "AUDIT_ACTOR": "credit-reminder@aiven-control-test.iam.gserviceaccount.com",
}


def test_the_configuration_comes_from_the_environment():
    assert ReminderConfig.from_env(ENV) == CFG
    assert (
        ReminderConfig.from_env({k: v for k, v in ENV.items() if k != "AUDIT_ACTOR"}).actor is None
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CREDIT_EXPIRY", ""),
        ("CREDIT_EXPIRY", "2027-13-04"),
        ("CREDIT_EXPIRY", "20270104"),
        ("CREDIT_EXPIRY", "4 January 2027"),
        ("AUDIT_PROJECT", ""),
        ("AUDIT_PROJECT", "Aiven-Control"),
    ],
)
def test_a_configuration_that_makes_no_sense_is_refused(name, value):
    with pytest.raises(ValueError, match=name):
        ReminderConfig.from_env({**ENV, name: value})


@pytest.mark.parametrize("name", ["CREDIT_EXPIRY", "AUDIT_PROJECT"])
def test_a_missing_setting_is_refused(name):
    with pytest.raises(ValueError, match=name):
        ReminderConfig.from_env({key: value for key, value in ENV.items() if key != name})


# --- the entry point, as Cloud Scheduler calls it


@pytest.fixture
def wired(monkeypatch):
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    audit = FakeAudit()
    projects: list[str] = []
    monkeypatch.setattr(
        credit_reminder, "_audit", lambda project: projects.append(project) or audit
    )
    monkeypatch.setattr(credit_reminder, "_today", lambda: date(2026, 12, 20))
    return audit, projects


def test_main_writes_the_reminder(wired):
    audit, projects = wired
    assert credit_reminder.main(SimpleNamespace()) == ("reminded", 200)
    assert projects == ["aiven-control-test"]
    assert audit.entries[0].note == PLAN_TEXT


def test_main_fails_and_raises_the_alert_itself_when_the_audit_log_fails(wired, capsys):
    audit, _ = wired
    audit.fail = True
    body, status = credit_reminder.main(SimpleNamespace())
    assert status == 500 and "audit log" in body
    (line,) = log_lines(capsys)
    assert (line["outcome"], line["alert"], line["audit_write_failed"]) == ("failed", True, True)
    assert line["severity"] == "ALERT"


def test_the_real_audit_log_is_for_the_control_project():
    assert credit_reminder._audit("aiven-control-test").project == "aiven-control-test"
