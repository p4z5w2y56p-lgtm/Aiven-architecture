"""The helpers of the one-click apply of M2 (`aiven.m2_oneclick`, run by scripts/m2-oneclick.sh).

The plan of `fixtures/m2-plan.json` is a real one: Terraform 1.16.4 planned infra/terraform for a
fresh deployment against a stand-in for Google (no API call is needed for that), and the plan was
cut down to what the summary reads. Nothing here reaches Google: the Drive calls go to a stand-in
that answers from a table.
"""

import io
import json
import re
from pathlib import Path
from typing import Any

import pytest

from aiven import m2_oneclick
from aiven.common.config_guard import check_file
from aiven.m2_oneclick import (
    ALERT_POLICY,
    DRILL_ADDRESSES,
    DRILL_FUNCTION,
    ValuesError,
    clean_result,
    main,
    read_values,
    render_tfvars,
    summarize,
    write_values,
)
from tests.support import REPO_ROOT
from tests.support.gen import secret_values

FIXTURE = Path(__file__).parent / "fixtures" / "m2-plan.json"
EXAMPLE_TFVARS = REPO_ROOT / "infra" / "terraform" / "terraform.tfvars.example"
EXAMPLE_PLATFORM = REPO_ROOT / "config" / "platform.example.yaml"
VARIABLES = REPO_ROOT / "infra" / "terraform" / "variables.tf"
AWS_KEY = secret_values()["AWS access key"][0]

ANSWERS = {
    "agents_project": "aiven-agents-prod",
    "gateway_project": "aiven-gateway-prod",
    "control_project": "aiven-control-prod",
    "scratch_project": "aiven-scratch-prod",
    "billing_account": "01F2A3-B4C5D6-E7F809",
    "budget_currency": "EUR",
    "alert_email": "owner@aivenstudios.com",
    "agents": ("invoice-reminder",),
    "trusted_authors": ("owner@aivenstudios.com",),
    "sandbox_drive_id": "0AKx7rT2mQpLsUk9PVA",
}


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    """A working folder with the layout of the repository, and variables.tf where it belongs."""
    (tmp_path / "config").mkdir()
    (tmp_path / "infra" / "terraform").mkdir(parents=True)
    (tmp_path / "infra" / "terraform" / "variables.tf").write_bytes(VARIABLES.read_bytes())
    monkeypatch.chdir(tmp_path)
    return tmp_path


TFVARS = Path("infra/terraform/terraform.tfvars")
PLATFORM = Path("config/platform.yaml")


def assignments(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith("#")]


# --- the values


def test_without_the_files_no_value_is_known(repo):
    assert read_values() == {}


def test_the_values_of_the_example_files_count_as_missing(repo):
    TFVARS.write_bytes(EXAMPLE_TFVARS.read_bytes())
    PLATFORM.write_bytes(EXAMPLE_PLATFORM.read_bytes())
    values = read_values()
    for name in ("agents_project", "gateway_project", "billing_account", "trusted_authors"):
        assert name not in values
    assert values["budget_currency"] == "EUR"
    assert values["agents"] == ("invoice-reminder",)


def test_written_values_read_back_and_pass_the_guard(repo):
    written = write_values(dict(ANSWERS))
    assert check_file(TFVARS) == [] and check_file(PLATFORM) == []
    read = read_values()
    for name, value in ANSWERS.items():
        assert read[name] == value, name
    assert written["agents_project"] == "aiven-agents-prod"
    assert "gateway_principal: gateway@aiven-gateway-prod.iam.gserviceaccount.com" in (
        PLATFORM.read_text()
    )


def test_the_terraform_values_have_the_layout_of_the_example_that_terraform_fmt_keeps(repo):
    # The example passes `terraform fmt -check` in CI. With the same names in the same blocks, the
    # file that is written has its `=` in the same columns, whatever the values are.
    example = {
        "agents_project": "aiven-agents-example",
        "gateway_project": "aiven-gateway-example",
        "control_project": "aiven-control-example",
        "scratch_project": "aiven-scratch-example",
        "billing_account": "01ABCD-23EF45-6789AB",
        "budget_currency": "EUR",
        "alert_email": "alerts@aivenstudios.com",
        "agents": ("invoice-reminder",),
    }
    assert assignments(render_tfvars(example)) == assignments(EXAMPLE_TFVARS.read_text())


def test_usd_gets_the_usd_budgets(repo):
    write_values({**ANSWERS, "budget_currency": "USD"})
    text = TFVARS.read_text()
    assert "budget_alert_amount = 11\n" in text and "budget_stop_amount  = 27\n" in text


def test_writing_keeps_the_other_settings_and_the_amounts_already_there(repo):
    write_values(dict(ANSWERS))
    text = TFVARS.read_text().replace("budget_stop_amount  = 25", "budget_stop_amount  = 30")
    TFVARS.write_text(text + "\nbudget_stop_enabled = false\n")
    write_values({"alert_email": "alerts@aivenstudios.com"})
    after = TFVARS.read_text()
    assert "budget_stop_amount  = 30\n" in after
    assert "budget_stop_enabled = false\n" in after
    assert 'alert_email        = "alerts@aivenstudios.com"\n' in after
    assert check_file(TFVARS) == []


def test_without_a_drive_id_the_platform_values_say_it_comes_later(repo):
    write_values({k: v for k, v in ANSWERS.items() if k != "sandbox_drive_id"})
    assert "# sandbox_drive_id: added once the drive exists" in PLATFORM.read_text()
    assert "sandbox_drive_id" not in read_values()


def test_a_drive_id_of_digits_stays_a_string(repo):
    write_values({**ANSWERS, "sandbox_drive_id": "1234567890"})
    assert read_values()["sandbox_drive_id"] == "1234567890"


def test_a_value_that_the_guard_refuses_is_not_kept(repo):
    write_values(dict(ANSWERS))
    before = (TFVARS.read_bytes(), PLATFORM.read_bytes())
    with pytest.raises(ValuesError) as refused:
        write_values({"sandbox_drive_id": AWS_KEY})  # the shape of a drive ID; the scan sees it
    assert "C-SECRET" in str(refused.value) and AWS_KEY not in str(refused.value)
    assert (TFVARS.read_bytes(), PLATFORM.read_bytes()) == before


def test_new_files_that_the_guard_refuses_are_removed(repo):
    with pytest.raises(ValuesError):
        write_values({**ANSWERS, "sandbox_drive_id": AWS_KEY})
    assert not TFVARS.exists() and not PLATFORM.exists()


def test_a_value_that_is_not_ascii_is_refused_and_not_kept(repo):
    with pytest.raises(ValuesError, match="not plain ASCII"):
        write_values({**ANSWERS, "alert_email": "mátthijs@aivenstudios.com"})
    assert not TFVARS.exists() and not PLATFORM.exists()


def test_missing_values_are_named(repo):
    with pytest.raises(ValuesError, match="missing: billing_account, budget_currency"):
        write_values(
            {k: v for k, v in ANSWERS.items() if k not in ("billing_account", "budget_currency")}
        )


def test_two_files_that_name_different_projects_are_refused(repo):
    write_values(dict(ANSWERS))
    PLATFORM.write_text(PLATFORM.read_text().replace("aiven-agents-prod", "aiven-agents-else"))
    with pytest.raises(ValuesError, match="different agents project"):
        read_values()


def test_a_gateway_account_of_another_project_is_refused(repo):
    write_values(dict(ANSWERS))
    PLATFORM.write_text(
        PLATFORM.read_text().replace("gateway@aiven-gateway-prod", "gateway@aiven-gateway-else")
    )
    with pytest.raises(ValuesError, match="another gateway account"):
        read_values()


def test_a_file_that_the_guard_refuses_stops_the_reading_without_its_value(repo):
    write_values(dict(ANSWERS))
    PLATFORM.write_text(PLATFORM.read_text() + f"# {AWS_KEY}\n")
    with pytest.raises(ValuesError) as refused:
        read_values()
    assert "error C-SECRET config/platform.yaml:" in str(refused.value)
    assert AWS_KEY not in str(refused.value)


def test_values_read_prints_name_value_lines(repo, capsys):
    write_values(dict(ANSWERS))
    assert main(["values-read"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "agents=invoice-reminder" in lines
    assert "trusted_authors=owner@aivenstudios.com" in lines
    assert "sandbox_drive_id=0AKx7rT2mQpLsUk9PVA" in lines
    assert all(line.split("=", 1)[0] in m2_oneclick.FIELDS for line in lines)  # no tfvars.* lines


def test_values_write_takes_name_value_pairs(repo, capsys):
    pairs = [f"{k}={','.join(v) if isinstance(v, tuple) else v}" for k, v in ANSWERS.items()]
    assert main(["values-write", *pairs]) == 0
    assert read_values()["agents"] == ("invoice-reminder",)
    assert main(["values-write", "password=x"]) == 1
    assert "not a value to write" in capsys.readouterr().err


# --- the plan summary


def plan() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text())


def resource(doc: dict[str, Any], address: str) -> dict[str, Any]:
    def walk(module):
        yield from module.get("resources", [])
        for child in module.get("child_modules", []):
            yield from walk(child)

    (found,) = [r for r in walk(doc["planned_values"]["root_module"]) if r["address"] == address]
    return found


def test_the_plan_of_a_fresh_deployment_matches_the_runbook():
    done = summarize(plan(), "main")
    assert done.status == 0 and done.refused == []
    assert done.lines[0] == "Terraform plan: 85 to create, 0 to change, 0 to replace, 0 to delete."
    rows = done.lines[1:-1]
    assert len(rows) == 11 and all(row.startswith("  ok  ") for row in rows), rows
    assert any("aiven-alert 10 EUR, aiven-stop 25 EUR" in row for row in rows)
    assert done.lines[-1].startswith("Safety: no service account key, no lock")


def test_a_service_account_key_is_refused():
    doc = plan()
    doc["resource_changes"].append(
        {
            "address": "google_service_account_key.k",
            "mode": "managed",
            "type": "google_service_account_key",
            "change": {"actions": ["create"]},
        }
    )
    done = summarize(doc, "main")
    assert done.status == 3 and "the plan makes a service account key" in done.refused


def test_the_audit_log_lock_is_refused():
    doc = plan()
    resource(doc, "module.control.google_logging_project_bucket_config.audit")["values"][
        "locked"
    ] = True
    done = summarize(doc, "main")
    assert done.status == 3
    assert any("locked = true" in reason for reason in done.refused)
    assert any(row.startswith("  !!  audit log bucket") for row in done.lines)


def test_a_bucket_retention_lock_is_refused():
    doc = plan()
    for module in doc["planned_values"]["root_module"]["child_modules"]:
        for r in module["resources"]:
            if r["type"] == "google_storage_bucket" and r["values"].get("retention_policy"):
                r["values"]["retention_policy"][0]["is_locked"] = True
    done = summarize(doc, "main")
    assert done.status == 3 and any("is_locked = true" in reason for reason in done.refused)


def test_a_role_for_a_person_is_refused():
    doc = plan()
    for module in doc["planned_values"]["root_module"]["child_modules"]:
        for r in module["resources"]:
            if r["type"] == "google_project_iam_member":
                r["values"]["member"] = "user:someone@aivenstudios.com"
                break
    done = summarize(doc, "main")
    assert done.status == 3 and any("user:someone@aivenstudios.com" in r for r in done.refused)


def test_a_count_that_differs_from_the_runbook_is_flagged_and_left_to_the_question():
    doc = plan()
    for module in doc["planned_values"]["root_module"]["child_modules"]:
        module["resources"] = [
            r for r in module["resources"] if r["type"] != "google_firestore_database"
        ]
    done = summarize(doc, "main")
    assert done.status == 0
    assert any(row.startswith("  !!  Firestore databases") for row in done.lines)


def test_deletes_in_the_main_plan_are_shown():
    doc = plan()
    for change in doc["resource_changes"][:3]:
        change["change"]["actions"] = ["delete"]
    doc["resource_changes"].append(
        {
            "address": DRILL_FUNCTION,
            "mode": "managed",
            "type": "google_cloudfunctions2_function",
            "change": {"actions": ["delete"]},
        }
    )
    done = summarize(doc, "main")
    assert done.status == 0
    assert "  WARNING: this plan deletes or replaces 3 resources:" in done.lines
    assert "  The copy of the drill is still there and goes: 1 resources." in done.lines


def drill_plan(mode: str, *, stops: str = "aiven-scratch-mock") -> dict[str, Any]:
    """A plan after the apply: the drill's resources come or go, the alert policy changes."""
    doc = plan()
    for change in doc["resource_changes"]:
        change["change"]["actions"] = ["no-op"] if change["mode"] == "managed" else ["read"]
    action = "create" if mode == "drill-on" else "delete"
    for address in DRILL_ADDRESSES:
        doc["resource_changes"].append(
            {
                "address": address,
                "mode": "managed",
                "type": address.split(".")[2],
                "change": {"actions": [action]},
            }
        )
    alert = next(c for c in doc["resource_changes"] if c["address"] == ALERT_POLICY)
    alert["change"]["actions"] = ["update"]
    if mode == "drill-on":
        control = next(
            m
            for m in doc["planned_values"]["root_module"]["child_modules"]
            if m["address"] == "module.control"
        )
        env = {"STOP_PROJECTS": stops, "STOP_ENABLED": "true"}
        control["resources"].append(
            {
                "address": DRILL_FUNCTION,
                "mode": "managed",
                "type": "google_cloudfunctions2_function",
                "values": {
                    "name": "budget-stop-drill",
                    "service_config": [{"environment_variables": env}],
                },
            }
        )
    return doc


def test_the_drill_switched_on_holds_the_drill_and_stops_scratch_only():
    done = summarize(drill_plan("drill-on"), "drill-on", "aiven-scratch-mock")
    assert done.status == 0, done.refused
    assert "  The drill function stops aiven-scratch-mock only." in done.lines


def test_a_drill_function_that_would_stop_another_project_is_refused():
    doc = drill_plan("drill-on", stops="aiven-agents-mock,aiven-gateway-mock")
    done = summarize(doc, "drill-on", "aiven-scratch-mock")
    assert done.status == 3
    assert any("would stop aiven-agents-mock,aiven-gateway-mock" in r for r in done.refused)


@pytest.mark.parametrize("mode", ["drill-on", "drill-off"])
def test_a_drill_plan_with_anything_else_is_refused(mode):
    doc = drill_plan(mode)
    doc["resource_changes"][0]["change"]["actions"] = ["delete"]
    done = summarize(doc, mode, "aiven-scratch-mock")
    assert done.status == 3
    assert any(f"the {mode} plan would also delete" in r for r in done.refused)


def test_the_drill_switched_off_removes_the_drill_only():
    done = summarize(drill_plan("drill-off"), "drill-off", "aiven-scratch-mock")
    assert done.status == 0, done.refused


def test_plan_summary_on_the_command_line(capsys):
    assert main(["plan-summary", str(FIXTURE)]) == 0
    assert capsys.readouterr().out.startswith("Terraform plan: 85 to create")


def test_a_plan_that_cannot_be_read_is_exit_2_with_the_class_only(tmp_path, capsys):
    bad = tmp_path / "plan.json"
    bad.write_text(f"not json {AWS_KEY}")
    assert main(["plan-summary", str(bad)]) == 2
    err = capsys.readouterr().err
    assert err == "plan-summary could not run (JSONDecodeError)\n"


# --- the result file


def test_the_result_leaves_out_a_line_that_looks_like_a_secret(tmp_path, monkeypatch, capsys):
    text = f"M2 one-click result\nAccount: owner@aivenstudios.com\nnote {AWS_KEY}\nlast line\n"
    assert AWS_KEY not in clean_result(text)
    assert clean_result(text).splitlines() == [
        "M2 one-click result",
        "Account: owner@aivenstudios.com",
        "[line left out: it looked like a secret]",
        "last line",
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    assert main(["result-write", str(tmp_path / "m2-result.txt")]) == 0
    assert AWS_KEY not in (tmp_path / "m2-result.txt").read_text()


def test_the_module_never_handles_a_token_itself():
    # The Drive call takes its login from google.auth; no token is read, printed or passed on.
    source = Path(m2_oneclick.__file__).read_text()
    found = re.search(
        r"print-access-token|\baccess_token\b|\brefresh_token\b|\.token\b", source, re.I
    )
    assert found is None
