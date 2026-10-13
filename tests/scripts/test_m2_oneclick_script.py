"""`scripts/m2-oneclick.sh`, the one-click apply of M2: shellcheck, and dry runs against a mock.

The mock (tests/scripts/oneclick_mock) is a `gcloud` that answers as Google would for a fresh
deployment and writes down every call, a `uname` that says macOS, a `brew` that must not be
called, and a `curl` that downloads something that is not Terraform. Terraform itself is real
(1.16.4, as the script demands) and plans the real infra/terraform: on a first run it needs no API
call, so a stand-in token (GOOGLE_OAUTH_ACCESS_TOKEN) is all it gets. Nothing reaches Google.

The dry runs need Terraform 1.16.4 on the PATH and its providers (from the registry, or a mirror
in TF_CLI_CONFIG_FILE). Without them they are skipped, unless AIVEN_REQUIRE_MOCK_RUN=1 (CI's
terraform job sets it), which makes a missing Terraform a failure.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aiven.common.config_guard import check_file
from tests.support import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "m2-oneclick.sh"
MOCK = Path(__file__).parent / "oneclick_mock"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "m2-apply.md"

# What a dry run may never call: everything that changes something in Google Cloud.
CHANGES = (
    "services enable",
    "add-iam-policy-binding",
    "buckets create",
    "buckets update",
    "scheduler jobs run",
    "pubsub topics publish",
    "billing projects link",
    "run services update",
)


def test_shellcheck_finds_nothing():
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck is not installed (CI runs it as a step of its own)")
    scripts = [SCRIPT, REPO_ROOT / ".githooks" / "pre-commit", *sorted(MOCK.iterdir())]
    done = subprocess.run(["shellcheck", *map(str, scripts)], capture_output=True, text=True)
    assert done.returncode == 0, done.stdout


def test_the_script_checks_terraform_against_the_hashes_of_the_runbook():
    text = SCRIPT.read_text()
    runbook = RUNBOOK.read_text()
    for arch in ("darwin_arm64", "darwin_amd64"):
        (in_script,) = re.findall(rf'TF_SHA256_{arch}="([0-9a-f]{{64}})"', text)
        (in_runbook,) = re.findall(
            rf"`terraform_1\.16\.4_{arch}\.zip` \| `([0-9a-f]{{64}})`", runbook
        )
        assert in_script == in_runbook, arch
    assert 'TF_VERSION="1.16.4"' in text


def test_the_script_is_strict_bash_that_never_prints_a_token_or_locks_the_audit_log():
    text = SCRIPT.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "\nset -Eeuo pipefail\n" in text
    assert b"\r" not in SCRIPT.read_bytes()
    assert os.access(SCRIPT, os.X_OK)
    assert "print-access-token" not in text and "print-identity-token" not in text
    assert "locked = true" not in text and "--locked" not in text
    # No Drive scope anywhere: Google blocks it for gcloud's login, and the browser then never
    # comes back, which would hang the run (ruling R162).
    assert "auth/drive" not in text and "--scopes" not in text
    assert "aiven-deploy-check keys apis iam stores budgets" in text
    # The drill publishes on the drill's own topic only, never on the real budget-stop topic.
    assert re.findall(r"pubsub topics publish (\S+)", text) == ['"$DRILL_TOPIC"']
    assert 'DRILL_TOPIC="budget-stop-drill"' in text


def test_the_part_before_bash_4_is_plain_enough_for_bash_3_2():
    # macOS starts the script with bash 3.2. Until it has a newer bash, the script uses nothing
    # that bash 3.2 lacks: no `[[`, no arrays it writes, no `declare`, no `${x,,}`, no `mapfile`.
    text = SCRIPT.read_text()
    head = text[: text.index("\nset -Eeuo pipefail\n")]
    for later in ("[[", "declare", "mapfile", "readarray", ",,}", "^^}", "+=(", "|&", "&>>"):
        assert later not in head, later


# --- dry runs against the mock


def terraform_dir() -> Path | None:
    found = shutil.which("terraform")
    if found is None:
        return None
    version = subprocess.run([found, "version"], capture_output=True, text=True).stdout
    return Path(found).parent if version.startswith("Terraform v1.16.4\n") else None


@pytest.fixture(scope="module")
def copy_of_the_repository(tmp_path_factory) -> Path:
    """The repository as Git has it (with what is not committed yet), in a folder of its own."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout
    copy = tmp_path_factory.mktemp("oneclick") / "repo"
    for name in filter(None, listed.decode().split("\0")):
        source = REPO_ROOT / name
        if source.is_file() and not name.startswith(("config/platform.yaml", "m2-result")):
            target = copy / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    (copy / "infra" / "terraform" / "terraform.tfvars").unlink(missing_ok=True)
    return copy


@pytest.fixture
def needs_terraform() -> None:
    if terraform_dir() is None:
        if os.environ.get("AIVEN_REQUIRE_MOCK_RUN") == "1":
            pytest.fail("Terraform 1.16.4 is not on the PATH, and the mock run is required here")
        pytest.skip("the dry runs need Terraform 1.16.4 on the PATH")


def run(
    repo: Path,
    tmp_path: Path,
    *options: str,
    answers: str = "",
    terraform: bool = True,
    **mock: str,
) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run the script in `repo` against the mock: the process, and the gcloud calls it made."""
    calls = tmp_path / "calls.log"
    calls.touch()
    temp = tmp_path / "tmp"
    temp.mkdir(exist_ok=True)
    if terraform:
        found = terraform_dir()
    else:  # a Terraform of another version comes first, so the script downloads one
        found = tmp_path / "old-terraform"
        found.mkdir(exist_ok=True)
        old = found / "terraform"
        old.write_text("#!/bin/sh\necho 'Terraform v1.5.7'\n")
        old.chmod(0o755)
    env = {
        **{
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("CLOUDSDK_", "GOOGLE_", "MOCK_"))
        },
        # The mock comes first, so its gcloud, uname, brew and curl are the ones the script finds.
        "PATH": os.pathsep.join([str(MOCK), str(found), os.environ["PATH"]]),
        "TMPDIR": str(temp),
        "MOCK_LOG": str(calls),
        "GOOGLE_OAUTH_ACCESS_TOKEN": "mock",  # Terraform's provider: a stand-in, never a real token
        **mock,
    }
    done = subprocess.run(
        ["bash", str(repo / "scripts" / "m2-oneclick.sh"), *options],
        input=answers,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )
    return done, calls.read_text().splitlines()


def logins_are_gone(tmp_path: Path, calls: list[str]) -> bool:
    revoked = (
        "auth application-default revoke --quiet" in calls and "auth revoke --all --quiet" in calls
    )
    left = list((tmp_path / "tmp").glob("aiven-m2-gcloud.*"))
    return revoked and not left


def reset(repo: Path) -> None:
    """No values, no state, no report: as before the first run."""
    for name in (
        "config/platform.yaml",
        "infra/terraform/terraform.tfvars",
        "m2-result.txt",
        ".m2-oneclick/state",
    ):
        (repo / name).unlink(missing_ok=True)


# Enter for the billing account and its currency (both found), Enter for the alert address (the
# login), then the Sandbox drive ID.
FRESH_ANSWERS = "\n\n\n0AKx7rT2mQpLsUk9PVA\n"
ONLY_MINE = {"MOCK_PROJECTS": "my-first-project-511521"}  # one project of Matthijs's own, as now
PLANNED = re.compile(r"^ {5}(agents|gateway|control|scratch): (aiven-[a-z]+-[0-9a-f]{6})$", re.M)


def planned(out: str) -> dict[str, str]:
    return dict(PLANNED.findall(out))


def test_a_dry_run_without_projects_shows_the_four_it_would_make_and_changes_nothing(
    copy_of_the_repository, tmp_path, needs_terraform
):
    repo = copy_of_the_repository
    reset(repo)
    done, calls = run(repo, tmp_path, "--dry-run", answers=FRESH_ANSWERS, **ONLY_MINE)
    out = done.stdout + done.stderr
    assert done.returncode == 0, out
    assert not [call for call in calls if any(change in call for change in CHANGES)], calls
    assert not [call for call in calls if call.startswith(("brew", "projects create"))]
    assert not [call for call in calls if "my-first-project-511521" in call]  # never touched
    assert logins_are_gone(tmp_path, calls)
    assert "auth application-default login --quiet" in calls  # no Drive scope asked for

    # The projects it would make: aiven-<role>-<one suffix>, and no question in a dry run.
    ids = planned(out)
    assert sorted(ids) == ["agents", "control", "gateway", "scratch"]
    assert len({value.rsplit("-", 1)[1] for value in ids.values()}) == 1
    assert all(value.startswith(f"aiven-{role}-") for role, value in ids.items())
    assert "Make these" not in out
    assert f"NOTE projects: a full run makes: {ids['agents']} " in out

    # The values: in the dry run's own folder, never in the repository, and passed by the guard.
    assert not (repo / "config" / "platform.yaml").exists()
    assert not (repo / "infra" / "terraform" / "terraform.tfvars").exists()
    values = repo / ".m2-oneclick" / "dry-run-values"
    tfvars = values / "infra" / "terraform" / "terraform.tfvars"
    platform = values / "config" / "platform.yaml"
    assert check_file(tfvars) == [] and check_file(platform) == []
    assert f'control_project = "{ids["control"]}"' in tfvars.read_text()
    assert 'billing_account     = "01F2A3-B4C5D6-E7F809"' in tfvars.read_text()
    assert 'sandbox_drive_id: "0AKx7rT2mQpLsUk9PVA"' in platform.read_text()

    # The plan: what the runbook says, and nothing that it forbids.
    assert "Terraform plan: 87 to create, 0 to change, 0 to replace, 0 to delete." in out
    rows = [line for line in out.splitlines() if re.match(r"^ {5}(ok|!!) ", line)]
    assert len(rows) == 11 and all(row.startswith("     ok ") for row in rows), rows
    assert "NOTE org-policy-admin: you do not have it yet: a full run grants it" in out
    assert f"NOTE state-bucket: gs://{ids['control']}-tfstate does not exist yet" in out
    assert "Dry run: nothing was applied, and nothing changed in Google Cloud." in out
    assert "Apply?" not in out

    result = (repo / "m2-result.txt").read_text()
    assert "Mode: dry run (nothing applied)" in result
    assert "NOTE projects: a full run makes:" in result
    assert "PASS plan: dry run: planned, nothing applied" in result
    assert "Terraform plan: 87 to create" in result
    assert "mock" not in result.replace("-mock", "")  # the stand-in token is nowhere in it


def test_a_second_dry_run_shows_the_same_projects(
    copy_of_the_repository, tmp_path, needs_terraform
):
    repo = copy_of_the_repository
    reset(repo)
    first, _ = run(repo, tmp_path, "--dry-run", answers=FRESH_ANSWERS, **ONLY_MINE)
    again, calls = run(repo, tmp_path, "--dry-run", answers=FRESH_ANSWERS, **ONLY_MINE)
    assert again.returncode == 0, again.stdout + again.stderr
    assert planned(again.stdout) == planned(first.stdout) != {}
    assert not [call for call in calls if call.startswith("projects create")]


def test_a_dry_run_with_values_already_there_asks_nothing(
    copy_of_the_repository, tmp_path, needs_terraform
):
    repo = copy_of_the_repository
    reset(repo)
    pairs = [
        "agents_project=aiven-agents-mock",
        "gateway_project=aiven-gateway-mock",
        "control_project=aiven-control-mock",
        "scratch_project=aiven-scratch-mock",
        "billing_account=01F2A3-B4C5D6-E7F809",
        "budget_currency=EUR",
        "alert_email=owner@aivenstudios.com",
        "agents=invoice-reminder",
        "trusted_authors=owner@aivenstudios.com",
        "sandbox_drive_id=0AKx7rT2mQpLsUk9PVA",
    ]
    command = [sys.executable, "-m", "aiven.m2_oneclick", "values-write", "--root", str(repo)]
    subprocess.run(
        [*command, *pairs], check=True, env={**os.environ, "PYTHONPATH": str(repo / "src")}
    )
    before = (repo / "infra" / "terraform" / "terraform.tfvars").read_bytes()
    done, calls = run(repo, tmp_path, "--dry-run", answers="")  # no answers to give
    assert done.returncode == 0, done.stdout + done.stderr
    assert "Terraform plan: 87 to create" in done.stdout
    assert "NOTE state-bucket: gs://aiven-control-mock-tfstate does not exist yet" in done.stdout
    assert not [call for call in calls if call.startswith(("projects list", "projects create"))]
    assert (repo / "infra" / "terraform" / "terraform.tfvars").read_bytes() == before
    reset(repo)


def test_an_account_outside_aiven_stops_before_anything(
    copy_of_the_repository, tmp_path, needs_terraform
):
    done, calls = run(
        copy_of_the_repository, tmp_path, "--dry-run", MOCK_ACCOUNT="someone@gmail.com"
    )
    assert done.returncode == 3
    assert (
        "STOPPED: you logged in as someone@gmail.com, not with an @aivenstudios.com account"
        in done.stderr
    )
    assert "projects list --format=value(projectId)" not in calls
    assert logins_are_gone(tmp_path, calls)


def test_a_terraform_download_with_another_hash_is_thrown_away(copy_of_the_repository, tmp_path):
    repo = copy_of_the_repository
    done, _ = run(repo, tmp_path, "--dry-run", terraform=False)
    assert done.returncode == 3
    assert "STOPPED: the Terraform download does not have the SHA-256 of the runbook" in done.stderr
    assert not (repo / ".m2-oneclick" / "download" / "terraform_1.16.4_darwin_arm64.zip").exists()
    assert not (repo / ".m2-oneclick" / "bin" / "terraform").exists()


def test_help_shows_the_header_and_does_nothing(tmp_path):
    done = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert done.returncode == 0
    assert done.stdout.startswith("M2 in one go: everything of docs/runbooks/m2-apply.md")
    assert "Apply? (y/n)" in done.stdout


def test_an_unknown_option_is_refused(tmp_path):
    done = subprocess.run(["bash", str(SCRIPT), "--apply-now"], capture_output=True, text=True)
    assert done.returncode == 2
    assert "Unknown option: --apply-now" in done.stderr


# --- the steps after the apply, against the mock in its stateful mode
#
# These source the script (it runs `main` only when it is run, not sourced), and call its steps:
# the credit reminder, drills BD-1 and BD-2, and the Sandbox. The mock gcloud plays billing per
# project and the drill's copy of the budget stop; Terraform is a stand-in that shows the plans
# put in MOCK_PLANS. Waiting is three tries without sleeping, on the mock's own clock.

HARNESS = """
source "$REPO/scripts/m2-oneclick.sh"
sleep() { :; }
now() {
  local n
  n=$(($(cat "$MOCK_STATE/clock" 2>/dev/null || echo 0) + 1))
  echo "$n" >"$MOCK_STATE/clock"
  printf '2026-10-13T10:%02d:%02dZ' $((n / 60)) $((n % 60))
}
wait_until() {
  local try
  shift 2
  for try in 1 2 3; do "$@" && return 0; done
  return 1
}
helper() { "$PYTHON" -m aiven.m2_oneclick "$@"; }
check_config() {
  "$PYTHON" -c 'import sys; from aiven.common.config_guard import main; sys.exit(main(sys.argv[1:]))' "$@"
}
TF="$FAKE_TERRAFORM" TFRUN="$REPO/infra/terraform" DRY_RUN=0 ACCOUNT=owner@aivenstudios.com
V_agents_project=aiven-agents-mock V_gateway_project=aiven-gateway-mock
V_control_project=aiven-control-mock V_scratch_project=aiven-scratch-mock
V_billing_account=01F2A3-B4C5D6-E7F809 V_budget_currency=EUR STOP_AMOUNT=25
V_alert_email=owner@aivenstudios.com V_sandbox_drive_id=0AKx7rT2mQpLsUk9PVA
"""


def after_apply(
    repo: Path,
    tmp_path: Path,
    steps: str,
    plans: dict | None = None,
    *,
    answers: str = "",
    keep_state: bool = False,
    **mock: str,
):
    """Run `steps` (bash) after the harness: the process, the mock's calls, and its state folder.

    `answers` are what is typed at the questions; `keep_state` keeps the script's
    .m2-oneclick/state and the mock's projects from a run before (in the same tmp_path)."""
    import json

    from tests.scripts.test_m2_oneclick import drill_plan

    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    planned = tmp_path / "plans"
    planned.mkdir(exist_ok=True)
    for mode in ("drill-on", "drill-off"):
        doc = (plans or {}).get(mode) or drill_plan(mode)
        (planned / f"{mode}.json").write_text(json.dumps(doc))
    calls = tmp_path / "calls.log"
    calls.touch()
    if not keep_state:
        (repo / ".m2-oneclick" / "state").unlink(missing_ok=True)
    env = {
        **{
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("CLOUDSDK_", "GOOGLE_", "MOCK_"))
        },
        "PATH": os.pathsep.join([str(MOCK), os.environ["PATH"]]),
        "REPO": str(repo),
        "PYTHON": sys.executable,
        "PYTHONPATH": str(repo / "src"),
        "FAKE_TERRAFORM": str(MOCK / "fake-terraform"),
        "MOCK_LOG": str(calls),
        "MOCK_STATE": str(state),
        "MOCK_PLANS": str(planned),
        **mock,
    }
    done = subprocess.run(
        ["bash", "-c", HARNESS + steps],
        input=answers,
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return done, calls.read_text().splitlines(), state


def lines(done: subprocess.CompletedProcess, prefix: str) -> list[str]:
    return [line.strip() for line in done.stdout.splitlines() if line.strip().startswith(prefix)]


def test_the_reminder_and_both_drills_pass_and_are_not_run_twice(copy_of_the_repository, tmp_path):
    done, calls, state = after_apply(
        copy_of_the_repository, tmp_path, "reminder; drills; sandbox; reminder; drills"
    )
    assert done.returncode == 0, done.stdout + done.stderr
    passed = [line.split(":")[0] for line in lines(done, "PASS ")]
    assert passed == [
        "PASS credit-reminder",
        "PASS bd1-unlink",
        "PASS bd1-audit",
        "PASS bd1-real-projects",
        "PASS bd2-relink",
        "PASS bd2-below",
        "PASS bd2-below-billing",
        "PASS bd2-disabled",
        "PASS bd2-disabled-billing",
        "PASS bd2-first",
        "PASS bd2-second",
        "PASS bd2-one-entry",
        "PASS drills",
        "PASS credit-reminder",
        "PASS drills",
    ]
    assert lines(done, "FAIL ") == []
    assert "not run again, so no second email" in done.stdout
    assert "passed before" in done.stdout
    # The Sandbox is by hand: Google refuses the Drive scope to gcloud's login (ruling R162).
    (manual,) = lines(done, "MANUAL sandbox-member")
    assert "add gateway@aiven-gateway-mock.iam.gserviceaccount.com as Contributor" in manual
    (check,) = lines(done, "MANUAL sandbox-check")
    assert "exactly you (Manager) and gateway@aiven-gateway-mock" in check
    # Put back as it was: billing on scratch, the copy switched on again, then removed.
    assert (state / "billing-aiven-scratch-mock").read_text() == "True\n"
    assert (state / "stop-enabled").read_text() == "true\n"
    terraform = [call for call in calls if call.startswith("terraform ")]
    assert [call.split()[2] for call in terraform] == [
        "plan",
        "show",
        "apply",
        "plan",
        "show",
        "apply",
    ]
    assert (
        "-var=budget_stop_drill=true" in terraform[0]
        and "-var=budget_stop_drill=false" in terraform[3]
    )
    # Once: one reminder, and one drill.
    assert sum(call.startswith("scheduler jobs run") for call in calls) == 1
    assert all("budget-stop-drill" in call for call in calls if call.startswith("pubsub"))
    assert sum(call.startswith("pubsub topics publish") for call in calls) == 5


def test_a_drill_that_does_not_stop_fails_and_still_puts_everything_back(
    copy_of_the_repository, tmp_path
):
    done, calls, state = after_apply(
        copy_of_the_repository, tmp_path, "drills", MOCK_DRILL_BROKEN="1"
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert lines(done, "FAIL ") == [
        "FAIL bd1-unlink: billing of aiven-scratch-mock still on 5 minutes after publishing",
        "FAIL drills: stopped at bd1-unlink; scratch linked again, drill copy removed",
    ]
    terraform = [call.split()[2] for call in calls if call.startswith("terraform ")]
    assert terraform == ["plan", "show", "apply", "plan", "show", "apply"]  # switched off again
    assert "drills=PASS" not in (copy_of_the_repository / ".m2-oneclick" / "state").read_text()


def test_a_drill_plan_with_more_than_the_drill_is_not_applied(copy_of_the_repository, tmp_path):
    from tests.scripts.test_m2_oneclick import drill_plan

    wider = drill_plan("drill-on")
    wider["resource_changes"][0]["change"]["actions"] = ["delete"]
    done, calls, _ = after_apply(copy_of_the_repository, tmp_path, "drills", {"drill-on": wider})
    assert done.returncode == 3
    assert "STOPPED: the plan to switch the drill on holds more than the drill" in done.stderr
    assert not [
        call
        for call in calls
        if call.startswith(("terraform -chdir", "pubsub")) and " apply " in f" {call} "
    ]
    assert not [call for call in calls if call.startswith("pubsub")]


def test_the_drill_does_not_start_while_a_real_project_has_no_billing(
    copy_of_the_repository, tmp_path
):
    done, calls, _ = after_apply(
        copy_of_the_repository,
        tmp_path,
        'echo False >"$MOCK_STATE/billing-aiven-gateway-mock"; drills',
    )
    assert done.returncode == 3
    assert (
        "STOPPED: billing is off on the agents or gateway project before the drill" in done.stderr
    )
    assert not [call for call in calls if call.startswith(("pubsub", "terraform"))]


def test_a_second_audit_entry_for_a_project_stopped_already_fails_bd2(
    copy_of_the_repository, tmp_path
):
    done, _, _ = after_apply(copy_of_the_repository, tmp_path, "drills", MOCK_DOUBLE_AUDIT="1")
    assert done.returncode == 0, done.stdout + done.stderr
    assert lines(done, "FAIL ") == [
        "FAIL bd2-one-entry: not so: one budget_stop audit entry for the two",
        "FAIL drills: stopped at bd2-one-entry; scratch linked again, drill copy removed",
    ]


def test_ci_runs_shellcheck_and_requires_the_dry_runs():
    from ruamel.yaml import YAML

    jobs = YAML(typ="safe").load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())[
        "jobs"
    ]
    test_runs = [str(step.get("run", "")) for step in jobs["test"]["steps"]]
    assert (
        "shellcheck scripts/m2-oneclick.sh .githooks/pre-commit tests/scripts/oneclick_mock/*"
        in test_runs
    )
    (dry_runs,) = [
        step
        for step in jobs["terraform"]["steps"]
        if "test_m2_oneclick_script.py" in str(step.get("run", ""))
    ]
    assert dry_runs["env"] == {"AIVEN_REQUIRE_MOCK_RUN": "1"}
    runs = [str(step.get("run", "")) for step in jobs["terraform"]["steps"]]
    assert runs.index(dry_runs["run"]) > runs.index("terraform -chdir=infra/terraform test")


@pytest.mark.parametrize(
    ("steps", "says"),
    [
        ('record SKIP apply "you answered no"; APPLIED=no; report', "Not applied: nothing changed"),
        ("record PASS apply applied; APPLIED=yes; report", "M2 is applied and checked."),
        (
            "record PASS apply applied; record FAIL bd1-unlink x; APPLIED=yes; report",
            "M2 is applied; 1 step(s) failed (above).",
        ),
        ("DRY_RUN=1; report", "Dry run: nothing was applied, and nothing changed in Google Cloud."),
    ],
    ids=["answered-no", "all-green", "a-check-failed", "dry-run"],
)
def test_the_report_says_what_happened(copy_of_the_repository, tmp_path, steps, says):
    done, _, _ = after_apply(copy_of_the_repository, tmp_path, steps + '; echo "failed=$FAILED"')
    assert done.returncode == 0, done.stderr
    assert says in done.stdout
    assert "Send m2-result.txt to Claude." in done.stdout
    expected = "failed=1" if "FAIL" in steps else "failed=0"
    assert done.stdout.rstrip().endswith(expected)


# --- making the four projects (no project IDs in the values yet)

NO_VALUES = (
    "V_agents_project= V_gateway_project= V_control_project= V_scratch_project= "
    "V_billing_account= V_budget_currency= V_alert_email= V_sandbox_drive_id= ORG=; "
)
# Enter for the billing account, y to make the projects, Enter for the currency, the alert address
# and "no drive yet".
MAKE = "\ny\n\n\n\n"
ROLES = ("agents", "gateway", "control", "scratch")


def make_projects(repo: Path, tmp_path: Path, answers: str = MAKE, **mock: str):
    mock = {"MOCK_PROJECTS": "my-first-project-511521", **mock}
    return after_apply(repo, tmp_path, NO_VALUES + "values", answers=answers, **mock)


def made(calls: list[str]) -> list[str]:
    return [call.split()[2] for call in calls if call.startswith("projects create")]


def test_the_four_projects_are_made_and_linked_after_one_yes(copy_of_the_repository, tmp_path):
    repo = copy_of_the_repository
    reset(repo)
    done, calls, _ = make_projects(repo, tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    ids = made(calls)
    assert [project.rsplit("-", 1)[0] for project in ids] == [f"aiven-{role}" for role in ROLES]
    assert len({project.rsplit("-", 1)[1] for project in ids}) == 1  # one suffix
    for role, project in zip(ROLES, ids, strict=True):
        assert (
            f"projects create {project} --organization=998877665544 --name=AIVEN {role} --quiet"
            in calls
        )
        assert f"billing projects link {project} --billing-account=01F2A3-B4C5D6-E7F809" in calls
    assert "Make these 4 projects? (y/n)" not in done.stdout  # read -p prints only on a terminal
    assert "PASS projects: made and linked to 01F2A3-B4C5D6-E7F809:" in done.stdout
    assert not [call for call in calls if "my-first-project-511521" in call]  # never touched

    tfvars = (repo / "infra" / "terraform" / "terraform.tfvars").read_text()
    platform = (repo / "config" / "platform.yaml").read_text()
    for role, project in zip(ROLES, ids, strict=True):
        assert f"{role}_project" in tfvars and f'"{project}"' in tfvars
    assert f"agents_project: {ids[0]}" in platform
    assert f"gateway_principal: gateway@{ids[1]}.iam.gserviceaccount.com" in platform
    assert check_file(repo / "infra" / "terraform" / "terraform.tfvars") == []

    # Run again: the values name the projects now, so nothing is made or asked.
    again, calls_again, _ = after_apply(repo, tmp_path, "values", keep_state=True)
    assert again.returncode == 0, again.stdout + again.stderr
    assert made(calls_again) == ids  # the calls of the first run only
    reset(repo)


def test_answering_no_asks_for_existing_projects_instead(copy_of_the_repository, tmp_path):
    repo = copy_of_the_repository
    reset(repo)
    existing = "aiven-agents-mock aiven-gateway-mock aiven-control-mock aiven-scratch-mock"
    # Enter (billing), n, Enter for each of the four suggested projects, currency, alert, drive.
    done, calls, _ = make_projects(
        repo,
        tmp_path,
        answers="\nn\n" + "\n" * 7,
        MOCK_PROJECTS=f"{existing} my-first-project-511521",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert made(calls) == []
    assert not [call for call in calls if call.startswith("billing projects link")]
    assert (
        'control_project = "aiven-control-mock"'
        in (repo / "infra" / "terraform" / "terraform.tfvars").read_text()
    )
    reset(repo)


def test_a_project_id_that_is_taken_gets_a_new_suffix(copy_of_the_repository, tmp_path):
    repo = copy_of_the_repository
    reset(repo)
    done, calls, _ = make_projects(repo, tmp_path, MOCK_CREATE_TAKEN="gateway")
    assert done.returncode == 0, done.stdout + done.stderr
    tried = made(calls)
    assert len(tried) == 5  # the gateway twice
    first, second = [project for project in tried if project.startswith("aiven-gateway-")]
    assert first != second
    tfvars = (repo / "infra" / "terraform" / "terraform.tfvars").read_text()
    assert f'"{second}"' in tfvars and f'"{first}"' not in tfvars
    reset(repo)


def test_a_full_project_quota_stops_with_what_happened(copy_of_the_repository, tmp_path):
    repo = copy_of_the_repository
    reset(repo)
    done, calls, _ = make_projects(repo, tmp_path, MOCK_CREATE_QUOTA="1")
    assert done.returncode == 3
    assert "STOPPED: project aiven-agents-" in done.stderr and "could not be made" in done.stderr
    assert "Hint: a quota of your account or billing account is full" in done.stdout
    assert not [call for call in calls if call.startswith("billing projects link")]
    assert not (repo / "infra" / "terraform" / "terraform.tfvars").exists()
    reset(repo)


def test_a_run_that_stopped_at_a_full_billing_quota_resumes_with_the_same_ids(
    copy_of_the_repository, tmp_path
):
    repo = copy_of_the_repository
    reset(repo)
    stopped, calls, _ = make_projects(repo, tmp_path, MOCK_LINK_QUOTA="1")
    assert stopped.returncode == 3
    assert "takes no more linked projects (its quota is full)" in stopped.stderr
    assert "billing_quota_increase" in stopped.stderr
    assert not (repo / "infra" / "terraform" / "terraform.tfvars").exists()
    first = made(calls)
    assert len(first) == 1  # made, and then its billing could not be linked

    # Quota raised: the run again makes the other three, with the IDs it showed the first time.
    again, calls, _ = after_apply(
        repo,
        tmp_path,
        NO_VALUES + "values",
        answers=MAKE,
        keep_state=True,
        MOCK_PROJECTS="my-first-project-511521",
    )
    assert again.returncode == 0, again.stdout + again.stderr
    ids = made(calls)
    assert ids[0] == first[0] and len(ids) == 4
    assert len({project.rsplit("-", 1)[1] for project in ids}) == 1
    assert f"billing projects link {first[0]} --billing-account=01F2A3-B4C5D6-E7F809" in calls
    reset(repo)
