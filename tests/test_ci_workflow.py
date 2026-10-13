"""The policies step of CI (`.github/workflows/ci.yml`), and the platform values it needs (R92).

The real `config/platform.yaml` holds no credentials: project ids, the addresses of the trusted
authors, the gateway principal and the drive id. It is committed once the projects exist. Until
then, and whatever the policies are, CI must not judge them against the example values: every real
policy fails E-PRINCIPAL against those, which would be a failure with a wrong reason.

The step is a shell script in the workflow file. These tests take it out of the file and run it with
bash, in a folder of their own where `uv` is a stand-in that writes down the words it is called
with. The workflow is read, not trusted: that it parses, and that every action in it is pinned by
the SHA of a commit, are tests as well.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from tests.support import REPO_ROOT

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
EXAMPLE = REPO_ROOT / "config" / "platform.example.yaml"

MISSING = (
    "config/platform.yaml is missing: "
    "commit the deployment's platform values (they hold no credentials)"
)

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="the step is a bash script")


def steps() -> list[dict]:
    return YAML(typ="safe").load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["test"]["steps"]


def policies_step() -> str:
    """The script of the step that validates the policies."""
    (step,) = [step for step in steps() if str(step.get("name", "")).startswith("Policies")]
    return step["run"]


def a_stand_in_for_uv(folder: Path) -> Path:
    """The folder of a `uv` that writes down its words, a call to a line, and does nothing else."""
    where = folder / "bin"
    where.mkdir()
    stand_in = where / "uv"
    stand_in.write_text('#!/bin/sh\necho "$*" >> "$UV_CALLS"\n')
    stand_in.chmod(0o755)
    return where


def run_the_step(folder: Path, *, base: str = "") -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run the policies step in `folder` the way CI does (`bash -e` on the script).

    `base` is the SHA of the base of a pull request, empty for a push. The result is the finished
    process, and the calls that the step made to `uv`.
    """
    script, calls = folder / "step.sh", folder / "uv-calls.txt"
    script.write_text(policies_step(), encoding="utf-8")
    path = f"{a_stand_in_for_uv(folder)}{os.pathsep}{os.environ['PATH']}"
    environment = {"PATH": path, "UV_CALLS": str(calls), "BASE_SHA": base}
    done = subprocess.run(
        ["bash", "-e", str(script)],
        cwd=folder,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return done, calls.read_text().splitlines() if calls.exists() else []


def with_policies(folder: Path, *names: str) -> list[str]:
    """Make these policy files in the folder, and give their paths as the step sees them."""
    (folder / "policies").mkdir()
    for name in names:
        (folder / "policies" / name).write_text("a policy\n")
    return [f"policies/{name}" for name in names]


def with_platform_values(folder: Path) -> None:
    (folder / "config").mkdir(exist_ok=True)
    (folder / "config" / "platform.yaml").write_text("the platform values\n")


# --- the workflow itself


def test_the_workflow_parses_and_has_one_step_for_the_policies():
    names = [str(step.get("name", "")) for step in steps()]
    assert sum(name.startswith("Policies") for name in names) == 1


def test_every_action_is_pinned_by_the_sha_of_a_commit():
    used = [step["uses"] for step in steps() if "uses" in step]
    assert used
    for action in used:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), action


# --- the policies step (ruling R92)


@needs_bash
def test_with_no_policies_the_step_does_nothing_and_needs_no_platform_values(tmp_path):
    done, calls = run_the_step(tmp_path)
    assert (done.returncode, done.stdout.strip(), done.stderr) == (0, "No policies yet.", "")
    assert calls == []


@needs_bash
def test_with_no_policies_the_step_does_nothing_with_platform_values_too(tmp_path):
    with_platform_values(tmp_path)
    done, calls = run_the_step(tmp_path)
    assert (done.returncode, done.stdout.strip()) == (0, "No policies yet.")
    assert calls == []


@needs_bash
def test_policies_without_the_platform_values_fail_with_one_clear_line(tmp_path):
    with_policies(tmp_path, "invoice-reminder.md")
    done, calls = run_the_step(tmp_path)
    assert done.returncode == 1
    assert done.stdout + done.stderr == MISSING + "\n"
    assert calls == []  # the validator did not run: there is nothing to judge a policy against


@needs_bash
def test_the_example_values_are_never_used_in_their_place(tmp_path):
    with_policies(tmp_path, "invoice-reminder.md", "payment-nudge.md")
    (tmp_path / "config").mkdir()
    shutil.copy(EXAMPLE, tmp_path / "config" / "platform.example.yaml")
    done, calls = run_the_step(tmp_path)
    assert (done.returncode, done.stdout + done.stderr) == (1, MISSING + "\n")
    assert calls == []


@needs_bash
def test_the_validator_is_pointed_at_the_platform_values_and_at_every_policy(tmp_path):
    names = with_policies(tmp_path, "payment-nudge.md", "invoice-reminder.md")
    with_platform_values(tmp_path)
    done, calls = run_the_step(tmp_path)
    assert (done.returncode, done.stderr) == (0, "")
    (call,) = calls
    words = call.split()
    assert words[:3] == ["run", "aiven-policy", "validate"]
    assert words[words.index("--config") + 1] == "config/platform.yaml"
    assert "--previous-ref" not in words  # a push has no base
    assert words[-len(names) :] == sorted(names)  # the files, as the shell lists them


@needs_bash
def test_a_pull_request_gives_the_base_to_the_validator_as_well(tmp_path):
    names = with_policies(tmp_path, "invoice-reminder.md")
    with_platform_values(tmp_path)
    done, calls = run_the_step(tmp_path, base="0123456789abcdef0123456789abcdef01234567")
    assert done.returncode == 0
    (call,) = calls
    words = call.split()
    assert words[words.index("--config") + 1] == "config/platform.yaml"
    assert words[words.index("--previous-ref") + 1] == "0123456789abcdef0123456789abcdef01234567"
    assert words[-1:] == names


# --- the example values say where the real ones are


def test_the_example_values_say_where_the_real_ones_are_and_when_ci_needs_them():
    top = EXAMPLE.read_text(encoding="utf-8").splitlines()[:2]
    assert all(line.startswith("# ") for line in top)
    text = " ".join(top)
    assert "config/platform.yaml" in text
    assert "no credentials" in text
    assert "CI" in text and "first policy" in text
