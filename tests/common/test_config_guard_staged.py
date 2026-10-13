"""`aiven-check-config --staged` and the pre-commit hook that runs it (M2 review, decision 4).

The hook is optional; CI stays the gate. What the hook checks is what the commit holds: the files
as the Git index has them, with the variables.tf of the index, from any folder of the work tree,
and also for `git commit -a` and `git commit <file>`, which give the hook an index of their own.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aiven.common.config_guard import main
from tests.common.test_config_guard import AWS_KEY, OUTPUT_LINE, PLATFORM, TFVARS, TFVARS_NAMES
from tests.common.test_config_guard import variables_tf as declaring
from tests.support import REPO_ROOT
from tests.support.git import WHERE_GIT_LOOKS

HOOK = REPO_ROOT / ".githooks" / "pre-commit"
PLATFORM_FILE = "config/platform.yaml"
TFVARS_FILE = "infra/terraform/terraform.tfvars"
VARIABLES_FILE = "infra/terraform/variables.tf"
SECRET_PLATFORM = PLATFORM + f"# {AWS_KEY}\n"


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    """An empty repository of the test's own, as the working folder; no config of the machine."""
    for name in WHERE_GIT_LOOKS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    work = tmp_path / "repo"
    work.mkdir()
    monkeypatch.chdir(work)
    git("init", "-q", "-b", "main")
    for setting in ("user.name=Test", "user.email=test@aivenstudios.com", "commit.gpgsign=false"):
        git("config", *setting.split("=", 1))
    return work


def git(*args: str, **options) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True, **options)


def put(name: str, text: str, *, stage: bool = True) -> None:
    path = Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if stage:
        git("add", name)


def staged(capsys) -> tuple[int, list[str], str]:
    """`--staged`: the exit code, the code and place of each problem, and stderr."""
    status = main(["--staged"])
    captured = capsys.readouterr()
    found = []
    for line in captured.out.splitlines():
        match = OUTPUT_LINE.fullmatch(line)
        assert match is not None, line
        found.append(f"{match[1]} {match[2]}" + (f":{match[3]}" if match[3] else ""))
    assert AWS_KEY not in captured.out + captured.err
    return status, found, captured.err


def test_it_checks_the_file_as_the_index_holds_it_and_not_the_working_copy(repo, capsys):
    put(PLATFORM_FILE, PLATFORM)
    put(PLATFORM_FILE, SECRET_PLATFORM, stage=False)  # changed, but not staged
    assert staged(capsys) == (0, [], "checked (staged): config/platform.yaml\n")
    git("add", PLATFORM_FILE)
    assert staged(capsys)[:2] == (1, ["C-SECRET config/platform.yaml:8"])
    put(PLATFORM_FILE, PLATFORM, stage=False)  # mended in the working copy only: still staged
    assert staged(capsys)[:2] == (1, ["C-SECRET config/platform.yaml:8"])


def test_terraform_values_are_checked_against_the_variables_tf_of_the_index(repo, capsys):
    put(VARIABLES_FILE, declaring(TFVARS_NAMES))
    put(TFVARS_FILE, TFVARS + "extra = 1\n")
    put(VARIABLES_FILE, declaring((*TFVARS_NAMES, "extra")), stage=False)
    assert staged(capsys)[:2] == (1, ["C-UNKNOWN-KEY infra/terraform/terraform.tfvars:22"])
    git("add", VARIABLES_FILE)
    assert staged(capsys)[:2] == (0, [])


def test_without_a_variables_tf_in_the_index_the_names_cannot_be_checked(repo, capsys):
    put(TFVARS_FILE, TFVARS)
    put(VARIABLES_FILE, declaring(TFVARS_NAMES), stage=False)  # there, but not in the commit
    assert staged(capsys)[:2] == (1, ["C-NO-VARIABLES infra/terraform/terraform.tfvars"])


def test_each_default_file_in_the_index_is_checked_from_any_folder(repo, capsys, monkeypatch):
    put("config/platform.example.yaml", PLATFORM)
    put(VARIABLES_FILE, declaring(TFVARS_NAMES))
    put("infra/terraform/terraform.tfvars.example", TFVARS)
    put(TFVARS_FILE, TFVARS.replace('"aiven"', f'"{AWS_KEY}"'))
    git("commit", "-q", "-m", "values")  # committed files are in the index too
    monkeypatch.chdir(repo / "infra")
    status, found, err = staged(capsys)
    assert (status, found) == (1, ["C-SECRET infra/terraform/terraform.tfvars:21"])
    assert err == (
        "checked (staged): config/platform.example.yaml, infra/terraform/terraform.tfvars, "
        "infra/terraform/terraform.tfvars.example\n"
    )


def test_a_file_that_is_not_in_the_index_is_not_part_of_the_commit(repo, capsys):
    put(PLATFORM_FILE, SECRET_PLATFORM, stage=False)  # never added
    assert staged(capsys) == (
        0,
        [],
        "nothing to check: the index holds none of config/platform.yaml, "
        "config/platform.example.yaml, infra/terraform/terraform.tfvars, "
        "infra/terraform/terraform.tfvars.example\n",
    )


def test_outside_a_work_tree_it_is_exit_2(tmp_path, capsys, monkeypatch):
    for name in WHERE_GIT_LOOKS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert main(["--staged"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "cannot read the Git index (CalledProcessError): --staged needs Git, in a Git work tree\n"
    )


def test_staged_takes_no_files(capsys):
    with pytest.raises(SystemExit) as stopped:
        main(["--staged", PLATFORM_FILE])
    assert stopped.value.code == 2
    assert "give no files" in capsys.readouterr().err


# --- the hook itself, run by git


def test_the_hook_is_an_executable_sh_script_that_runs_the_staged_check():
    text = HOOK.read_bytes()
    assert text.startswith(b"#!/bin/sh\n")
    assert b"\r" not in text
    assert text.rstrip(b"\n").endswith(b"exec uv run --frozen aiven-check-config --staged")
    assert os.access(HOOK, os.X_OK)
    assert ".githooks/* text eol=lf" in (REPO_ROOT / ".gitattributes").read_text().splitlines()


@pytest.fixture
def hooked(repo, tmp_path, monkeypatch) -> Path:
    """The repository with the real hook, and a `uv` on the PATH that runs this checkout's guard."""
    tools = tmp_path / "tools"
    tools.mkdir()
    fake_uv = tools / "uv"
    run_guard = (
        "import sys; from aiven.common.config_guard import main; sys.exit(main(sys.argv[1:]))"
    )
    fake_uv.write_text(
        "#!/bin/sh\n"
        '[ "$1 $2 $3" = "run --frozen aiven-check-config" ] || exit 99\n'
        "shift 3\n"
        f'exec "{sys.executable}" -c "{run_guard}" "$@"\n'
    )
    fake_uv.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tools}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT / "src"))
    git("config", "core.hooksPath", str(HOOK.parent))
    put(PLATFORM_FILE, PLATFORM)
    git("commit", "-q", "-m", "clean values")  # the hook lets a clean commit through
    return repo


def commit(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "commit", "-q", *args], capture_output=True, text=True)


def head() -> str:
    return git("rev-parse", "HEAD").stdout


@pytest.mark.parametrize(
    "how",
    [["-m", "staged"], ["-a", "-m", "all"], ["-m", "named", PLATFORM_FILE]],
    ids=["staged", "commit-a", "commit-path"],
)
def test_the_hook_refuses_a_commit_that_would_hold_a_secret(hooked, how):
    before = head()
    put(PLATFORM_FILE, SECRET_PLATFORM, stage=how[0] == "-m" and len(how) == 2)
    done = commit(*how)
    assert done.returncode != 0
    assert "error C-SECRET config/platform.yaml:8: " in done.stdout + done.stderr
    assert AWS_KEY not in done.stdout + done.stderr
    assert head() == before


def test_the_hook_lets_a_commit_through_that_holds_ids_only(hooked):
    before = head()
    put(PLATFORM_FILE, PLATFORM.replace("aiven-agents-test", "aiven-agents-two"))
    assert commit("-m", "another project").returncode == 0
    assert head() != before


def test_without_uv_the_hook_refuses_and_says_how_to_turn_it_off(tmp_path):
    empty = tmp_path / "no-tools"
    empty.mkdir()
    done = subprocess.run([str(HOOK)], env={"PATH": str(empty)}, capture_output=True, text=True)
    assert done.returncode == 1
    assert "uv is not on the PATH" in done.stderr
    assert "git config --unset core.hooksPath" in done.stderr


def test_the_readme_says_how_to_install_the_hook_and_that_ci_stays_the_gate():
    readme = (REPO_ROOT / "README.md").read_text()
    assert "git config core.hooksPath .githooks" in readme
    assert "CI stays the gate" in readme
