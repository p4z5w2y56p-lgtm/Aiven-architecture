"""The `aiven-policy` command line (validator-spec section 1): validate, render and verify.

The command line is thin: the checks are tested in the modules that make them. These tests are about
what it adds. It reads the platform values and the catalog, turns the findings into lines (or one
JSON document), decides the exit code, and never prints text of a file.

Most tests call `main` in this process and read what it printed. The self test of validator-spec
section 9 runs the real command in a subprocess, as CI does. Files are made with
`variant_file(*changes, render=True)` (tests/support/variants.py), which gives whole valid files. A
test that needs Git makes a repository of its own in the working folder of the test, and one that
needs a signature makes a key of its own (tests/support/signing.py).

`CODES_TRIGGERED` maps the codes that the tests of this module trigger, and that no other test
module does, to the test that triggers each (test_coverage_of_codes.py reads it).
"""

import io
import itertools
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from aiven.policy import cli
from aiven.policy.catalog import load_catalog
from aiven.policy.cli import FILE_AND_BODY_CODES, main
from aiven.policy.findings import Finding, format_line, message
from aiven.policy.validate import Validated, validate_file
from tests.support import REPO_ROOT, gen
from tests.support.bodies import policy_of, rerendered
from tests.support.frontmatter import tool_line, without
from tests.support.policies import (
    AGENTS_PROJECT,
    FOLDER_ID,
    TEMPLATE_PATH,
    line_of,
    platform_config,
    valid_base,
)
from tests.support.rules import setting, with_tools
from tests.support.signing import Signer, make_signer
from tests.support.signing import work_in_a_temporary_folder as work_in_a_temporary_folder
from tests.support.spec_tables import code_spans, table_after
from tests.support.variants import principal_of, variant_file

CODES_TRIGGERED = {"E-INTERNAL": "test_crash_exits_2_with_e_internal"}

CATALOG_FILE = REPO_ROOT / "catalog" / "catalog-v1.yaml"
CFG = platform_config()
CATALOG = load_catalog(CATALOG_FILE)

INVOICE = "policies/invoice-reminder.md"
VALID = variant_file(render=True)  # version 1 of invoice-reminder: the three warnings of the base

# Without --previous-ref the history is not known, and validate says that it checks none (R86).
NO_REF_NOTE = "note: version order and widening need --previous-ref"

# Where the output holds an E-INTERNAL and --debug was not given, the cause can be had that way.
DEBUG_NOTE = "note: run again with --debug to see the cause"


# --- calling the command line


@dataclass(frozen=True)
class Ran:
    """What one call of `main` gave: the exit code, and what it printed."""

    status: int
    out: str
    err: str

    @property
    def lines(self) -> list[str]:
        return self.out.splitlines()


@pytest.fixture(autouse=True)
def no_config_from_the_environment(monkeypatch):
    monkeypatch.delenv("AIVEN_POLICY_CONFIG", raising=False)


def platform_yaml(project: str = CFG.agents_project) -> str:
    """The text of a platform file: the platform values of the tests, for this agents project."""
    return (
        f"agents_project: {project}\n"
        f"trusted_authors: [{', '.join(CFG.trusted_authors)}]\n"
        f"gateway_principal: {CFG.gateway_principal}\n"
    )


@pytest.fixture
def platform(tmp_path) -> Path:
    """The platform values of the tests (the project of the base policy), as a file."""
    path = tmp_path / "platform.yaml"
    path.write_text(platform_yaml())
    return path


class Cli:
    """Calls `main` and keeps what it printed."""

    def __init__(self, capsys, platform: Path):
        self.capsys = capsys
        self.platform = platform

    def raw(self, *argv: str) -> Ran:
        status = main(list(argv))
        out, err = self.capsys.readouterr()
        return Ran(status, out, err)

    def __call__(self, command: str, *argv: str, catalog: Path = CATALOG_FILE) -> Ran:
        """`main` for a command, with the platform values and the catalog of the tests."""
        options = ["--config", str(self.platform), "--catalog", str(catalog)]
        return self.raw(command, *options, *argv)


@pytest.fixture
def run(capsys, platform) -> Cli:
    return Cli(capsys, platform)


@pytest.fixture
def built_catalog(tmp_path) -> Path:
    """The catalog with the Drive and Email wrappers built: no tool of the base is planned."""
    planned = CATALOG_FILE.read_text()
    built = planned.replace("{drive: planned, email: planned", "{drive: built, email: built")
    assert built != planned
    path = tmp_path / "built-catalog.yaml"
    path.write_text(built)
    return path


def swap(data: bytes, old: bytes, new: bytes) -> bytes:
    """`data` with the one place where `old` stands replaced by `new`."""
    assert data.count(old) == 1, f"{old!r} must occur exactly once"
    return data.replace(old, new)


def write(name: str, data: bytes) -> Path:
    """The file `name` in the working folder of the test."""
    path = Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def findings_of(name: str, data: bytes):
    return validate_file(Path(name), data, CFG, CATALOG)


# --- the working folder


def test_the_tests_of_this_module_run_in_a_folder_of_their_own(tmp_path):
    # The fixture of tests/support/signing.py, imported above: it looks unused, and it is not.
    assert tmp_path in Path.cwd().parents


# --- the template self test (validator-spec section 9)

OUTPUT_LINE = re.compile(
    r"(?P<severity>error|warning) (?P<code>[EW]-[A-Z-]+) (?P<path>[^:\s]+)"
    r"(?::(?P<line>\d+))?: (?P<text>.+)"
)


def test_template_self_test_matches_spec_section_9():
    header, *rows = table_after("9. Template self-test")
    assert header[:3] == ["Severity", "Code", "Line"]
    environment = {k: v for k, v in os.environ.items() if k != "AIVEN_POLICY_CONFIG"}
    done = subprocess.run(
        ["uv", "run", "aiven-policy", "validate", "templates/policy-template.md"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 1
    shown = [OUTPUT_LINE.fullmatch(line) for line in done.stdout.splitlines()]
    assert None not in shown  # every line is a finding, and nothing else is printed
    assert [(m["severity"], m["code"], m["line"]) for m in shown] == [
        (severity, code, None if line == "(file)" else line) for severity, code, line, _ in rows
    ]
    assert {m["path"] for m in shown} == {"templates/policy-template.md"}
    for found, (_, code, _, about) in zip(shown, rows, strict=True):
        for span in code_spans(about):  # what the finding is about is in its message
            assert span in found["text"], (code, span)
        if code == "W-TOOL-NOT-LIVE":
            assert re.search(r"\(([^)]+)\)", about).group(1) in found["text"]


# --- validate: the lines and the exit code


def test_a_valid_file_exits_0_and_prints_its_warnings(run):
    write(INVOICE, VALID)
    done = run("validate", INVOICE)
    assert done.status == 0
    assert [line.split()[:2] for line in done.lines] == [["warning", "W-TOOL-NOT-LIVE"]] * 3
    assert done.lines == [format_line(f) for f in findings_of(INVOICE, VALID)]
    assert done.err.splitlines() == [NO_REF_NOTE]


def test_an_error_exits_1_and_the_lines_are_those_of_validate_file(run):
    data = variant_file(setting("limits.runs_per_day", 11), render=True)
    write(INVOICE, data)
    done = run("validate", INVOICE)
    assert done.status == 1
    assert "error E-RANGE policies/invoice-reminder.md:" in done.out
    assert done.lines == [format_line(f) for f in findings_of(INVOICE, data)]


# --- where the platform values and the catalog come from (ruling R61)
#
# These tests give no --config and no --catalog, so the files are found from the working folder.

EXAMPLE_NOTE = "note: using the example platform config"


@pytest.fixture
def tree(run):
    """The working folder as a checkout has it: the catalog and the example platform values."""
    Path("config").mkdir()
    Path("catalog").mkdir()
    Path("catalog/catalog-v1.yaml").write_bytes(CATALOG_FILE.read_bytes())
    example = REPO_ROOT / "config" / "platform.example.yaml"
    Path("config/platform.example.yaml").write_bytes(example.read_bytes())
    write(INVOICE, VALID)
    return run


def test_without_a_config_the_example_is_used_and_one_note_says_so(tree):
    done = tree.raw("validate", INVOICE)
    # The example names another agents project than the policy does: a real policy fails closed.
    assert done.status == 1
    assert [line.split()[:2] for line in done.lines if line.startswith("error")] == [
        ["error", "E-PRINCIPAL"]
    ]
    assert done.err.splitlines() == [EXAMPLE_NOTE, NO_REF_NOTE]


def test_config_platform_yaml_comes_before_the_example(tree):
    Path("config/platform.yaml").write_text(platform_yaml())
    done = tree.raw("validate", INVOICE)
    assert (done.status, done.err.splitlines()) == (0, [NO_REF_NOTE])


def test_the_environment_comes_before_the_files(tree, tmp_path, monkeypatch):
    Path("config/platform.yaml").write_text(platform_yaml("aiven-agents-elsewhere"))
    chosen = tmp_path / "chosen.yaml"
    chosen.write_text(platform_yaml())
    monkeypatch.setenv("AIVEN_POLICY_CONFIG", str(chosen))
    done = tree.raw("validate", INVOICE)
    assert (done.status, done.err.splitlines()) == (0, [NO_REF_NOTE])


def test_the_flag_comes_before_the_environment(tree, tmp_path, monkeypatch):
    wrong = tmp_path / "wrong.yaml"
    wrong.write_text(platform_yaml("aiven-agents-elsewhere"))
    monkeypatch.setenv("AIVEN_POLICY_CONFIG", str(wrong))
    done = tree.raw("validate", "--config", str(tree.platform), INVOICE)
    assert (done.status, done.err.splitlines()) == (0, [NO_REF_NOTE])


def test_an_empty_environment_variable_is_no_choice(tree, monkeypatch):
    monkeypatch.setenv("AIVEN_POLICY_CONFIG", "")
    assert tree.raw("validate", INVOICE).err.splitlines() == [EXAMPLE_NOTE, NO_REF_NOTE]


def test_the_catalog_can_be_named(tree, built_catalog):
    done = tree.raw(
        "validate", "--config", str(tree.platform), "--catalog", str(built_catalog), INVOICE
    )
    assert (done.status, done.out) == (0, "")  # no wrapper is planned, so no warning either


# --- validate: several files

NUDGE = "policies/payment-nudge.md"
NUDGE_ID = principal_of("payment-nudge")


def agent_file(agent: str) -> bytes:
    """A file of another agent, with the principal of that agent and its sections rendered again.

    It is not a whole valid file (its title is still the one of the base), which does not matter
    here: these tests are about where the findings of several files go.
    """
    return variant_file(
        setting("agent", agent), setting("principal", principal_of(agent)), render=True
    )


def path_of(line: str) -> str:
    """The path that a line of the output is about: its third word, without the line number."""
    return line.split()[2].partition(":")[0]


def by_file(lines: list[str]) -> dict[str, list[str]]:
    """The lines of an output, by the path they are about."""
    files: dict[str, list[str]] = {}
    for line in lines:
        files.setdefault(path_of(line), []).append(line)
    return files


def test_the_files_are_reported_one_after_the_other_in_the_order_of_the_arguments(run):
    write(INVOICE, VALID)
    write(NUDGE, agent_file("payment-nudge"))
    forward = run("validate", INVOICE, NUDGE)
    backward = run("validate", NUDGE, INVOICE)
    assert forward.status == backward.status == 1
    # The runs of lines of one path: a file is one block, so each path comes up once.
    assert [path for path, _ in itertools.groupby(map(path_of, forward.lines))] == [INVOICE, NUDGE]
    assert [path for path, _ in itertools.groupby(map(path_of, backward.lines))] == [NUDGE, INVOICE]
    # A block does not depend on the files that come with it.
    assert by_file(forward.lines) == by_file(backward.lines)


def test_findings_across_the_files_go_with_the_file_they_are_about(run):
    # Two files of one agent. The copy has a principal of its own, so only the agent is a duplicate.
    copy = variant_file(setting("principal", principal_of("invoice-copy")), render=True)
    write(INVOICE, VALID)
    write("policies/invoice-copy.md", copy)
    done = run("validate", INVOICE, "policies/invoice-copy.md")
    files = by_file(done.lines)
    expected = "Agent invoice-reminder is defined in more than one file: "
    for path in (INVOICE, "policies/invoice-copy.md"):
        duplicates = [line for line in files[path] if " E-AGENT-DUPLICATE " in line]
        assert len(duplicates) == 1, path
        assert duplicates[0].endswith(expected + "invoice-copy.md, invoice-reminder.md.")
    assert not any(" E-PRINCIPAL-DUPLICATE " in line for line in done.lines)
    assert done.status == 1


def test_a_finding_across_files_is_sorted_in_with_the_findings_of_its_file(run):
    copy = variant_file(setting("principal", principal_of("invoice-copy")), render=True)
    write(INVOICE, VALID)
    write("policies/invoice-copy.md", copy)
    done = run("validate", INVOICE, "policies/invoice-copy.md")
    # Findings about the whole file come first, then the lines, as validate_file sorts them.
    codes = [line.split()[1] for line in by_file(done.lines)[INVOICE]]
    assert codes == ["E-AGENT-DUPLICATE", "W-TOOL-NOT-LIVE", "W-TOOL-NOT-LIVE", "W-TOOL-NOT-LIVE"]


def test_a_finding_across_files_reaches_a_file_whose_name_has_an_unprintable_character(run):
    # The finding carries the name as it is shown, with the character written out as an escape.
    copy = variant_file(setting("principal", principal_of("invoice-copy")), render=True)
    odd = "policies/invoice\ncopy.md"
    write(INVOICE, VALID)
    write(odd, copy)
    done = run("validate", INVOICE, odd)
    assert [line.split()[1] for line in done.lines].count("E-AGENT-DUPLICATE") == 2
    assert "invoice\\u000acopy.md" in done.out


def spy_on_check_set(monkeypatch) -> list[list[str]]:
    """The paths that `check_set` was given, for each call."""
    seen: list[list[str]] = []
    real = cli.check_set

    def check_set(items, previous):
        seen.append([str(path) for path, _ in items])
        return real(items, previous)

    monkeypatch.setattr(cli, "check_set", check_set)
    return seen


def test_a_file_that_gives_no_policy_is_left_out_of_the_set(run, monkeypatch):
    seen = spy_on_check_set(monkeypatch)
    write(INVOICE, VALID)
    write(NUDGE, swap(VALID, b"max_class: R2", b"max_class: ["))
    done = run("validate", NUDGE, INVOICE)
    assert seen == [[INVOICE]]
    assert [m for m in by_file(done.lines)[NUDGE] if " E-YAML " in m]  # reported all the same
    assert done.status == 1


def test_the_set_is_sorted_by_path_whatever_the_order_of_the_arguments(run, monkeypatch):
    seen = spy_on_check_set(monkeypatch)
    names = ["policies/zeta-agent.md", "policies/alpha-agent.md", "policies/mid-agent.md"]
    for name in names:
        write(name, agent_file(Path(name).stem))
    run("validate", *names)
    run("validate", *reversed(names))
    assert seen == [sorted(names)] * 2


def test_a_file_named_twice_is_checked_once(run):
    write(INVOICE, VALID)
    once = run("validate", INVOICE)
    twice = run("validate", INVOICE, "./" + INVOICE)
    assert twice.status == 0
    assert twice.lines == once.lines


def test_a_file_in_two_spellings_is_checked_once_under_the_first(run):
    write(INVOICE, VALID)
    twisty = "policies/../" + INVOICE  # the same file, named by way of its folder
    for first, second in ((INVOICE, twisty), (twisty, INVOICE)):
        done = run("validate", first, second)
        assert done.status == 0
        assert done.lines == [format_line(f) for f in findings_of(first, VALID)]


def test_a_link_to_a_file_is_the_same_file(run):
    write(INVOICE, VALID)
    Path("policies/link.md").symlink_to("invoice-reminder.md")
    done = run("validate", INVOICE, "policies/link.md")
    assert done.status == 0
    assert done.lines == [format_line(f) for f in findings_of(INVOICE, VALID)]


def test_a_link_that_leads_round_in_a_circle_is_a_crash_and_not_a_traceback(run):
    # Naming the files is where it fails (a loop of links cannot be resolved), and the handler of
    # the crashes must not need what failed: it names the files as they were given.
    Path("loop").symlink_to("loop")
    done = run("validate", "loop")
    assert done.status == 2
    assert [line.split()[:3] for line in done.lines] == [["error", "E-INTERNAL", "loop:"]]
    assert "Traceback" not in done.err


# --- validate --json (validator-spec section 1, ruling R23)

ZERO_WIDTH_SPACE = b"\xe2\x80\x8b"  # a hidden character: a finding with a column


def test_json_output_has_en_and_nl(run):
    data = variant_file(setting("limits.runs_per_day", 11), render=True)
    data = swap(data, b"Once a day", b"Once" + ZERO_WIDTH_SPACE + b" TODO a day")
    write(INVOICE, data)
    done = run("validate", "--json", INVOICE)
    assert done.status == 1
    document = json.loads(done.out)  # one document, and nothing else on stdout
    assert list(document) == ["findings"]
    found = findings_of(INVOICE, data)
    assert {"E-RANGE", "E-HIDDEN-CHAR", "E-PLACEHOLDER", "W-TOOL-NOT-LIVE"} <= {
        f.code for f in found
    }
    assert len(document["findings"]) == len(found)
    for entry, finding in zip(document["findings"], found, strict=True):
        assert list(entry) == ["path", "line", "column", "severity", "code", "params", "en", "nl"]
        assert entry == {
            "path": INVOICE,
            "line": finding.line,
            "column": finding.column,
            "severity": finding.severity,
            "code": finding.code,
            "params": finding.params,
            "en": message(finding, "en"),
            "nl": message(finding, "nl"),
        }
        assert entry["nl"] != entry["en"]
    assert {entry["column"] is None for entry in document["findings"]} == {True, False}
    (placeholder,) = [e for e in document["findings"] if e["code"] == "E-PLACEHOLDER"]
    assert "v\u00f3\u00f3r" in placeholder["nl"]  # the Dutch text is read back as it was written
    assert done.out.isascii()  # and it is escaped in the output: any terminal and log can take it


def test_json_output_of_a_file_without_findings_is_an_empty_list(run, built_catalog):
    write(INVOICE, VALID)
    done = run("validate", "--json", INVOICE, catalog=built_catalog)
    assert (done.status, json.loads(done.out)) == (0, {"findings": []})


def test_the_params_of_the_json_are_cleaned_again(run, monkeypatch):
    # The writer reads the params directly, and the dict of a finding is not frozen (ruling R23).
    card = gen.valid_card()  # made now: no number of a card is in the source
    params = {"field": "version", "value": "1", "min": "1", "max": "9999"}
    finding = Finding("E-RANGE", "error", INVOICE, 5, params=params)
    finding.params["value"] = card
    monkeypatch.setattr(cli, "validate_policy", lambda *args: Validated(None, [finding], {}))
    write(INVOICE, VALID)
    done = run("validate", "--json", INVOICE)
    (entry,) = json.loads(done.out)["findings"]
    assert entry["params"] == {**params, "value": "[hidden]"}
    assert card not in done.out
    assert card not in run("validate", INVOICE).out


def test_a_file_name_cannot_start_a_line_of_its_own(run):
    # A newline in a file name could begin a line that the runner of CI takes for a command.
    name = "policies/x\n::error::forged.md"
    write(name, VALID)
    done = run("validate", name)
    assert done.lines
    assert all(line.startswith(("error ", "warning ")) for line in done.lines)
    assert "x\\u000a::error::forged.md" in done.out


# --- validate --previous-ref (validator-spec 3.9, 3.6)
#
# Each test makes a Git repository of its own in the working folder. With a ref, the previous bytes
# of a file come from `git show <ref>:<path>`; they are loaded and built, and never reported on.

NEXT_VERSION = setting("version", 2)
SKIPS_A_VERSION = setting("version", 3)
MORE_RUNS_A_DAY = setting("limits.runs_per_day", 2)


# What tells git where its repository is. A test run from a hook of git has them set to the real
# repository, and a test that makes a repository and commits to it must not meet that one.
WHERE_GIT_LOOKS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
)


@pytest.fixture
def git_environment(tmp_path, monkeypatch) -> None:
    """Git sees the working folder of the test, and no repository above it."""
    for name in WHERE_GIT_LOOKS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))


def git(*args: str) -> None:
    """Run Git in the working folder: quiet, with an author, and never signing."""
    config = [
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Test",
        "-c",
        "user.email=t@example.com",
    ]
    subprocess.run(["git", *config, *args], check=True, capture_output=True)


def commit() -> None:
    git("add", "-A")
    git("commit", "-q", "-m", "a commit")


@pytest.fixture
def repo(run, git_environment) -> Cli:
    git("init", "-q", "-b", "main")
    return run


def version_two(*changes) -> bytes:
    return variant_file(NEXT_VERSION, *changes, render=True)


def test_the_next_version_is_valid_against_the_version_before_it(repo):
    write(INVOICE, VALID)
    commit()
    write(INVOICE, version_two())
    done = repo("validate", "--previous-ref", "HEAD", INVOICE)
    assert done.status == 0
    assert [line.split()[1] for line in done.lines] == ["W-TOOL-NOT-LIVE"] * 3
    assert done.err == ""  # nothing is left out, so nothing is said


def test_without_a_ref_no_version_order_and_no_widening_is_checked_and_a_note_says_so(run):
    # The history of a file is not known, and a file is not a new agent for that (ruling R86): a
    # version 2 or a version 3 is not wrong, and nothing here can tell.
    for version in (2, 3):
        write(INVOICE, variant_file(setting("version", version), render=True))
        done = run("validate", INVOICE)
        assert done.status == 0
        assert {line.split()[1] for line in done.lines} == {"W-TOOL-NOT-LIVE"}
        assert done.err.splitlines() == [NO_REF_NOTE]
    done = run("validate", "--json", INVOICE)  # also with --json: the note is not in the document
    assert {entry["code"] for entry in json.loads(done.out)["findings"]} == {"W-TOOL-NOT-LIVE"}
    assert done.err.splitlines() == [NO_REF_NOTE]


def test_a_version_that_skips_one_is_refused(repo):
    write(INVOICE, VALID)
    commit()
    write(INVOICE, variant_file(SKIPS_A_VERSION, render=True))
    done = repo("validate", "--previous-ref", "HEAD", INVOICE)
    assert done.status == 1
    assert "version is 3, but the next version must be 2." in done.out


def test_a_version_that_gives_the_agent_more_room_is_a_warning(repo):
    write(INVOICE, VALID)
    commit()
    write(INVOICE, version_two(MORE_RUNS_A_DAY))
    done = repo("validate", "--previous-ref", "HEAD", INVOICE)
    assert done.status == 0
    widens = [line for line in done.lines if " W-WIDENS " in line]
    assert len(widens) == 1 and "limits.runs_per_day: 1 -> 2" in widens[0]


def test_the_ref_can_be_any_commit_and_not_only_the_last(repo):
    write(INVOICE, VALID)
    commit()
    write(INVOICE, version_two())
    commit()
    write(INVOICE, variant_file(setting("version", 3), render=True))
    assert repo("validate", "--previous-ref", "HEAD", INVOICE).status == 0
    before_that = repo("validate", "--previous-ref", "HEAD~1", INVOICE)  # where version 1 is
    assert before_that.status == 1
    assert "version is 3, but the next version must be 2." in before_that.out


def test_a_file_that_is_not_at_the_ref_is_a_new_agent(repo):
    write("README.md", b"nothing here\n")
    commit()
    write(INVOICE, VALID)
    assert repo("validate", "--previous-ref", "HEAD", INVOICE).status == 0
    write(INVOICE, version_two())
    done = repo("validate", "--previous-ref", "HEAD", INVOICE)
    assert done.status == 1
    assert "version is 2, but the next version must be 1." in done.out


def test_the_previous_version_is_never_reported_on(repo):
    # The version before has an error of its own. It is loaded and built, and nothing is said of it.
    write(INVOICE, variant_file(setting("limits.runs_per_day", 11), render=True))
    commit()
    write(INVOICE, version_two())
    done = repo("validate", "--previous-ref", "HEAD", INVOICE)
    assert done.status == 0
    assert "E-RANGE" not in done.out


NO_POLICY_NOTE = (
    "note: the previous version of {path} gives no policy, "
    "so its version order and widening are not checked"
)


def test_a_previous_version_that_gives_no_policy_is_unknown_history_and_not_a_new_agent(repo):
    # The file is at the ref, but nothing can be built from it (ruling R88). That is not a new agent
    # that must be at version 1: the history of this file is not known, as without a ref.
    write(INVOICE, swap(VALID, b"max_class: R2", b"max_class: ["))
    commit()
    for data in (VALID, version_two(), variant_file(SKIPS_A_VERSION, render=True)):
        write(INVOICE, data)
        done = repo("validate", "--previous-ref", "HEAD", INVOICE)
        assert done.status == 0
        assert {line.split()[1] for line in done.lines} == {"W-TOOL-NOT-LIVE"}
        assert done.err.splitlines() == [NO_POLICY_NOTE.format(path=INVOICE)]


def test_unknown_history_is_for_that_file_only(repo):
    # Two agents. The previous version of one gives no policy, and the other skips a version.
    other = "policies/payment-nudge.md"
    skips = (SKIPS_A_VERSION, setting("agent", "payment-nudge"), setting("principal", NUDGE_ID))
    write(INVOICE, swap(VALID, b"max_class: R2", b"max_class: ["))
    write(other, agent_file("payment-nudge"))
    commit()
    write(INVOICE, version_two())
    write(other, variant_file(*skips, render=True))
    done = repo("validate", "--previous-ref", "HEAD", INVOICE, other)
    orders = [(path_of(line), line.split()[1]) for line in done.lines if "VERSION-ORDER" in line]
    assert orders == [(other, "E-VERSION-ORDER")]  # and none for the file of unknown history
    assert done.err.splitlines() == [NO_POLICY_NOTE.format(path=INVOICE)]


def test_a_widening_is_not_reported_for_a_file_of_unknown_history_either(repo):
    # Two files of one agent. The previous version of the first is known. That of the copy gives no
    # policy, but check_set compares the copy with the previous version of the agent all the same,
    # and would find that it widens: for a file of unknown history that is left out as well.
    copy = "policies/invoice-copy.md"
    write(INVOICE, VALID)
    write(copy, swap(VALID, b"max_class: R2", b"max_class: ["))
    commit()
    widened = (NEXT_VERSION, MORE_RUNS_A_DAY)
    write(INVOICE, variant_file(*widened, render=True))
    write(
        copy,
        variant_file(*widened, setting("principal", principal_of("invoice-copy")), render=True),
    )
    done = repo("validate", "--previous-ref", "HEAD", INVOICE, copy)
    assert [path_of(line) for line in done.lines if " W-WIDENS " in line] == [INVOICE]
    assert [line for line in done.lines if "VERSION-ORDER" in line] == []
    assert done.err.splitlines() == [NO_POLICY_NOTE.format(path=copy)]


def test_the_note_about_a_previous_version_that_gives_no_policy_names_the_file_escaped(repo):
    name = "policies/x\n::error::y.md"  # a newline in a name could start a line of its own
    write(name, swap(VALID, b"max_class: R2", b"max_class: ["))
    commit()
    write(name, version_two())  # a version that would be E-VERSION-ORDER for a new agent
    done = repo("validate", "--previous-ref", "HEAD", name)
    assert "VERSION-ORDER" not in done.out  # (the name of the file is not the agent's: E-FILENAME)
    (note,) = done.err.splitlines()
    assert note == NO_POLICY_NOTE.format(path="policies/x\\u000a::error::y.md")


def spy_on_subprocess(monkeypatch) -> list[tuple[tuple, dict]]:
    """Every call of subprocess.run, as (positional arguments, keyword arguments)."""
    calls: list[tuple[tuple, dict]] = []
    real = subprocess.run

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    return calls


def git_commands(calls) -> list[tuple[str, list[str]]]:
    """Each call of git as (the folder it runs in, what it is asked to do)."""
    commands = []
    for args, _ in calls:
        (argv,) = args
        assert argv[:2] == [
            "git",
            "-C",
        ]  # git changes folder first: it need not be called from the repo
        commands.append((argv[2], argv[3:]))
    return commands


def test_git_is_run_with_a_list_of_arguments_and_no_shell(repo, monkeypatch):
    write(INVOICE, VALID)
    commit()
    calls = spy_on_subprocess(monkeypatch)
    assert repo("validate", "--previous-ref", "HEAD", INVOICE).status == 0
    assert calls
    for args, kwargs in calls:
        (argv,) = args
        assert isinstance(argv, list) and argv[0] == "git"
        assert all(isinstance(word, str) for word in argv)
        assert not kwargs.get("shell")
        assert kwargs.get("timeout")  # a git that hangs cannot hold up the build
    commands = git_commands(calls)
    folder = str(Path(INVOICE).resolve().parent)  # git runs in the folder of the file
    assert {where for where, _ in commands} == {folder}
    shows = [command for _, command in commands if command[0] == "show"]
    assert shows == [["show", "HEAD:policies/invoice-reminder.md"]]
    listings = [command for _, command in commands if command[0] == "ls-tree"]
    assert listings
    for command in listings:  # a path stands after `--`, so that nothing it says can be an option
        assert command[-2:] == ["--", "policies/invoice-reminder.md"]


def test_the_path_given_to_git_is_relative_to_the_repository(repo, monkeypatch):
    write(INVOICE, VALID)
    commit()
    calls = spy_on_subprocess(monkeypatch)
    absolute = str(Path.cwd() / INVOICE)
    assert repo("validate", "--previous-ref", "HEAD", absolute).status == 0
    monkeypatch.chdir("policies")  # and from a folder of the repository
    assert repo("validate", "--previous-ref", "HEAD", "invoice-reminder.md").status == 0
    shows = [command for _, command in git_commands(calls) if command[0] == "show"]
    assert shows == [["show", "HEAD:policies/invoice-reminder.md"]] * 2


def test_the_ref_works_from_outside_the_repository_with_an_absolute_path(
    repo, monkeypatch, tmp_path
):
    write(INVOICE, VALID)
    commit()
    write(INVOICE, version_two())
    absolute = str(Path.cwd() / INVOICE)
    monkeypatch.chdir(tmp_path)  # the folder above the repository: git finds none from here
    done = repo("validate", "--previous-ref", "HEAD", absolute)
    assert (done.status, done.err) == (0, "")
    assert {line.split()[1] for line in done.lines} == {"W-TOOL-NOT-LIVE"}
    write(absolute, variant_file(SKIPS_A_VERSION, render=True))  # the file of the repository
    skipped = repo("validate", "--previous-ref", "HEAD", absolute)
    assert skipped.status == 1 and "next version must be 2" in skipped.out


# --- a crash is E-INTERNAL and exit code 2 (validator-spec section 1, appendix A)

LEAK = "LEAK: a line of the file and the words of an exception"


def internal(path: str, detail: str) -> str:
    """The line for a crash: the name of the exception class is all that is said of it."""
    finding = Finding("E-INTERNAL", "error", path, params={"detail": detail})
    return format_line(finding)


def crashing(error: BaseException):
    def crash(*args, **kwargs):
        raise error

    return crash


def test_crash_exits_2_with_e_internal(run, monkeypatch):
    monkeypatch.setattr(cli, "validate_policy", crashing(RuntimeError(LEAK)))
    write(INVOICE, VALID)
    write(NUDGE, agent_file("payment-nudge"))
    done = run("validate", INVOICE, NUDGE)
    assert done.status == 2
    # One line for each file of the command, and nothing else: no finding, no text of the error.
    assert [line.split()[:2] for line in done.lines] == [["error", "E-INTERNAL"]] * 2
    assert done.lines == [internal(INVOICE, "RuntimeError"), internal(NUDGE, "RuntimeError")]
    assert "The validator could not finish (RuntimeError)." in done.lines[0]
    assert "LEAK" not in done.out + done.err
    assert "Traceback" not in done.err
    assert done.err.splitlines() == [DEBUG_NOTE]  # one fixed line: where the cause can be had


def test_a_file_named_twice_gets_one_line_when_the_command_crashes(run, monkeypatch):
    monkeypatch.setattr(cli, "validate_policy", crashing(RuntimeError(LEAK)))
    write(INVOICE, VALID)
    done = run("validate", INVOICE, "./" + INVOICE)
    assert done.lines == [internal(INVOICE, "RuntimeError")]


def test_a_crash_in_one_file_hides_the_findings_of_the_files_before_it(run, monkeypatch):
    real = cli.validate_policy

    def second_one_crashes(path, data, cfg, catalog):
        if path.name == "payment-nudge.md":
            raise KeyError(LEAK)
        return real(path, data, cfg, catalog)

    monkeypatch.setattr(cli, "validate_policy", second_one_crashes)
    write(INVOICE, VALID)
    write(NUDGE, agent_file("payment-nudge"))
    done = run("validate", INVOICE, NUDGE)
    assert (done.status, done.lines) == (
        2,
        [internal(INVOICE, "KeyError"), internal(NUDGE, "KeyError")],
    )


def test_debug_prints_the_traceback_to_stderr_and_only_then(run, monkeypatch):
    monkeypatch.setattr(cli, "validate_policy", crashing(RuntimeError(LEAK)))
    write(INVOICE, VALID)
    quiet = run("validate", INVOICE)
    loud = run("validate", "--debug", INVOICE)
    assert quiet.err.splitlines() == [DEBUG_NOTE]
    assert "Traceback" in loud.err and "RuntimeError" in loud.err and "LEAK" in loud.err
    assert DEBUG_NOTE not in loud.err  # it has been run with --debug
    assert (loud.status, loud.out) == (2, quiet.out)  # the same line, on stdout, either way


def test_a_crash_in_json_is_a_json_document_with_the_finding(run, monkeypatch):
    monkeypatch.setattr(cli, "validate_policy", crashing(RuntimeError(LEAK)))
    write(INVOICE, VALID)
    done = run("validate", "--json", INVOICE)
    assert done.status == 2
    (entry,) = json.loads(done.out)["findings"]
    assert (entry["code"], entry["path"], entry["params"]) == (
        "E-INTERNAL",
        INVOICE,
        {"detail": "RuntimeError"},
    )
    assert "LEAK" not in done.out


def test_a_crash_while_writing_the_lines_is_a_crash_too(run, monkeypatch):
    # A message that cannot be made (a check that forgot a param) is a bug and not half a message.
    broken = Finding("E-RANGE", "error", INVOICE, 5, params={"field": "version"})
    monkeypatch.setattr(cli, "validate_policy", lambda *args: Validated(None, [broken], {}))
    write(INVOICE, VALID)
    done = run("validate", INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "KeyError")])


# --- an output that cannot be written: stdout is closed or full, or cannot take the text

WRITE_NOTE = "note: the output could not be written"
DRIVER = "import sys; from aiven.policy.cli import main; sys.exit(main(sys.argv[1:]))"


class Unwritable:
    """A stdout that cannot be written to: `write` raises the error. It can have a descriptor."""

    def __init__(self, error: BaseException, fd: int | None = None):
        self.error = error
        self.fd = fd

    def write(self, text: str) -> int:
        raise self.error

    def flush(self) -> None:
        pass

    def fileno(self) -> int:
        if self.fd is None:
            raise io.UnsupportedOperation("fileno")
        return self.fd


WRITE_ERRORS = {
    "a full disk": OSError(28, LEAK),
    "an encoding that cannot take the text": UnicodeEncodeError(
        "ascii", LEAK, 0, 1, "ordinal not in range(128)"
    ),
    "a pipe that is closed": BrokenPipeError(32, LEAK),
}


@pytest.mark.parametrize("name", WRITE_ERRORS)
def test_an_output_that_cannot_be_written_is_exit_2_with_one_fixed_line_and_no_message(
    run, monkeypatch, name
):
    write(INVOICE, VALID)
    monkeypatch.setattr(sys, "stdout", Unwritable(WRITE_ERRORS[name]))
    done = run("render", INVOICE)  # render has nothing else to say on stderr
    assert done.status == 2
    # The one line, and so no traceback and nothing of the error (its message can hold file text).
    assert done.err == WRITE_NOTE + "\n"


def test_the_stdout_of_the_process_is_pointed_at_the_null_device_when_it_fails(run, monkeypatch):
    # Python writes what is still in the buffer of stdout once more when it exits. That fails again,
    # prints the error, and makes the exit code 120 (the tests below run the real thing).
    read_end, write_end = os.pipe()
    try:
        own = Unwritable(OSError(LEAK), fd=write_end)
        monkeypatch.setattr(sys, "stdout", own)
        monkeypatch.setattr(sys, "__stdout__", own)  # it is the stdout of the process
        write(INVOICE, VALID)
        assert run("render", INVOICE).status == 2
        assert os.fstat(write_end).st_rdev == os.stat(os.devnull).st_rdev
    finally:
        os.close(read_end)
        os.close(write_end)


def test_the_descriptor_of_a_stand_in_for_stdout_is_left_alone(run, monkeypatch):
    read_end, write_end = os.pipe()
    try:
        monkeypatch.setattr(sys, "stdout", Unwritable(OSError(LEAK), fd=write_end))
        write(INVOICE, VALID)
        assert run("render", INVOICE).status == 2
        assert stat.S_ISFIFO(os.fstat(write_end).st_mode)  # still the pipe
    finally:
        os.close(read_end)
        os.close(write_end)


def clean_environment(**more: str) -> dict[str, str]:
    """The environment of a real run: stdout buffered as it is in CI, and no platform values."""
    dropped = {"AIVEN_POLICY_CONFIG", "PYTHONUNBUFFERED", "PYTHONIOENCODING"}
    return {**{k: v for k, v in os.environ.items() if k not in dropped}, **more}


def test_a_pipe_that_is_closed_is_exit_2_and_not_exit_120_with_a_traceback():
    command = [sys.executable, "-c", DRIVER, "validate", "templates/policy-template.md"]
    options = {"cwd": REPO_ROOT, "env": clean_environment(), "stdout": subprocess.PIPE}
    with subprocess.Popen(command, stderr=subprocess.PIPE, **options) as process:
        process.stdout.close()  # whoever read the output has gone
        err = process.stderr.read().decode()
        status = process.wait()
    assert status == 2
    assert WRITE_NOTE in err.splitlines()
    for text in ("Traceback", "Exception ignored", "BrokenPipe", "Broken pipe"):
        assert text not in err


def test_a_character_that_the_encoding_of_stdout_cannot_take_is_written_as_an_escape(run):
    name = "caf\u00e9.md"  # a file name with an accent, written as an escape in this source
    write(name, VALID)
    command = [sys.executable, "-c", DRIVER, "validate", "--config", str(run.platform)]
    command += ["--catalog", str(CATALOG_FILE), name]
    environment = clean_environment(PYTHONIOENCODING="ascii")
    done = subprocess.run(command, env=environment, capture_output=True, check=False)
    assert done.returncode == 1  # the name is not the agent's: E-FILENAME, and that is all
    assert "caf\\xe9.md" in done.stdout.decode("ascii")  # it is ASCII, and the accent is an escape
    assert b"Traceback" not in done.stderr


@pytest.mark.parametrize("flag", [[], ["--json"]], ids=["lines", "json"])
def test_a_file_that_is_not_there_is_a_crash(run, flag):
    done = run("validate", *flag, "policies/nowhere.md")
    assert done.status == 2
    assert "E-INTERNAL" in done.out and "FileNotFoundError" in done.out


def test_a_platform_file_that_is_not_valid_is_a_crash_and_says_nothing_of_it(run, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(f"agents_project: {LEAK}\n")
    write(INVOICE, VALID)
    done = run("validate", "--config", str(bad), INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "ConfigError")])
    assert "LEAK" not in done.out + done.err


def test_an_environment_variable_that_names_no_file_is_a_crash_and_no_fallback(tree, monkeypatch):
    monkeypatch.setenv("AIVEN_POLICY_CONFIG", "config/nowhere.yaml")
    done = tree.raw("validate", INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "FileNotFoundError")])
    assert done.err.splitlines() == [DEBUG_NOTE]  # and the example was not used (no note of it)


def test_a_catalog_that_is_not_valid_is_a_crash(run, tmp_path):
    bad = tmp_path / "bad-catalog.yaml"
    bad.write_text("schema: something-else\n")
    write(INVOICE, VALID)
    done = run("validate", INVOICE, catalog=bad)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "CatalogError")])


def test_a_crash_in_the_checks_across_the_files_is_a_crash(run, monkeypatch):
    monkeypatch.setattr(cli, "check_set", crashing(ValueError(LEAK)))
    write(INVOICE, VALID)
    done = run("validate", INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "ValueError")])


def test_a_ref_that_git_does_not_know_is_a_crash_and_not_a_new_agent(repo):
    write(INVOICE, VALID)
    commit()
    done = repo("validate", "--previous-ref", "no-such-ref", INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "CalledProcessError")])


def test_a_folder_that_is_no_repository_is_a_crash(run, git_environment):
    write(INVOICE, VALID)
    done = run("validate", "--previous-ref", "HEAD", INVOICE)  # no git init here
    assert (done.status, done.lines) == (2, [internal(INVOICE, "CalledProcessError")])


@pytest.mark.parametrize("ref", ["", "-x", "--output=stolen"], ids=["empty", "short", "option"])
def test_a_ref_that_is_empty_or_could_be_an_option_is_refused_and_git_is_not_run(
    repo, monkeypatch, ref
):
    # An empty ref would make `git show :path`, which is the index and not a commit. A ref that
    # starts with a hyphen would be read by git as an option.
    write(INVOICE, VALID)
    commit()
    calls = spy_on_subprocess(monkeypatch)
    done = repo("validate", f"--previous-ref={ref}", INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "ValueError")])
    assert calls == []


def test_a_file_that_is_in_no_repository_is_a_crash(repo, tmp_path):
    # Git is asked in the folder of the file, and finds no repository there (the folder where the
    # command is run has one, and is not looked at).
    outside = tmp_path / "elsewhere" / "invoice-reminder.md"
    outside.parent.mkdir()
    outside.write_bytes(VALID)
    write(INVOICE, VALID)
    commit()
    done = repo("validate", "--previous-ref", "HEAD", str(outside))
    assert (done.status, done.lines) == (2, [internal(str(outside), "CalledProcessError")])


def test_a_file_in_another_repository_is_judged_by_that_one(repo, tmp_path):
    # The repository of the command has no previous version of the file; that of the file has one.
    other = tmp_path / "other"
    other.mkdir()
    file = other / "invoice-reminder.md"
    file.write_bytes(VALID)
    git("-C", str(other), "init", "-q", "-b", "main")
    git("-C", str(other), "add", "-A")
    git("-C", str(other), "commit", "-q", "-m", "a commit")
    file.write_bytes(version_two())
    done = repo("validate", "--previous-ref", "HEAD", str(file))
    assert (done.status, done.err) == (0, "")  # version 2 follows version 1 of that repository


@pytest.mark.parametrize(
    "argv",
    [[], ["nothing"], ["validate"], ["validate", "--json"], ["verify", "x.md"], ["render"]],
    ids=[
        "no command",
        "unknown command",
        "no file",
        "only a flag",
        "no signature",
        "no file for render",
    ],
)
def test_a_command_line_that_makes_no_sense_is_a_usage_error_with_exit_code_2(capsys, argv):
    with pytest.raises(SystemExit) as stop:
        main(argv)
    assert stop.value.code == 2
    out, err = capsys.readouterr()
    assert out == "" and err.startswith("usage: aiven-policy")


# --- render (validator-spec section 7, rulings R29 and R62)
#
# Render rewrites the two generated sections when the front matter loads and builds a policy without
# an error. What the file and the body say does not stop it: the placeholders, the name of the file
# and the drift are what a template has on its way to being a policy.

TEMPLATE_FILE = "templates/policy-template.md"
STALE = variant_file(NEXT_VERSION, MORE_RUNS_A_DAY)  # the front matter is new, the sections old
HEADING = b"## Enforced rules (generated)"


def test_render_of_the_template_gives_the_template_back(run):
    # The template is the reference output of the renderer, byte for byte (validator-spec section 7)
    # with its placeholders as they are; the findings of its file and body do not stop it.
    write(TEMPLATE_FILE, TEMPLATE_PATH.read_bytes())
    done = run("render", TEMPLATE_FILE)
    assert (done.status, done.out, done.err) == (0, "", "")
    assert Path(TEMPLATE_FILE).read_bytes() == TEMPLATE_PATH.read_bytes()


def test_the_template_becomes_a_policy_with_its_two_values_and_a_render(run):
    # Validator-spec section 9: "fill in the two values in the front matter, run `aiven-policy
    # render`, and save the file as `policies/invoice-reminder.md`. After that only the three
    # warnings remain (exit 0)." Each value is filled in where it stands first: in the front matter.
    text = TEMPLATE_PATH.read_text()
    text = text.replace("REPLACE_ME_AGENTS_PROJECT", AGENTS_PROJECT, 1)
    text = text.replace("REPLACE_ME_FOLDER_ID", FOLDER_ID, 1)
    write(INVOICE, text.encode())
    before = run("validate", INVOICE)
    assert before.status == 1 and " E-PLACEHOLDER " in before.out  # the sections still have them
    assert run("render", INVOICE).status == 0
    done = run("validate", INVOICE)
    assert done.status == 0
    assert [line.split()[:2] for line in done.lines] == [["warning", "W-TOOL-NOT-LIVE"]] * 3
    assert (
        Path(INVOICE).read_bytes() == valid_base()
    )  # and it is the file that the tests start from


def test_render_rewrites_the_generated_sections_and_nothing_else(run):
    write(INVOICE, STALE)
    assert "E-BODY-DRIFT" in run("validate", INVOICE).out
    done = run("render", INVOICE)
    assert (done.status, done.out, done.err) == (0, "", "")
    rendered = Path(INVOICE).read_bytes()
    assert rendered == rerendered(STALE) != STALE
    assert rendered.split(HEADING)[0] == STALE.split(HEADING)[0]  # before the sections: as it was
    assert "E-BODY-DRIFT" not in run("validate", INVOICE).out
    run("render", INVOICE)
    assert Path(INVOICE).read_bytes() == rendered  # and a second render changes nothing


def test_the_findings_that_do_not_stop_a_render_are_those_of_spec_3_1_3_7_and_3_8():
    # The file, the body and the content: every other finding of the validator is of the front
    # matter, which render needs to be good. The spec is the authority on which is which.
    headings = ("3.1 File", "3.7 Body", "3.8 Content safety")
    spec = {row[0] for heading in headings for row in table_after(heading)[1:]}
    assert len(spec) == 18
    assert FILE_AND_BODY_CODES == spec


# A file that is not right, but not in its front matter: render goes on.
NOT_IN_THE_FRONT_MATTER = {
    "no newline at the end": lambda data: data.rstrip(b"\n"),
    "a hidden character": lambda data: swap(data, b"Once a day", b"Once\xe2\x80\x8b a day"),
    "a placeholder in the body": lambda data: swap(data, b"Once a day", b"TODO Once a day"),
    "a link in the body": lambda data: swap(data, b"Once a day", b"See www.example.com. Once"),
    "a tool that is not explained": lambda data: swap(
        data, b"- `sheets.read`: reads", b"- `sheets.sned`: reads"
    ),
    "a name that is not the agent": lambda data: data,  # the file is written as another name
}


@pytest.mark.parametrize("name", NOT_IN_THE_FRONT_MATTER)
def test_what_the_file_and_the_body_say_does_not_stop_a_render(run, name):
    data = NOT_IN_THE_FRONT_MATTER[name](STALE)
    target = "policies/other-name.md" if name == "a name that is not the agent" else INVOICE
    write(target, data)
    done = run("render", target)
    assert (done.status, done.out) == (0, "")
    assert Path(target).read_bytes() == rerendered(data)


def test_a_content_finding_does_not_stop_a_render_either(run):
    secret = gen.secret_values()["Google API key"][0]  # made now: no key is in the source
    data = swap(STALE, b"Once a day", secret.encode() + b" Once a day")
    write(INVOICE, data)
    done = run("render", INVOICE)
    assert (done.status, done.out) == (0, "")
    assert Path(INVOICE).read_bytes() == rerendered(data)


def test_a_warning_in_the_front_matter_does_not_stop_a_render(run):
    data = variant_file(setting("untrusted_input", "taint"), setting("shadow.min_runs", 5))
    write(INVOICE, data)
    assert run("render", INVOICE).status == 0
    assert Path(INVOICE).read_bytes() == rerendered(data)


# A file whose front matter does not load, or builds no policy, or builds one with an error.
FRONT_MATTER_ERRORS = {
    "front matter that is no YAML": (swap(VALID, b"max_class: R2", b"max_class: ["), "E-YAML"),
    "no front matter": (swap(VALID, b"---\nschema:", b"--- \nschema:"), "E-FM-MISSING"),
    "a field that is missing": (variant_file(without("shadow.min_runs")), "E-FIELD-MISSING"),
    "a number out of range": (variant_file(setting("limits.runs_per_day", 11)), "E-RANGE"),
    "a tool that is not in the catalog": (
        variant_file(with_tools("sheets.read", "gmail.sned")),
        "E-TOOL-UNKNOWN",
    ),
    "a principal that is not the agent's": (
        variant_file(setting("principal", "agent-other@aiven-agents-test.iam.gserviceaccount.com")),
        "E-PRINCIPAL",
    ),
}


@pytest.mark.parametrize("name", FRONT_MATTER_ERRORS)
def test_an_error_in_the_front_matter_stops_the_render_and_only_it_is_shown(run, name):
    data, code = FRONT_MATTER_ERRORS[name]
    # The body has a finding of its own, which render has no reason to show.
    data = swap(data, b"Once a day", b"TODO Once a day")
    write(INVOICE, data)
    done = run("render", INVOICE)
    assert done.status == 1
    assert Path(INVOICE).read_bytes() == data  # not touched
    shown = {line.split()[1] for line in done.lines}
    assert code in shown
    assert shown.isdisjoint({"E-PLACEHOLDER", "E-FILENAME", "E-BODY-DRIFT"})
    assert {line.split()[0] for line in done.lines} <= {"error", "warning"}


def test_a_placeholder_where_a_number_belongs_stops_the_render_and_is_shown(run):
    # No policy comes out of that front matter, and no check of it has an error to show: the finding
    # that says why is the one of the file.
    data = swap(VALID, b"version: 1\n", b"version: TODO\n")
    write(INVOICE, data)
    done = run("render", INVOICE)
    assert done.status == 1
    line = line_of(data.decode(), "version: TODO")
    assert f"error E-PLACEHOLDER policies/invoice-reminder.md:{line}:" in done.out
    assert Path(INVOICE).read_bytes() == data


# Files whose generated sections the renderer cannot put where they belong, with the errors of the
# body that say why. Nothing is wrong in their front matter, so render shows all their findings.
REFUSED_BY_THE_RENDERER = {
    "a section behind the sign-off": (
        VALID + b"\n## Appendix\n\nMore text.\n",
        {"E-BODY-SECTIONS"},
    ),
    "a second title": (VALID + b"\n# Second title\n\nMore text.\n", {"E-BODY-SECTIONS"}),
    "the heading in a fence that is never closed": (
        swap(VALID, HEADING, b"```\n" + HEADING),
        {"E-BODY-SECTIONS"},
    ),
    "no sections, and a comment that is open": (
        VALID.split(HEADING)[0] + b"<!-- open\n",
        {"E-BODY-SECTIONS", "E-BODY-HTML"},
    ),
}


@pytest.mark.parametrize("name", REFUSED_BY_THE_RENDERER)
def test_sections_that_cannot_be_rewritten_stop_the_render_and_the_file_is_not_touched(run, name):
    data, codes = REFUSED_BY_THE_RENDERER[name]
    write(INVOICE, data)
    done = run("render", INVOICE)
    assert done.status == 1
    assert done.lines == [format_line(f) for f in findings_of(INVOICE, data)]  # all of them
    assert {line.split()[1] for line in done.lines if line.startswith("error")} == codes
    assert Path(INVOICE).read_bytes() == data


def test_a_value_error_of_the_renderer_counts_as_a_front_matter_error(run, monkeypatch):
    # The renderer refuses what has no text in section 7, such as a tool outside the catalog.
    monkeypatch.setattr(cli, "rewrite", crashing(ValueError(LEAK)))
    write(INVOICE, STALE)
    done = run("render", INVOICE)
    assert done.status == 1
    assert Path(INVOICE).read_bytes() == STALE
    assert done.lines == [format_line(f) for f in findings_of(INVOICE, STALE)]  # all of them
    assert "LEAK" not in done.out + done.err and "Traceback" not in done.err


def test_the_file_is_replaced_at_once_by_a_file_of_the_same_folder(run, monkeypatch):
    write(INVOICE, STALE)
    replaced: list[tuple[Path, Path, bytes]] = []
    real = os.replace

    def replace(source, target):
        replaced.append((Path(source), Path(target), Path(source).read_bytes()))
        real(source, target)

    monkeypatch.setattr(os, "replace", replace)
    assert run("render", INVOICE).status == 0
    ((source, target, content),) = replaced
    assert source.parent == target.parent == Path(INVOICE).resolve().parent
    assert content == Path(INVOICE).read_bytes() == rerendered(STALE)
    assert not source.exists()
    assert sorted(path.name for path in Path("policies").iterdir()) == ["invoice-reminder.md"]


def test_a_write_that_fails_leaves_the_file_as_it_was_and_no_temporary_file(run, monkeypatch):
    write(INVOICE, STALE)
    monkeypatch.setattr(os, "replace", crashing(OSError(LEAK)))
    done = run("render", INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "OSError")])
    assert Path(INVOICE).read_bytes() == STALE
    assert sorted(path.name for path in Path("policies").iterdir()) == ["invoice-reminder.md"]


def test_the_file_keeps_its_permissions(run):
    path = write(INVOICE, STALE)
    path.chmod(0o640)
    assert run("render", INVOICE).status == 0
    assert path.stat().st_mode & 0o777 == 0o640


def test_a_symbolic_link_is_followed_and_stays_a_link(run):
    target = write("elsewhere/invoice-reminder.md", STALE)
    link = Path(INVOICE)
    link.parent.mkdir()
    link.symlink_to(target.resolve())
    assert run("render", INVOICE).status == 0
    assert link.is_symlink()
    assert target.read_bytes() == rerendered(STALE)


def test_a_file_that_is_not_there_cannot_be_rendered(run):
    done = run("render", INVOICE)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "FileNotFoundError")])
    assert not Path(INVOICE).exists()


# --- verify (validator-spec sections 2 and 3.10)
#
# This is the check before the upload: the signature, the file, and the version against the active
# one. Whether a wrapper is switched on for the agent and whether the folder is in the Sandbox drive
# only the gateway knows: here a wrapper is live unless the catalog says planned, and the folder
# passes.

VERIFY_NOTE = "note: wrapper enablement and the Drive folder are checked at the gateway"
OTHER_HASH = "sha256:" + "a" * 64


@pytest.fixture
def signer(tmp_path) -> Signer:
    return make_signer(tmp_path / "matthijs")


def signed(signer: Signer, data: bytes = VALID) -> Path:
    """Write the file, sign it as it is, and give the path of the signature."""
    write(INVOICE, data)
    sig = Path(INVOICE + ".sig")
    sig.write_bytes(signer.sign(data))
    return sig


def verify(run: Cli, signer: Signer, sig: Path, *more: str, catalog: Path | None = None) -> Ran:
    options = ["--sig", str(sig), "--allowed-signers", str(signer.allowed_signers)]
    return run("verify", INVOICE, *options, *more, catalog=catalog or CATALOG_FILE)


def test_a_signed_file_that_is_valid_loads(run, signer, built_catalog):
    sig = signed(signer)
    done = verify(run, signer, sig, catalog=built_catalog)
    assert (done.status, done.out) == (0, "")
    assert done.err.splitlines() == [VERIFY_NOTE]


def test_a_wrapper_that_the_catalog_says_is_planned_is_not_live(run, signer):
    sig = signed(signer)
    done = verify(run, signer, sig)  # the real catalog: no wrapper is built
    assert done.status == 1
    assert [line.split()[:2] for line in done.lines] == [["error", "E-TOOL-NOT-LIVE"]] * 3
    text = VALID.decode()
    for line, tool in zip(done.lines, ("sheets.read", "gmail.draft", "gmail.send"), strict=True):
        assert f"{INVOICE}:{tool_line(text, tool)}: Tool {tool} needs the" in line
    assert done.err.splitlines() == [VERIFY_NOTE]  # the note is there when the file fails as well


def test_the_folder_of_the_policy_passes_because_only_the_gateway_can_check_it(
    run, signer, built_catalog
):
    # The base has a folder ID. Nothing here knows the Sandbox drive, so it cannot be refused.
    assert policy_of(VALID).scope.drive_folder_id is not None
    done = verify(run, signer, signed(signer), catalog=built_catalog)
    assert (done.status, done.out) == (0, "")


def test_a_signature_file_that_is_not_there_is_e_sig_missing(run, signer, built_catalog):
    write(INVOICE, VALID)
    done = verify(run, signer, Path(INVOICE + ".sig"), catalog=built_catalog)
    assert done.status == 1
    assert done.lines == [
        "error E-SIG-MISSING policies/invoice-reminder.md: "
        "No signature file invoice-reminder.md.sig. Unsigned policies are never loaded."
    ]


def test_a_file_that_changed_after_it_was_signed_is_e_sig_invalid(run, signer, built_catalog):
    sig = signed(signer)
    write(INVOICE, swap(VALID, b"Once a day", b"Once a week"))
    done = verify(run, signer, sig, catalog=built_catalog)
    assert done.status == 1
    assert [line.split()[:3] for line in done.lines] == [["error", "E-SIG-INVALID", INVOICE + ":"]]


def test_a_signature_of_another_key_is_e_sig_invalid(run, signer, tmp_path, built_catalog):
    stranger = make_signer(tmp_path / "stranger")
    sig = signed(stranger)
    done = verify(run, signer, sig, catalog=built_catalog)
    assert (done.status, [line.split()[1] for line in done.lines]) == (1, ["E-SIG-INVALID"])


def test_a_signed_file_with_an_error_is_refused_with_that_error(run, signer, built_catalog):
    data = variant_file(setting("limits.runs_per_day", 11), render=True)
    sig = signed(signer, data)
    done = verify(run, signer, sig, catalog=built_catalog)
    assert done.status == 1
    assert "error E-RANGE" in done.out


def test_a_version_below_the_active_one_is_refused(run, signer, built_catalog):
    sig = signed(signer)
    active = ["--active-version", "3", "--active-sha256", OTHER_HASH]
    done = verify(run, signer, sig, *active, catalog=built_catalog)
    assert done.status == 1
    assert done.lines == [
        "error E-VERSION-ORDER policies/invoice-reminder.md: "
        "version is 1, but the next version must be 4. Older versions can never come back."
    ]


def test_the_smallest_active_version_is_1(run, signer, built_catalog):
    sig = signed(signer)
    active = ["--active-version", "1", "--active-sha256", policy_of(VALID).sha256]
    assert verify(run, signer, sig, *active, catalog=built_catalog).status == 0


def test_the_active_version_itself_loads_again(run, signer, built_catalog):
    sig = signed(signer)
    active = ["--active-version", "1", "--active-sha256", policy_of(VALID).sha256]
    assert verify(run, signer, sig, *active, catalog=built_catalog).status == 0


@pytest.mark.parametrize(
    "options",
    [
        ["--active-version", "3"],
        ["--active-sha256", OTHER_HASH],
        ["--active-version", "3", "--active-sha256", "sha256:abc"],
        ["--active-version", "three", "--active-sha256", OTHER_HASH],
        ["--active-version", "0", "--active-sha256", OTHER_HASH],
        ["--active-version", "-1", "--active-sha256", OTHER_HASH],
        ["--active-version", "1.5", "--active-sha256", OTHER_HASH],
    ],
    ids=[
        "no hash",
        "no version",
        "a hash that is not one",
        "a version that is no number",
        "a version of 0",
        "a version below 0",
        "a version that is not whole",
    ],
)
def test_the_active_version_and_its_hash_go_together_and_are_well_formed(
    run, signer, built_catalog, options
):
    sig = signed(signer)
    with pytest.raises(SystemExit) as stop:
        verify(run, signer, sig, *options, catalog=built_catalog)
    assert stop.value.code == 2
    out, err = run.capsys.readouterr()
    assert out == "" and err.startswith("usage: aiven-policy verify")


def test_a_trust_anchor_that_cannot_be_used_is_e_internal_and_exit_2(run, signer, tmp_path):
    # verify() says E-INTERNAL when the fault is the setup and not the policy. That is exit 2.
    sig = signed(signer)
    gone = Signer(signer.key, tmp_path / "no-allowed-signers")
    done = verify(run, gone, sig)
    assert (done.status, done.lines) == (2, [internal(INVOICE, "FileNotFoundError")])
    assert done.err.splitlines() == [VERIFY_NOTE, DEBUG_NOTE]


def test_a_signature_that_cannot_be_read_is_a_crash_and_not_a_missing_one(run, signer, tmp_path):
    write(INVOICE, VALID)
    done = verify(run, signer, tmp_path)  # a folder
    assert (done.status, done.lines) == (2, [internal(INVOICE, "IsADirectoryError")])


def test_a_file_that_is_not_there_cannot_be_verified(run, signer, tmp_path):
    done = verify(run, signer, tmp_path / "x.sig")
    assert (done.status, done.lines) == (2, [internal(INVOICE, "FileNotFoundError")])
