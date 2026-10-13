"""The seam in validate.py: `validate_policy` gives the policy with the findings (validator-spec 1).

`validate_file` gives the findings of one run of the checks. `validate_policy` is the same run, and
it also gives the `Policy` that the front matter builds, and the file line of each entry of `tools`
(a `Policy` has no line map, ruling R55). `verify` needs them and calls it, so that no check runs
twice for a file that it loads. The tests of `verify` are in test_verify.py.
"""

import hashlib
from collections import Counter
from pathlib import Path

import pytest

from aiven.policy import validate as validate_module
from aiven.policy.constants import MAX_FILE_BYTES, MAX_SCANNED_BYTES
from aiven.policy.validate import report_order, validate_file, validate_policy
from tests.support import gen
from tests.support.bodies import policy_of
from tests.support.frontmatter import BASE_TEXT, tool_line, tool_lines
from tests.support.policies import BASE_PATH, TEMPLATE_NAME, TEMPLATE_PATH, padded, valid_base
from tests.support.rules import CATALOG, CFG, with_tools
from tests.support.signing import work_in_a_temporary_folder as work_in_a_temporary_folder
from tests.support.spies import CHECKS, spy_on
from tests.support.variants import variant_file

BASE = valid_base()
TEMPLATE = TEMPLATE_PATH.read_bytes()
BASE_TOOLS = ("sheets.read", "gmail.draft", "gmail.send")

# These tests ran in a folder of their own when they were a part of test_verify.py, and they still
# do (the fixture above, tests/support/signing.py).

SEAM_INPUTS = {
    "the valid base": BASE,
    "the template": TEMPLATE,
    "no front matter": b"# invoice-reminder\n",
    "a syntax error": BASE.replace(b"max_class: R2", b"max_class: ["),
    "a wrong type": BASE.replace(b"version: 1", b"version: one"),
    "a number out of range": BASE.replace(b"runs_per_day: 1", b"runs_per_day: 11"),
    "a file over 64 KiB": padded(MAX_FILE_BYTES + 1),
    "a file too large to read through": b"x" * (MAX_SCANNED_BYTES + 1),
}

# Inputs that have a policy: the front matter is complete and well typed. The values do not have
# to be right (ruling R4): the template still holds its placeholders, and a number may be too high.
HAVE_A_POLICY = ("the valid base", "the template", "a number out of range", "a file over 64 KiB")


def test_the_tests_of_this_module_run_in_a_folder_of_their_own(tmp_path):
    # The fixture of tests/support/signing.py, imported above: it looks unused, and it is not.
    assert tmp_path in Path.cwd().parents


@pytest.mark.parametrize("name", SEAM_INPUTS)
def test_validate_file_gives_only_the_findings_of_validate_policy(name):
    data = SEAM_INPUTS[name]
    findings = validate_file(BASE_PATH, data, CFG, CATALOG)
    assert isinstance(findings, list)
    assert findings == validate_policy(BASE_PATH, data, CFG, CATALOG).findings


@pytest.mark.parametrize("name", SEAM_INPUTS)
def test_the_findings_of_validate_policy_are_in_report_order(name):
    findings = validate_policy(BASE_PATH, SEAM_INPUTS[name], CFG, CATALOG).findings
    assert findings == sorted(findings, key=report_order)


def test_the_template_has_the_findings_of_section_9_in_report_order():
    findings = validate_policy(TEMPLATE_NAME, TEMPLATE, CFG, CATALOG).findings
    assert [(found.code, found.line) for found in findings] == [
        ("E-FILENAME", None),
        ("E-PLACEHOLDER", 6),
        ("W-TOOL-NOT-LIVE", 9),
        ("W-TOOL-NOT-LIVE", 10),
        ("W-TOOL-NOT-LIVE", 11),
        ("E-PLACEHOLDER", 25),
        ("E-PLACEHOLDER", 56),
        ("E-PLACEHOLDER", 84),
    ]


@pytest.mark.parametrize("name", SEAM_INPUTS)
def test_validate_policy_gives_the_policy_that_the_front_matter_builds(name):
    result = validate_policy(BASE_PATH, SEAM_INPUTS[name], CFG, CATALOG)
    if name in HAVE_A_POLICY:
        assert result.policy == policy_of(SEAM_INPUTS[name])
    else:
        assert result.policy is None


def test_the_policy_of_validate_policy_has_the_hash_of_the_bytes():
    policy = validate_policy(BASE_PATH, BASE, CFG, CATALOG).policy
    assert policy is not None
    assert policy.sha256 == "sha256:" + hashlib.sha256(BASE).hexdigest()


def test_validate_policy_runs_every_check_once(monkeypatch):
    calls = spy_on(monkeypatch, validate_module, CHECKS)
    validate_policy(BASE_PATH, BASE, CFG, CATALOG)
    assert calls == Counter(dict.fromkeys(CHECKS, 1))


def test_validate_file_runs_every_check_once_too(monkeypatch):
    calls = spy_on(monkeypatch, validate_module, CHECKS)
    validate_file(BASE_PATH, BASE, CFG, CATALOG)
    assert calls == Counter(dict.fromkeys(CHECKS, 1))


def test_validate_policy_gives_the_line_of_each_tool():
    result = validate_policy(BASE_PATH, BASE, CFG, CATALOG)
    assert result.tool_lines == {tool: tool_line(BASE_TEXT, tool) for tool in BASE_TOOLS}


def test_a_tool_that_is_listed_twice_has_the_line_of_its_first_entry():
    data = variant_file(with_tools("sheets.read", "gmail.draft", "sheets.read"))
    first, second = tool_lines(data.decode(), "sheets.read")
    assert first < second
    assert validate_policy(BASE_PATH, data, CFG, CATALOG).tool_lines["sheets.read"] == first


def test_tools_that_fail_their_rules_have_a_line_too():
    data = variant_file(with_tools("sheets.read", "gmail.sned"))
    lines = validate_policy(BASE_PATH, data, CFG, CATALOG).tool_lines
    assert lines == {tool: tool_line(data.decode(), tool) for tool in ("sheets.read", "gmail.sned")}


def test_there_are_no_tool_lines_when_the_list_has_no_value():
    data = BASE.replace(b"  - gmail.send\n", b"  - [a, b]\n")  # an entry of the wrong type
    result = validate_policy(BASE_PATH, data, CFG, CATALOG)
    assert (result.policy, result.tool_lines) == (None, {})


def test_the_tool_lines_hold_text_of_the_file_and_are_not_in_the_repr():
    secret = gen.secret_values()["AWS access key"][0]
    result = validate_policy(
        BASE_PATH, variant_file(with_tools("sheets.read", secret)), CFG, CATALOG
    )
    assert secret in result.tool_lines
    assert secret not in repr(result)
