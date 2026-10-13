"""Guards on the Terraform in infra/ that CI runs with the other tests (rulings R98, R105).

`terraform test` (infra/terraform/tests) checks what the configuration makes. These check what it
must never hold, and that it stays in step with the validator and with CI. They read the files as
text: they need no Terraform.
"""

import re
from pathlib import Path

from ruamel.yaml import YAML

from aiven.policy.constants import AGENT_ID_LENGTH, AGENT_ID_PATTERN, RESERVED_AGENT_IDS
from tests.support import REPO_ROOT

INFRA = REPO_ROOT / "infra"
TERRAFORM = INFRA / "terraform"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def terraform_files() -> list[Path]:
    """Every Terraform file in infra/: configuration, tests and values."""
    files = [
        path
        for path in INFRA.rglob("*")
        if path.is_file()
        and ".terraform" not in path.parts
        and (path.suffix in (".tf", ".hcl") or path.name.endswith((".tfvars", ".tfvars.example")))
    ]
    assert files
    return sorted(files)


def text_of(path: Path) -> str:
    """The text of a file without its lines that are comments, so that a note may name what is
    refused. A comment after code stays: the guards read it too, which errs on the safe side."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not re.match(r"\s*(#|//)", line))


def test_nothing_is_locked_without_matthijs_confirming():
    # Locking the audit log bucket (locked) or a bucket's retention policy (is_locked) cannot be
    # undone. Matthijs confirms the audit log lock separately, and the commit that makes it lifts
    # this guard for that one line (ruling R105).
    for path in terraform_files():
        assert not re.search(r"\b(is_)?locked\s*=\s*true\b", text_of(path)), path


def test_no_service_account_key_is_ever_made():
    for path in terraform_files():
        assert "google_service_account_key" not in text_of(path), path


def test_iam_is_only_ever_added_never_set_whole():
    # An authoritative resource (_iam_policy, _iam_binding) replaces what is there, Matthijs's own
    # access and Google's service agents included. Only _iam_member is used.
    for path in terraform_files():
        found = re.search(r'(resource|data)\s+"google_\w+_iam_(policy|binding)"', text_of(path))
        assert found is None, (path, found)


def test_every_api_stays_on_when_terraform_lets_go_of_it():
    for path in terraform_files():
        text = text_of(path)
        services = len(re.findall(r'resource\s+"google_project_service"', text))
        assert services == text.count("disable_on_destroy = false"), path


def test_every_location_written_out_is_europe_west4():
    # The tests of terraform test are left out: they try other regions on purpose.
    for path in terraform_files():
        if path.name.endswith(".tftest.hcl"):
            continue
        for found in re.finditer(r'\b(location|region|location_id)\s*=\s*"([^"]*)"', text_of(path)):
            assert found[2] == "europe-west4", (path, found[0])


def test_the_agent_id_rule_is_the_validators():
    text = (TERRAFORM / "variables.tf").read_text(encoding="utf-8")
    (block,) = re.findall(r'variable "agents" \{.*?\n\}', text, re.DOTALL)
    assert f'can(regex("^{AGENT_ID_PATTERN}$", agent))' in block
    low, high = AGENT_ID_LENGTH
    assert f"length(agent) >= {low} && length(agent) <= {high}" in block
    (reserved,) = re.findall(r"toset\(\[\s*(.*?)\s*\]\)\)\) == 0", block, re.DOTALL)
    assert set(re.findall(r'"([a-z]+)"', reserved)) == RESERVED_AGENT_IDS


def test_the_project_id_rule_is_the_validators():
    from aiven.policy.config import PROJECT_ID

    text = (TERRAFORM / "variables.tf").read_text(encoding="utf-8")
    rules = re.findall(r'can\(regex\("\^(.*?)\$", var\.(\w+)_project\)\)', text)
    assert sorted(name for _, name in rules) == ["agents", "control", "gateway"]
    assert {rule for rule, _ in rules} == {PROJECT_ID}


# --- versions (ruling R98)


def terraform_job() -> list[dict]:
    jobs = YAML(typ="safe").load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    return jobs["terraform"]["steps"]


def required_version() -> str:
    (version,) = re.findall(
        r'required_version = "([0-9.]+)"', (TERRAFORM / "versions.tf").read_text()
    )
    return version


def test_ci_runs_the_terraform_of_versions_tf_and_checks_its_sha256():
    version = required_version()
    (download,) = [
        str(step["run"])
        for step in terraform_job()
        if "releases.hashicorp.com" in str(step.get("run", ""))
    ]
    assert f"/terraform/{version}/terraform_{version}_linux_amd64.zip" in download
    assert re.search(
        r'echo "[0-9a-f]{64}  \$RUNNER_TEMP/terraform\.zip" \| sha256sum -c -', download
    )


def test_ci_checks_format_validates_and_tests_with_the_locked_providers():
    runs = [str(step.get("run", "")) for step in terraform_job()]
    assert (
        "terraform -chdir=infra/terraform init -backend=false -input=false -lockfile=readonly"
        in runs
    )
    assert "terraform -chdir=infra/terraform fmt -check -recursive" in runs
    assert "terraform -chdir=infra/terraform validate" in runs
    assert "terraform -chdir=infra/terraform test" in runs
    assert runs.index("terraform -chdir=infra/terraform test") > runs.index(
        "terraform -chdir=infra/terraform validate"
    )


def test_every_action_of_the_terraform_job_is_pinned_by_the_sha_of_a_commit():
    used = [step["uses"] for step in terraform_job() if "uses" in step]
    assert used
    for action in used:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), action


def test_the_lock_file_holds_the_provider_of_versions_tf_for_five_platforms():
    versions = (TERRAFORM / "versions.tf").read_text(encoding="utf-8")
    lock = (TERRAFORM / ".terraform.lock.hcl").read_text(encoding="utf-8")
    pinned = dict(re.findall(r'source\s+= "(hashicorp/\w+)"\s+version\s+= "([0-9.]+)"', versions))
    locked = dict(
        re.findall(
            r'provider "registry\.terraform\.io/(hashicorp/\w+)" \{\s+version\s+= "([0-9.]+)"', lock
        )
    )
    assert pinned and pinned == locked
    for block in re.findall(r"hashes = \[(.*?)\]", lock, re.DOTALL):
        assert len(re.findall(r'"h1:[A-Za-z0-9+/=]+"', block)) >= 5
