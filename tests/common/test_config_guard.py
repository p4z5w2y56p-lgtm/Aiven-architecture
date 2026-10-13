"""The config guard, `aiven-check-config` (ruling R113).

`config/platform.yaml` and `infra/terraform/terraform.tfvars` hold IDs and addresses only, never a
credential, a key or a token (M1 review). The guard refuses what does not fit, and it never prints
a value: a line of its output is a code, a path, a line number and a fixed text.

Every secret-shaped value here is built from fragments at test time (tests/support/gen.py), and
every refusal checks that the output does not hold the value it refuses.
"""

import re
from pathlib import Path

import pytest

from aiven.common import config_guard
from aiven.common.config_guard import DEFAULT_FILES, main, secret_like
from aiven.policy.constants import MAX_FILE_BYTES
from tests.support import REPO_ROOT
from tests.support.gen import assignment, secret_values, valid_bsn, valid_card, valid_iban

EXAMPLE = REPO_ROOT / "config" / "platform.example.yaml"

SECRETS = secret_values()
AWS_KEY = SECRETS["AWS access key"][0]
GITHUB_TOKEN = SECRETS["GitHub token"][0]
PEM_HEADER = SECRETS["private key"][0]
SERVICE_ACCOUNT_KEY_LINE = '# "private' + '_key": "-----BEGIN"\n'
CARD, IBAN, BSN = valid_card(), valid_iban(), valid_bsn()

# `error <CODE> <path>[:<line>]: <text>`; the path is the shortest that fits.
OUTPUT_LINE = re.compile(r"error (C-[A-Z-]+) (.+?)(?::([0-9]+))?: (.+)")


def run(capsys, *paths: Path | str) -> tuple[int, list[tuple[str, int | None]], str]:
    """Run the command on `paths`: the exit code, the (code, line) of each output line, stdout."""
    status = main([str(path) for path in paths])
    out = capsys.readouterr().out
    found: list[tuple[str, int | None]] = []
    for line in out.splitlines():
        match = OUTPUT_LINE.fullmatch(line)
        assert match is not None, line
        found.append((match[1], None if match[3] is None else int(match[3])))
    return status, found, out


def same(found: list, expected: list) -> bool:
    return sorted(found, key=str) == sorted(expected, key=str)


def swap(text: str, old: str, new: str) -> str:
    assert old in text, old
    return text.replace(old, new, 1)


# --- platform values (config/platform.yaml)

PLATFORM = """\
# The platform values of the deployment: IDs and addresses, no credentials.
agents_project: aiven-agents-test
trusted_authors:
  - author@aivenstudios.com
  - second.author@aivenstudios.com
gateway_principal: gateway@aiven-gateway-test.iam.gserviceaccount.com
sandbox_drive_id: 0AbCdEfGhIjKlMnOpQ
"""
AUTHORS = "trusted_authors:\n  - author@aivenstudios.com\n  - second.author@aivenstudios.com\n"


def platform(tmp_path: Path, text: str, name: str = "platform.yaml") -> Path:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return path


def test_the_example_platform_values_pass(capsys):
    assert run(capsys, EXAMPLE) == (0, [], "")


@pytest.mark.parametrize(
    "text",
    [
        PLATFORM,
        swap(PLATFORM, "sandbox_drive_id: 0AbCdEfGhIjKlMnOpQ\n", ""),
        swap(PLATFORM, "0AbCdEfGhIjKlMnOpQ", "null"),
        PLATFORM.replace("\n", "\r\n"),
    ],
    ids=["all-four", "without-the-drive-id", "drive-id-null", "windows-line-ends"],
)
def test_realistic_platform_values_pass(tmp_path, capsys, text):
    assert run(capsys, platform(tmp_path, text)) == (0, [], "")


PLATFORM_REFUSED = {
    "private-key-in-a-comment": (PLATFORM + f"# {PEM_HEADER}\n", [("C-SECRET", 8)], PEM_HEADER),
    "service-account-key-line": (
        PLATFORM + SERVICE_ACCOUNT_KEY_LINE,
        [("C-SECRET", 8)],
        '"private' + '_key"',
    ),
    "token-assignment": (
        PLATFORM + "# " + assignment("token", ": ", "Zq7fK2pW") + "\n",
        [("C-SECRET", 8)],
        "Zq7fK2pW",
    ),
    "card-number-in-a-comment": (PLATFORM + f"# paid with {CARD}\n", [("C-SECRET", 8)], CARD),
    "iban-in-a-comment": (PLATFORM + f"# {IBAN}\n", [("C-SECRET", 8)], IBAN),
    "bsn-in-a-comment": (PLATFORM + f"# {BSN}\n", [("C-SECRET", 8)], BSN),
    # An AWS key fits the shape of a drive id, so only the scan stands in its way.
    "aws-key-as-the-drive-id": (
        swap(PLATFORM, "0AbCdEfGhIjKlMnOpQ", AWS_KEY),
        [("C-SECRET", 7)],
        AWS_KEY,
    ),
    # Written with an escape, the key is not in the line; it is in the value YAML reads.
    "escaped-aws-key-as-the-drive-id": (
        swap(PLATFORM, "0AbCdEfGhIjKlMnOpQ", '"\\x41' + AWS_KEY[1:] + '"'),
        [("C-SECRET", 7)],
        AWS_KEY[1:],
    ),
    "github-token-as-the-principal": (
        swap(PLATFORM, "gateway@aiven-gateway-test.iam.gserviceaccount.com", GITHUB_TOKEN),
        [("C-SECRET", 6), ("C-SHAPE", 6)],
        GITHUB_TOKEN,
    ),
    "unknown-key": (
        PLATFORM + "agent_project: aiven-agents-test\n",
        [("C-UNKNOWN-KEY", 8)],
        "agent_project",
    ),
    # A value of three characters is too short for the scan's assignment pattern.
    "secret-name": (PLATFORM + "api_key: n/a\n", [("C-SECRET-NAME", 8)], "api_key"),
    "secret-name-and-value": (
        PLATFORM + "api_key: Zq7fK2pW\n",
        [("C-SECRET-NAME", 8), ("C-SECRET", 8)],
        "Zq7fK2pW",
    ),
    "secret-name-quoted-with-a-space": (
        PLATFORM + '"db password": n/a\n',
        [("C-SECRET-NAME", None)],
        "db password",
    ),
    "project-with-capitals": (
        swap(PLATFORM, "aiven-agents-test", "Aiven-Agents-Test"),
        [("C-SHAPE", 2)],
        "Aiven-Agents-Test",
    ),
    "project-not-a-string": (
        swap(PLATFORM, "aiven-agents-test", "87654321"),
        [("C-SHAPE", 2)],
        "87654321",
    ),
    "project-empty": (swap(PLATFORM, " aiven-agents-test", ""), [("C-SHAPE", 2)], None),
    "author-with-capitals": (
        swap(PLATFORM, "  - author@", "  - Author@"),
        [("C-SHAPE", 3)],
        "Author@aivenstudios.com",
    ),
    "author-without-a-local-part": (
        swap(PLATFORM, "  - author@aivenstudios.com", "  - '@aivenstudios.com'"),
        [("C-SHAPE", 3)],
        "'@aivenstudios.com'",
    ),
    "author-not-a-string": (
        swap(PLATFORM, "  - author@aivenstudios.com", "  - 2718281"),
        [("C-SHAPE", 3)],
        "2718281",
    ),
    "authors-a-string": (
        swap(PLATFORM, AUTHORS, "trusted_authors: author@aivenstudios.com\n"),
        [("C-SHAPE", 3)],
        "author@aivenstudios.com",
    ),
    "authors-empty": (swap(PLATFORM, AUTHORS, "trusted_authors: []\n"), [("C-SHAPE", 3)], None),
    "principal-not-a-service-account": (
        swap(PLATFORM, "gateway@aiven-gateway-test.iam.gserviceaccount.com", "gw@example.com"),
        [("C-SHAPE", 6)],
        "gw@example.com",
    ),
    "drive-id-with-spaces": (
        swap(PLATFORM, "0AbCdEfGhIjKlMnOpQ", "'0AbCd EfGhI jKlMn'"),
        [("C-SHAPE", 7)],
        "0AbCd EfGhI jKlMn",
    ),
    "missing-key": (
        swap(PLATFORM, "agents_project: aiven-agents-test\n", ""),
        [("C-MISSING", None)],
        None,
    ),
    "duplicate-key": (
        PLATFORM + "agents_project: aiven-other-test\n",
        [("C-SYNTAX", 8)],
        "aiven-other-test",
    ),
    "not-yaml": (
        swap(PLATFORM, "0AbCdEfGhIjKlMnOpQ", "0AbCd: EfGhIjKlMnOpQ"),
        [("C-SYNTAX", 7)],
        "EfGhIjKlMnOpQ",
    ),
    "a-python-tag": (
        swap(PLATFORM, "aiven-agents-test", "!!python/object:os.system aiven-agents-test"),
        [("C-SYNTAX", 2)],
        "os.system",
    ),
    "not-a-mapping": ("- aiven-agents-test\n", [("C-SYNTAX", None)], "aiven-agents-test"),
    "empty": ("", [("C-SYNTAX", None)], None),
    "only-comments": ("# nothing yet\n", [("C-SYNTAX", None)], None),
    "not-ascii": (
        PLATFORM + "# caf\N{LATIN SMALL LETTER E WITH ACUTE}\n",
        [("C-ENCODING", 8)],
        None,
    ),
    # A control character can hide text from someone who reads the file in a terminal, and YAML
    # reads a lone carriage return as a line end, which the scan and the line numbers do not.
    "control-character": (PLATFORM + "# \x1b[2K\n", [("C-ENCODING", 8)], None),
    "delete-character": (PLATFORM + "# \x7f\n", [("C-ENCODING", 8)], None),
    "lone-carriage-returns": (PLATFORM.replace("\n", "\r"), [("C-ENCODING", 1)], None),
    "not-ascii-and-a-key": (
        PLATFORM + f"# caf\N{LATIN SMALL LETTER E WITH ACUTE} {AWS_KEY}\n",
        [("C-ENCODING", 8), ("C-SECRET", 8)],
        AWS_KEY,
    ),
}


@pytest.mark.parametrize(
    ("text", "expected", "value"), PLATFORM_REFUSED.values(), ids=PLATFORM_REFUSED.keys()
)
def test_platform_values_are_refused_without_repeating_the_value(
    tmp_path, capsys, text, expected, value
):
    status, found, out = run(capsys, platform(tmp_path, text))
    assert status == 1
    assert same(found, expected), found
    if value is not None:
        assert value not in out


def test_every_key_of_the_platform_values_is_named_in_the_refusal_of_an_unknown_one(
    tmp_path, capsys
):
    _, _, out = run(capsys, platform(tmp_path, PLATFORM + "agent_project: x\n"))
    for key in ("agents_project", "trusted_authors", "gateway_principal", "sandbox_drive_id"):
        assert key in out


# --- Terraform values (infra/terraform/terraform.tfvars)

TFVARS_NAMES = (
    "org_id",
    "billing_account",
    "agents_project",
    "gateway_project",
    "control_project",
    "scratch_project",
    "region",
    "agents",
    "alert_email",
    "budget_currency",
    "budget_alert_amount",
    "budget_stop_amount",
    "credit_alert_date",
    "credit_expiry_date",
    "stop_enabled",
    "service_label",
)

TFVARS = """\
# The Terraform values of the deployment: IDs and addresses, no credentials.
org_id          = "123456789012"
billing_account = "01ABCD-23EF45-6789AB"
agents_project  = "aiven-agents-test"
gateway_project = "aiven-gateway-test"
control_project = "aiven-control-test"
scratch_project = "aiven-scratch-test"
region          = "europe-west4"
agents = [
  "invoice-reminder", // the first test agent
  "payment-nudge",
]
alert_email         = "alerts@aivenstudios.com"
budget_currency     = "EUR"
budget_alert_amount = 10
budget_stop_amount  = 25.50
credit_alert_date   = "2026-12-20"
credit_expiry_date  = "2027-01-04" # the day the credit ends

stop_enabled  = true
service_label = "aiven"
"""


def variables_tf(names: tuple[str, ...]) -> str:
    return "".join(f'variable "{name}" {{\n  type = any\n}}\n\n' for name in names)


def tfvars(
    tmp_path: Path,
    text: str,
    *,
    name: str = "terraform.tfvars",
    declared: tuple[str, ...] | None = TFVARS_NAMES,
) -> Path:
    if declared is not None:
        (tmp_path / "variables.tf").write_text(variables_tf(declared), encoding="utf-8")
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return path


@pytest.mark.parametrize(
    "text",
    [
        TFVARS,
        TFVARS.replace("\n", "\r\n"),
        swap(
            TFVARS,
            'agents = [\n  "invoice-reminder", // the first test agent\n  "payment-nudge",\n]',
            "agents = []",
        ),
        swap(
            TFVARS,
            'agents = [\n  "invoice-reminder", // the first test agent\n  "payment-nudge",\n]',
            'agents = ["invoice-reminder", "payment-nudge"]',
        ),
        swap(TFVARS, "stop_enabled  = true", "stop_enabled  = false"),
        swap(TFVARS, '"EUR"', '"USD"'),
        TFVARS.rstrip("\n"),
        "",
    ],
    ids=[
        "all",
        "windows-line-ends",
        "no-agents",
        "list-on-one-line",
        "false",
        "usd",
        "no-newline-at-the-end",
        "empty",
    ],
)
def test_realistic_terraform_values_pass(tmp_path, capsys, text):
    assert run(capsys, tfvars(tmp_path, text)) == (0, [], "")


def test_the_example_of_the_terraform_values_is_checked_the_same_way(tmp_path, capsys):
    good = tfvars(tmp_path, TFVARS, name="terraform.tfvars.example")
    assert run(capsys, good) == (0, [], "")
    bad = tfvars(tmp_path, TFVARS + f"# {AWS_KEY}\n", name="terraform.tfvars.example")
    assert run(capsys, bad)[:2] == (1, [("C-SECRET", 22)])


AGENTS_LIST = 'agents = [\n  "invoice-reminder", // the first test agent\n  "payment-nudge",\n]'

TFVARS_REFUSED = {
    "interpolation": (
        swap(TFVARS, '"aiven"', '"${var.region}"'),
        [("C-SYNTAX", 21)],
        "${var.region}",
    ),
    "template-directive": (
        swap(TFVARS, '"aiven"', '"%{ if true }x%{ endif }"'),
        [("C-SYNTAX", 21)],
        "endif",
    ),
    "heredoc": (
        swap(TFVARS, 'service_label = "aiven"\n', "service_label = <<EOT\naiven-xyz\nEOT\n"),
        [("C-SYNTAX", 21)],
        "aiven-xyz",
    ),
    "map": (swap(TFVARS, '"aiven"', '{ name = "aiven-xyz" }'), [("C-SYNTAX", 21)], "aiven-xyz"),
    "function-call": (swap(TFVARS, '"aiven"', 'lower("AIVEN-XYZ")'), [("C-SYNTAX", 21)], "XYZ"),
    "reference": (swap(TFVARS, '"aiven"', "var.region"), [("C-SYNTAX", 21)], "var.region"),
    "block-comment": (TFVARS + "/* a note */\n", [("C-SYNTAX", 22)], "a note"),
    "backslash": (swap(TFVARS, '"aiven"', '"ai\\\\ven"'), [("C-SYNTAX", 21)], "ai\\\\ven"),
    "single-quotes": (swap(TFVARS, '"aiven"', "'aiven'"), [("C-SYNTAX", 21)], None),
    "duplicate": (TFVARS + 'region = "europe-west4"\n', [("C-SYNTAX", 22)], None),
    "two-on-a-line": (
        swap(TFVARS, "stop_enabled  = true", 'stop_enabled  = true region = "x"'),
        [("C-SYNTAX", 20)],
        None,
    ),
    "negative-number": (swap(TFVARS, "= 10\n", "= -10\n"), [("C-SYNTAX", 15)], None),
    "number-glued-to-a-word": (swap(TFVARS, "= 10\n", "= 10eur\n"), [("C-SYNTAX", 15)], "10eur"),
    "list-of-numbers": (swap(TFVARS, '"payment-nudge",', "7,"), [("C-SYNTAX", 11)], None),
    "unclosed-list": (swap(TFVARS, "]\n", ""), [("C-SYNTAX", 12)], None),
    "unclosed-list-at-the-end": (TFVARS + 'region = [\n  "x",\n', [("C-SYNTAX", 23)], None),
    "unclosed-list-without-a-newline": (TFVARS + 'region = ["x",', [("C-SYNTAX", 22)], None),
    "no-value": (
        swap(TFVARS, 'service_label = "aiven"', "service_label ="),
        [("C-SYNTAX", 21)],
        None,
    ),
    "no-equals": (
        swap(TFVARS, 'service_label = "aiven"', 'service_label "aiven"'),
        [("C-SYNTAX", 21)],
        None,
    ),
    "a-value-alone": (TFVARS + '"aiven-xyz"\n', [("C-SYNTAX", 22)], "aiven-xyz"),
    "unknown-name": (TFVARS + 'extra_setting = "x"\n', [("C-UNKNOWN-KEY", 22)], "extra_setting"),
    "secret-name": (TFVARS + 'api_token = "abc"\n', [("C-SECRET-NAME", 22)], "api_token"),
    "aws-key-in-a-comment": (TFVARS + f"# {AWS_KEY}\n", [("C-SECRET", 22)], AWS_KEY),
    "aws-key-as-a-value": (swap(TFVARS, '"aiven"', f'"{AWS_KEY}"'), [("C-SECRET", 21)], AWS_KEY),
    "private-key-in-a-comment": (TFVARS + f"// {PEM_HEADER}\n", [("C-SECRET", 22)], PEM_HEADER),
    "service-account-key-line": (
        TFVARS + SERVICE_ACCOUNT_KEY_LINE,
        [("C-SECRET", 22)],
        '"private' + '_key"',
    ),
    "card-number-as-the-label": (swap(TFVARS, '"aiven"', f'"{CARD}"'), [("C-SECRET", 21)], CARD),
    "org-id-with-letters": (
        swap(TFVARS, '"123456789012"', '"12345abc"'),
        [("C-SHAPE", 2)],
        "12345abc",
    ),
    "org-id-a-number": (swap(TFVARS, '"123456789012"', "123456789012"), [("C-SHAPE", 2)], None),
    "billing-account-in-lower-case": (
        swap(TFVARS, "01ABCD-23EF45-6789AB", "01abcd-23ef45-6789ab"),
        [("C-SHAPE", 3)],
        "01abcd-23ef45-6789ab",
    ),
    "project-with-capitals": (
        swap(TFVARS, '"aiven-control-test"', '"Aiven-Control-Test"'),
        [("C-SHAPE", 6)],
        "Aiven-Control-Test",
    ),
    "region-elsewhere": (
        swap(TFVARS, '"europe-west4"', '"europe-west1"'),
        [("C-SHAPE", 8)],
        "europe-west1",
    ),
    "agent-id-with-capitals": (
        swap(TFVARS, '"payment-nudge"', '"Payment_Nudge"'),
        [("C-SHAPE", 9)],
        "Payment_Nudge",
    ),
    "agent-id-reserved": (swap(TFVARS, '"payment-nudge"', '"admin"'), [("C-SHAPE", 9)], None),
    "agent-id-twice": (
        swap(TFVARS, '"payment-nudge"', '"invoice-reminder"'),
        [("C-SHAPE", 9)],
        None,
    ),
    "agents-a-string": (
        swap(TFVARS, AGENTS_LIST, 'agents = "invoice-reminder"'),
        [("C-SHAPE", 9)],
        None,
    ),
    "alert-email-with-capitals": (
        swap(TFVARS, "alerts@", "Alerts@"),
        [("C-SHAPE", 13)],
        "Alerts@aivenstudios.com",
    ),
    "currency-gbp": (swap(TFVARS, '"EUR"', '"GBP"'), [("C-SHAPE", 14)], "GBP"),
    "amount-quoted": (swap(TFVARS, "= 10\n", '= "10"\n'), [("C-SHAPE", 15)], None),
    "amount-zero": (swap(TFVARS, "= 10\n", "= 0\n"), [("C-SHAPE", 15)], None),
    "amount-a-bool": (swap(TFVARS, "= 25.50\n", "= true\n"), [("C-SHAPE", 16)], None),
    "date-month-13": (swap(TFVARS, "2026-12-20", "2026-13-20"), [("C-SHAPE", 17)], "2026-13-20"),
    "date-without-dashes": (swap(TFVARS, "2026-12-20", "20261220"), [("C-SHAPE", 17)], "20261220"),
    "plain-with-a-space": (swap(TFVARS, '"aiven"', '"two words"'), [("C-SHAPE", 21)], "two words"),
    "plain-empty": (swap(TFVARS, '"aiven"', '""'), [("C-SHAPE", 21)], None),
    "plain-a-list": (swap(TFVARS, '"aiven"', '["aiven-xyz"]'), [("C-SHAPE", 21)], "aiven-xyz"),
    "not-ascii": (
        TFVARS + "# caf\N{LATIN SMALL LETTER E WITH ACUTE}\n",
        [("C-ENCODING", 22)],
        None,
    ),
    "nul": (swap(TFVARS, '"europe-west4"', '"europe\x00west4"'), [("C-ENCODING", 8)], None),
    "lone-carriage-return": (swap(TFVARS, "\nregion", "\rregion"), [("C-ENCODING", 7)], None),
}


@pytest.mark.parametrize(
    ("text", "expected", "value"), TFVARS_REFUSED.values(), ids=TFVARS_REFUSED.keys()
)
def test_terraform_values_are_refused_without_repeating_the_value(
    tmp_path, capsys, text, expected, value
):
    status, found, out = run(capsys, tfvars(tmp_path, text))
    assert status == 1
    assert same(found, expected), found
    if value is not None:
        assert value not in out


def test_a_declared_name_that_suggests_a_secret_is_refused_all_the_same(tmp_path, capsys):
    text = TFVARS + 'db_password = "Zq7fK2pW"\n'
    status, found, out = run(
        capsys, tfvars(tmp_path, text, declared=(*TFVARS_NAMES, "db_password"))
    )
    assert status == 1
    assert same(found, [("C-SECRET-NAME", 22), ("C-SECRET", 22)])
    assert "Zq7fK2pW" not in out and "db_password" not in out


def test_a_declared_name_is_named_in_its_refusal(tmp_path, capsys):
    _, _, out = run(capsys, tfvars(tmp_path, swap(TFVARS, '"EUR"', '"GBP"')))
    assert "budget_currency" in out


def test_terraform_values_without_variables_tf_are_refused_as_a_whole(tmp_path, capsys):
    assert run(capsys, tfvars(tmp_path, TFVARS, declared=None))[:2] == (
        1,
        [("C-NO-VARIABLES", None)],
    )


def test_without_variables_tf_a_secret_is_still_found(tmp_path, capsys):
    text = TFVARS + f"# {AWS_KEY}\n" + 'api_token = "abc"\n'
    status, found, _ = run(capsys, tfvars(tmp_path, text, declared=None))
    assert status == 1
    assert same(found, [("C-NO-VARIABLES", None), ("C-SECRET", 22), ("C-SECRET-NAME", 23)])


def test_only_a_declaration_at_the_start_of_a_line_counts(tmp_path, capsys):
    # terraform fmt starts every top-level block at the start of a line; a comment does not.
    path = tfvars(tmp_path, 'extra_setting = "x"\nother_setting = "y"\n', declared=())
    (tmp_path / "variables.tf").write_text(
        '# variable "extra_setting" {\n#}\n  variable "other_setting" {\n  }\n', encoding="utf-8"
    )
    assert run(capsys, path)[:2] == (1, [("C-UNKNOWN-KEY", 1), ("C-UNKNOWN-KEY", 2)])


def test_the_assignments_before_a_syntax_error_are_still_checked(tmp_path, capsys):
    text = 'region = "europe-west1"\nservice_label = <<EOT\nx\nEOT\n'
    assert run(capsys, tfvars(tmp_path, text))[:2] == (1, [("C-SHAPE", 1), ("C-SYNTAX", 2)])


# --- every file


@pytest.mark.parametrize("name", ["platform.yaml", "terraform.tfvars"])
def test_a_file_larger_than_64_kib_is_not_read(tmp_path, capsys, name):
    path = tmp_path / name
    path.write_bytes(f"# {AWS_KEY}\n".encode() + b"#" * MAX_FILE_BYTES + b"\n")
    assert run(capsys, path)[:2] == (1, [("C-SIZE", None)])


def test_a_file_of_exactly_64_kib_is_read(tmp_path, capsys):
    path = tmp_path / "platform.yaml"
    path.write_bytes(PLATFORM.encode() + b"#" * (MAX_FILE_BYTES - len(PLATFORM) - 1) + b"\n")
    assert path.stat().st_size == MAX_FILE_BYTES
    assert run(capsys, path) == (0, [], "")


def test_a_file_that_cannot_be_read_is_refused(tmp_path, capsys):
    status, found, out = run(capsys, tmp_path / "platform.yaml")
    assert (status, found) == (1, [("C-READ", None)])
    assert "FileNotFoundError" in out
    (tmp_path / "terraform.tfvars").mkdir()
    assert run(capsys, tmp_path / "terraform.tfvars")[:2] == (1, [("C-READ", None)])


@pytest.mark.parametrize("name", ["platform.json", "terraform.tfvars.json", "notes.txt", "yaml"])
def test_a_file_of_another_kind_is_refused(tmp_path, capsys, name):
    path = tmp_path / name
    path.write_text("{}\n", encoding="utf-8")
    assert run(capsys, path)[:2] == (1, [("C-FILE-KIND", None)])


def test_problems_of_one_file_come_in_the_order_of_their_lines(tmp_path, capsys):
    text = swap(PLATFORM, "agents_project: aiven-agents-test\n", "") + f"# {AWS_KEY}\n"
    text = swap(text, "0AbCdEfGhIjKlMnOpQ", "'0AbCd EfGhI'")
    _, found, _ = run(capsys, platform(tmp_path, text))
    assert found == [("C-MISSING", None), ("C-SHAPE", 6), ("C-SECRET", 7)]


def test_each_file_is_checked_once_and_files_in_the_order_given(tmp_path, capsys):
    first = platform(tmp_path, PLATFORM + "extra: 1\n")
    second = tfvars(tmp_path, TFVARS + "extra = 1\n")
    status, found, out = run(capsys, second, first, second)
    assert (status, found) == (1, [("C-UNKNOWN-KEY", 22), ("C-UNKNOWN-KEY", 8)])
    assert out.index("terraform.tfvars") < out.index("platform.yaml")


def test_paths_are_escaped_and_the_output_is_ascii(tmp_path, capsys):
    path = platform(
        tmp_path,
        PLATFORM + "extra: 1\n",
        "pl\N{LATIN SMALL LETTER A WITH DIAERESIS}\x1b[2Jtform.yaml",
    )
    status, found, out = run(capsys, path)
    assert (status, found) == (1, [("C-UNKNOWN-KEY", 8)])
    assert out.isascii() and "\x1b" not in out
    assert len(out.splitlines()) == 1


def test_a_crash_says_the_name_of_the_class_only(tmp_path, capsys, monkeypatch):
    def crash(path):
        raise RuntimeError(f"a message with {AWS_KEY} in it")

    monkeypatch.setattr(config_guard, "check_file", crash)
    path = platform(tmp_path, PLATFORM)
    status, found, out = run(capsys, path)
    assert (status, found) == (2, [("C-INTERNAL", None)])
    assert "RuntimeError" in out and AWS_KEY not in out


# --- which files


def test_the_default_files_are_the_platform_values_the_terraform_values_and_their_examples():
    assert DEFAULT_FILES == (
        "config/platform.yaml",
        "config/platform.example.yaml",
        "infra/terraform/terraform.tfvars",
        "infra/terraform/terraform.tfvars.example",
    )


def test_with_no_arguments_it_checks_each_default_file_that_exists(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "infra" / "terraform").mkdir(parents=True)
    platform(tmp_path / "config", PLATFORM)
    platform(tmp_path / "config", PLATFORM + f"# {AWS_KEY}\n", "platform.example.yaml")
    tfvars(
        tmp_path / "infra" / "terraform", TFVARS + "extra = 1\n", name="terraform.tfvars.example"
    )
    assert main([]) == 1
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("error C-SECRET config/platform.example.yaml:8: ")
    assert lines[1].startswith("error C-UNKNOWN-KEY infra/terraform/terraform.tfvars.example:22: ")
    assert captured.err == (
        "checked: config/platform.yaml, config/platform.example.yaml, "
        "infra/terraform/terraform.tfvars.example\n"
    )


def test_with_no_arguments_and_none_of_the_files_there_is_nothing_to_check(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    assert main([]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("nothing to check: none of config/platform.yaml, ")


def test_a_default_file_that_is_not_a_file_is_refused(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config" / "platform.yaml").mkdir(parents=True)
    assert run(capsys)[:2] == (1, [("C-READ", None)])


def test_the_repository_passes_as_it_is(capsys, monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    assert main([]) == 0
    assert capsys.readouterr().out == ""


# --- names that suggest a secret (ruling R114)

SECRET_NAMES = [
    "password",
    "db_password",
    "DB_PASSWORD",
    "passwd",
    "passphrase",
    "pass",
    "pwd",
    "secret",
    "client_secret",
    "clientSecret",
    "client-secret",
    "token",
    "api_token",
    "githubToken",
    "apiKey",
    "api_key",
    "APIKey",
    "apikey",
    "access_key",
    "accesskey",
    "sa_key",
    "json_key",
    "ssh_keys",
    "key",
    "private",
    "private" + "_key",  # split: written whole in quotes, it is what the scan flags
    "privatekey",
    "auth",
    "oauth_client",
    "auth.token",
    "credentials",
    "gcp_credential",
    "creds",
    "tls_cert",
    "certificate",
    "pem",
    "p12",
    "pin",
    "otp",
    "jwt",
    "bearer",
    "db password",
]

PLAIN_NAMES = [
    "trusted_authors",
    "trustedAuthors",
    "author",
    "authors",
    "authority",
    "agents_project",
    "gateway_principal",
    "sandbox_drive_id",
    *TFVARS_NAMES,
    "keyword",
    "passenger",
    "pinned_version",
]


@pytest.mark.parametrize("name", SECRET_NAMES)
def test_a_name_that_suggests_a_secret(name):
    assert secret_like(name)


@pytest.mark.parametrize("name", PLAIN_NAMES)
def test_a_name_that_does_not(name):
    assert not secret_like(name)


# --- the values, for a tool that compares against them (the deploy check)


def test_read_tfvars_gives_the_values_of_a_file_the_guard_passes(tmp_path):
    from decimal import Decimal

    from aiven.common.config_guard import read_tfvars

    values = read_tfvars(tfvars(tmp_path, TFVARS))
    assert values["agents_project"] == "aiven-agents-test"
    assert values["agents"] == ("invoice-reminder", "payment-nudge")
    assert values["budget_stop_amount"] == Decimal("25.50")
    assert values["stop_enabled"] is True


def test_read_tfvars_refuses_a_file_the_guard_refuses_without_its_values(tmp_path):
    from aiven.common.config_guard import read_tfvars

    path = tfvars(tmp_path, swap(TFVARS, '"aiven"', f'"{AWS_KEY}"'))
    with pytest.raises(ValueError, match="C-SECRET line 21") as caught:
        read_tfvars(path)
    assert AWS_KEY not in str(caught.value)
