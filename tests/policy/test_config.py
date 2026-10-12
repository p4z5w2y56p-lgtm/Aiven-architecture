"""Platform configuration: deploy-time values (validator-spec section 6, "set at deploy")."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from aiven.policy.config import ConfigError, PlatformConfig, load_platform_config
from tests.support import REPO_ROOT

EXAMPLE_PATH = REPO_ROOT / "config" / "platform.example.yaml"

VALID = """\
agents_project: aiven-agents-test
trusted_authors:
  - author@aivenstudios.com
gateway_principal: gateway@aiven-gateway-test.iam.gserviceaccount.com
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "platform.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_example_config_loads():
    assert load_platform_config(EXAMPLE_PATH) == PlatformConfig(
        agents_project="aiven-agents-example",
        trusted_authors=("trusted-author@aivenstudios.com",),
        gateway_principal="gateway@aiven-gateway-example.iam.gserviceaccount.com",
        sandbox_drive_id=None,
    )


def test_sandbox_drive_id_is_optional_and_read_when_present(tmp_path):
    assert load_platform_config(_write(tmp_path, VALID)).sandbox_drive_id is None
    cfg = load_platform_config(_write(tmp_path, VALID + "sandbox_drive_id: 0AbCdEfGhIjKlMnOpQ\n"))
    assert cfg.sandbox_drive_id == "0AbCdEfGhIjKlMnOpQ"
    cfg = load_platform_config(_write(tmp_path, VALID + "sandbox_drive_id: null\n"))
    assert cfg.sandbox_drive_id is None


def test_trusted_authors_keep_their_order(tmp_path):
    text = VALID.replace(
        "  - author@aivenstudios.com\n", "  - b@aivenstudios.com\n  - a@aivenstudios.com\n"
    )
    assert load_platform_config(_write(tmp_path, text)).trusted_authors == (
        "b@aivenstudios.com",
        "a@aivenstudios.com",
    )


def test_config_is_frozen_and_hashable():
    cfg = PlatformConfig(
        "aiven-agents-test", ("a@aivenstudios.com",), "g@p-test1.iam.gserviceaccount.com"
    )
    assert cfg.sandbox_drive_id is None
    with pytest.raises(FrozenInstanceError):
        cfg.agents_project = "other"
    hash(cfg)


def _replace(old: str, new: str) -> str:
    assert old in VALID, old
    return VALID.replace(old, new)


BROKEN = {
    "unknown-key": (VALID + "extra: 1\n", "unknown key 'extra'"),
    "missing-agents-project": (
        _replace("agents_project: aiven-agents-test\n", ""),
        "missing key 'agents_project'",
    ),
    "missing-gateway-principal": (
        _replace("gateway_principal: gateway@aiven-gateway-test.iam.gserviceaccount.com\n", ""),
        "missing key 'gateway_principal'",
    ),
    "missing-trusted-authors": (
        _replace("trusted_authors:\n  - author@aivenstudios.com\n", ""),
        "missing key 'trusted_authors'",
    ),
    "project-is-not-a-string": (
        _replace("aiven-agents-test", "12345678"),
        "agents_project must be a string",
    ),
    "project-has-uppercase": (
        _replace("aiven-agents-test", "Aiven-Agents"),
        "not a valid project id",
    ),
    "project-is-too-short": (_replace("aiven-agents-test", "abc"), "not a valid project id"),
    "project-ends-with-hyphen": (
        _replace("aiven-agents-test", "aiven-agents-"),
        "not a valid project id",
    ),
    "project-looks-like-an-email": (
        _replace("aiven-agents-test", "x@evil-project"),
        "not a valid project id",
    ),
    "authors-is-a-string": (
        _replace(
            "trusted_authors:\n  - author@aivenstudios.com\n",
            "trusted_authors: author@aivenstudios.com\n",
        ),
        "trusted_authors must be a list",
    ),
    "authors-is-empty": (
        _replace("trusted_authors:\n  - author@aivenstudios.com\n", "trusted_authors: []\n"),
        "trusted_authors must not be empty",
    ),
    "author-is-not-an-address": (
        _replace("author@aivenstudios.com", "not-an-address"),
        "trusted_authors",
    ),
    "author-has-a-space": (
        _replace("author@aivenstudios.com", "'a b@aivenstudios.com'"),
        "trusted_authors",
    ),
    "principal-is-not-a-service-account": (
        _replace("gateway@aiven-gateway-test.iam.gserviceaccount.com", "gateway@example.com"),
        "gateway_principal",
    ),
    "drive-id-is-a-number": (
        VALID + "sandbox_drive_id: 1234567890123\n",
        "sandbox_drive_id must be a string",
    ),
    "drive-id-has-a-space": (VALID + "sandbox_drive_id: 'abc def ghi jkl'\n", "sandbox_drive_id"),
    "project-with-trailing-newline": (
        _replace("agents_project: aiven-agents-test\n", "agents_project: |\n  aiven-agents-test\n"),
        "not a valid project id",
    ),
    "author-with-trailing-newline": (
        _replace("  - author@aivenstudios.com\n", "  - |\n    author@aivenstudios.com\n"),
        "not an email address",
    ),
    "principal-with-trailing-newline": (
        _replace(
            "gateway_principal: gateway@aiven-gateway-test.iam.gserviceaccount.com\n",
            "gateway_principal: |\n  gateway@aiven-gateway-test.iam.gserviceaccount.com\n",
        ),
        "not a service account",
    ),
    "drive-id-with-trailing-newline": (
        VALID + "sandbox_drive_id: |\n  0AbCdEfGhIjKlMnOpQ\n",
        "not a valid drive id",
    ),
    "duplicate-key": (VALID + "agents_project: other-project\n", "duplicate key"),
    "not-a-mapping": ("- a\n", "must be a mapping"),
    "empty-file": ("", "must be a mapping"),
    "invalid-yaml": ("agents_project: [\n", "not valid"),
}


@pytest.mark.parametrize(("text", "problem"), BROKEN.values(), ids=BROKEN.keys())
def test_load_platform_config_rejects(tmp_path, text, problem):
    with pytest.raises(ConfigError, match=problem):
        load_platform_config(_write(tmp_path, text))


def test_load_platform_config_rejects_bytes_that_are_not_utf8(tmp_path):
    path = tmp_path / "platform.yaml"
    path.write_bytes(VALID.encode() + b"# \xff\n")
    with pytest.raises(ConfigError, match="UTF-8"):
        load_platform_config(path)


def test_config_errors_name_the_file(tmp_path):
    with pytest.raises(ConfigError, match=r"^platform\.yaml: "):
        load_platform_config(_write(tmp_path, VALID + "extra: 1\n"))
