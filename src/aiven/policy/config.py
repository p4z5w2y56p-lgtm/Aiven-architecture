"""Platform values that are set at deploy (validator-spec section 6).

These are the deploy-specific values: they differ per installation, so they live in a YAML file
(`config/platform.example.yaml` shows the shape) and never in `constants.py`.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

# Every pattern is used with fullmatch: `$` would accept a trailing newline, and a YAML block
# scalar can end in one.
# Google Cloud project IDs: 6 to 30 lowercase letters, digits and hyphens; start with a letter,
# do not end with a hyphen.
_PROJECT_ID = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
_PROJECT_ID_RE = re.compile(_PROJECT_ID)
_SERVICE_ACCOUNT_RE = re.compile(rf"{_PROJECT_ID}@{_PROJECT_ID}\.iam\.gserviceaccount\.com")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+")
# Drive and folder IDs share one alphabet (validator-spec 3.3, scope.drive_folder_id).
_DRIVE_ID_RE = re.compile(r"[A-Za-z0-9_-]{10,100}")

_REQUIRED = ("agents_project", "trusted_authors", "gateway_principal")
_OPTIONAL = ("sandbox_drive_id",)


class ConfigError(ValueError):
    """The platform configuration is missing a value or holds a wrong one."""


@dataclass(frozen=True)
class PlatformConfig:
    """What differs per deployment.

    `agents_project` is the project in every policy's `principal`. `trusted_authors` are the AIVEN
    accounts whose edits do not taint a run. `gateway_principal` is the gateway's own service
    account. `sandbox_drive_id` is the ID of the Shared Drive, unknown until the drive exists.
    """

    agents_project: str
    trusted_authors: tuple[str, ...]
    gateway_principal: str
    sandbox_drive_id: str | None = None


def load_platform_config(path: Path) -> PlatformConfig:
    """Read and check a platform configuration file. Raises ConfigError if anything is off."""
    path = Path(path)
    where = path.name
    try:
        doc = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, YAMLError) as error:
        raise ConfigError(f"{where}: not valid UTF-8 YAML: {error}") from error
    if not isinstance(doc, dict):
        raise ConfigError(f"{where}: must be a mapping of settings")
    for key in doc:
        if key not in (*_REQUIRED, *_OPTIONAL):
            raise ConfigError(f"{where}: unknown key {key!r}")
    for key in _REQUIRED:
        if key not in doc:
            raise ConfigError(f"{where}: missing key {key!r}")

    project = _string(doc["agents_project"], "agents_project", where)
    if not _PROJECT_ID_RE.fullmatch(project):
        raise ConfigError(
            f"{where}: agents_project {project!r} is not a valid project id "
            "(6 to 30 lowercase letters, digits and hyphens, starting with a letter)"
        )

    authors = doc["trusted_authors"]
    if not isinstance(authors, list):
        raise ConfigError(f"{where}: trusted_authors must be a list of email addresses")
    if not authors:
        raise ConfigError(f"{where}: trusted_authors must not be empty")
    for number, author in enumerate(authors):
        author = _string(author, f"trusted_authors[{number}]", where)
        if not _EMAIL_RE.fullmatch(author):
            raise ConfigError(
                f"{where}: trusted_authors[{number}] {author!r} is not an email address"
            )

    gateway = _string(doc["gateway_principal"], "gateway_principal", where)
    if not _SERVICE_ACCOUNT_RE.fullmatch(gateway):
        raise ConfigError(
            f"{where}: gateway_principal {gateway!r} is not a service account "
            "(name@project.iam.gserviceaccount.com)"
        )

    drive_id = doc.get("sandbox_drive_id")
    if drive_id is not None:
        drive_id = _string(drive_id, "sandbox_drive_id", where)
        if not _DRIVE_ID_RE.fullmatch(drive_id):
            raise ConfigError(f"{where}: sandbox_drive_id {drive_id!r} is not a valid drive id")

    return PlatformConfig(
        agents_project=project,
        trusted_authors=tuple(authors),
        gateway_principal=gateway,
        sandbox_drive_id=drive_id,
    )


def _string(value: object, name: str, where: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where}: {name} must be a string, found {value!r}")
    return value
