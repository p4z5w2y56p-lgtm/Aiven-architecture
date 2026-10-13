"""Platform values that are set at deploy (validator-spec section 6).

These are the deploy-specific values: they differ per installation, so they live in a YAML file
(`config/platform.example.yaml` shows the shape) and never in `constants.py`. The file holds IDs
and addresses only, never a credential, a key or a token (M1 review).

`platform_problems` is the one set of rules for the file. `load_platform_config` raises the first
problem; the config guard (`aiven-check-config`, ruling R113) reports them all, with their lines.
No message repeats a value from the file, and no error carries the YAML error it came from (whose
text quotes the file): a secret pasted into the file in the wrong place must not reach a log by way
of an error. The key and the line are enough to find it.
"""

import re
from collections.abc import Callable
from dataclasses import MISSING, dataclass, fields
from pathlib import Path
from typing import Literal

from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.error import YAMLError

from aiven.policy.addresses import is_address
from aiven.policy.constants import DRIVE_FOLDER_ID_PATTERN

# Every pattern is used with fullmatch: `$` would accept a trailing newline, and a YAML block
# scalar can end in one.
# Google Cloud project IDs: 6 to 30 lowercase letters, digits and hyphens; start with a letter,
# do not end with a hyphen.
PROJECT_ID = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
PROJECT_ID_RE = re.compile(PROJECT_ID)
SERVICE_ACCOUNT_RE = re.compile(rf"{PROJECT_ID}@{PROJECT_ID}\.iam\.gserviceaccount\.com")
# Drive and folder IDs share one alphabet (validator-spec 3.3, scope.drive_folder_id).
DRIVE_ID_RE = re.compile(DRIVE_FOLDER_ID_PATTERN)

PROJECT_ID_TEXT = "6 to 30 lowercase letters, digits and hyphens, starting with a letter"


class ConfigError(ValueError):
    """The platform configuration is missing a value or holds a wrong one.

    The message names a key, never a value. `line` is the line of the file that YAML stopped at,
    when that is known.
    """

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


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


ProblemKind = Literal["not a mapping", "unknown key", "missing key", "wrong value"]


@dataclass(frozen=True)
class Problem:
    """One thing wrong with the platform values.

    `key` is the key of the file it is about, or None when it is about the whole file. `text` says
    what is wrong. It names the keys of `PlatformConfig` and nothing else of the file: not a value,
    and not an unknown key, which may be a value written in the wrong place.
    """

    kind: ProblemKind
    key: object
    text: str


def _string(name: str, pattern: re.Pattern[str], shape: str) -> Callable[[object], list[str]]:
    """The check of a field that is one string of the shape of `pattern`."""

    def check(value: object) -> list[str]:
        if not isinstance(value, str):
            return [f"{name} must be a string"]
        if pattern.fullmatch(value) is None:
            return [f"{name} is not {shape}"]
        return []

    return check


def _authors(value: object) -> list[str]:
    if not isinstance(value, list):
        return ["trusted_authors must be a list of email addresses"]
    if not value:
        return ["trusted_authors must not be empty"]
    problems = []
    for number, author in enumerate(value):
        if not isinstance(author, str):
            problems.append(f"trusted_authors[{number}] must be a string")
        elif not is_address(author):
            problems.append(
                f"trusted_authors[{number}] is not an email address (local@domain, in lower case)"
            )
    return problems


# The check of each field of PlatformConfig, by name.
_CHECKS: dict[str, Callable[[object], list[str]]] = {
    "agents_project": _string(
        "agents_project", PROJECT_ID_RE, f"a valid project id ({PROJECT_ID_TEXT})"
    ),
    "trusted_authors": _authors,
    "gateway_principal": _string(
        "gateway_principal",
        SERVICE_ACCOUNT_RE,
        "a service account (name@project.iam.gserviceaccount.com)",
    ),
    "sandbox_drive_id": _string(
        "sandbox_drive_id",
        DRIVE_ID_RE,
        "a valid drive id (10 to 100 letters, digits, _ and -)",
    ),
}


def platform_problems(doc: object) -> list[Problem]:
    """Every problem of a parsed platform file: unknown keys, missing keys, then each field.

    The keys are the fields of PlatformConfig. A field with a default may be left out or be null;
    any other field is checked whatever its value, null included.
    """
    if not isinstance(doc, dict):
        return [Problem("not a mapping", None, "must be a mapping of settings")]
    names = [field.name for field in fields(PlatformConfig)]
    required = [field.name for field in fields(PlatformConfig) if field.default is MISSING]
    known = ", ".join(names)
    problems = [
        Problem("unknown key", key, f"unknown key; the keys are {known}")
        for key in doc
        if key not in names
    ]
    problems += [
        Problem("missing key", name, f"missing key {name!r}")
        for name in required
        if name not in doc
    ]
    for name in names:
        if name in doc and (doc[name] is not None or name in required):
            problems += [Problem("wrong value", name, text) for text in _CHECKS[name](doc[name])]
    return problems


def parse_platform_values(text: str) -> object:
    """The document in `text`, read with the safe YAML loader (no tags, no Python objects).

    Raises ConfigError with the line YAML stopped at. The error says what kind of problem it is
    and nothing of the text, and it is raised from None: YAML's own error quotes the file.
    """
    try:
        return YAML(typ="safe", pure=True).load(text)
    except DuplicateKeyError as error:
        raise ConfigError("duplicate key", _line(error)) from None
    except YAMLError as error:
        raise ConfigError("not valid YAML", _line(error)) from None


def _line(error: YAMLError) -> int | None:
    mark = getattr(error, "problem_mark", None)
    return None if mark is None else mark.line + 1


def load_platform_config(path: Path) -> PlatformConfig:
    """Read and check a platform configuration file. Raises ConfigError if anything is off."""
    path = Path(path)
    where = path.name
    try:
        doc = parse_platform_values(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"{where}: not valid UTF-8 YAML") from None
    except ConfigError as error:
        at = "" if error.line is None else f" (line {error.line})"
        raise ConfigError(f"{where}: {error}{at}", error.line) from None
    problems = platform_problems(doc)
    if problems:
        raise ConfigError(f"{where}: {problems[0].text}")
    # With no problem, doc is a mapping and every field has its shape.
    return PlatformConfig(
        agents_project=doc["agents_project"],
        trusted_authors=tuple(doc["trusted_authors"]),
        gateway_principal=doc["gateway_principal"],
        sandbox_drive_id=doc.get("sandbox_drive_id"),
    )
