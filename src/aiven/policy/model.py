"""The typed policy (validator-spec sections 3.3 to 3.5), and `build_policy`, which makes it.

A `Policy` is what the gateway enforces: the front matter of a policy file, with Python types. It
is built from what `frontmatter.load` returns, and `build_policy` runs the field, tool, limit and
scope rules on the same data, so that one pass gives the object and the findings.

When there is a `Policy` (ruling R4): it is None only when a field of the field table is missing
(E-FIELD-MISSING), or is in the file without a usable value. That is a wrong type, from `load`
(E-FIELD-TYPE) or from the rules (`max_class: high`, a folder ID of the wrong shape), or a
placeholder where a number or a list belongs, which `load` reports as E-PLACEHOLDER only. In every
other case there is one, even when the values fail their rules: they stay as written, so a
placeholder in `principal` or in the folder ID is in the `Policy` too, for the renderer. So the
types of a `Policy` say what a valid policy holds, and a `Policy` made from a file with errors can
hold other values (`max_class` "R3", `untrusted_input` "off", a tool that is not in the catalog).

Each list is kept without its repeats (ruling R26): an entry stays the first time it is written.

`Policy.sha256` is the hash of the exact bytes of the file (section 2).

Nothing from the file is in the repr of a `Policy`, a `Limits` or a `Scope`, numbers included:
a number can be a card number or a BSN, and a `Policy` is built even when E-RANGE says the number is
out of range. A `Finding` hides such a value in its params, so the repr must not print it in a log,
a traceback or a failed assertion (ruling R52). Only `sha256` is shown.
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from aiven.policy.catalog import Catalog
from aiven.policy.config import PlatformConfig
from aiven.policy.fields import Fields, check_fields
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import FIELDS, FrontMatter
from aiven.policy.limits_scope import check_limits, check_scope
from aiven.policy.tools import check_forbidden, check_tools

MaxClass = Literal["R0", "R1", "R2"]
UntrustedInput = Literal["strict", "taint"]


@dataclass(frozen=True)
class Limits:
    """The `limits` of a policy (section 3.3). No value is in the repr."""

    emails_per_day: int = field(repr=False)
    records_per_run: int = field(repr=False)
    spend_eur_per_run: int = field(repr=False)
    max_runtime_s: int = field(repr=False)
    runs_per_day: int = field(repr=False)


@dataclass(frozen=True)
class Scope:
    """The `scope` of a policy. A field that the file does not have is None, or empty.

    No value is in the repr.
    """

    drive_folder_id: str | None = field(repr=False)
    drive_folder_path: str | None = field(repr=False)
    email_to: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class Policy:
    """The front matter of a policy file as the gateway enforces it. See the module docstring.

    Only `sha256` is in the repr.
    """

    agent: str = field(repr=False)
    version: int = field(repr=False)
    principal: str = field(repr=False)
    max_class: MaxClass = field(repr=False)
    tools: tuple[str, ...] = field(repr=False)
    forbidden: tuple[str, ...] = field(repr=False)
    untrusted_input: UntrustedInput = field(repr=False)
    limits: Limits = field(repr=False)
    scope: Scope = field(repr=False)
    shadow_min_runs: int = field(repr=False)
    sha256: str


def build_policy(
    fm: FrontMatter,
    data: bytes,
    cfg: PlatformConfig,
    catalog: Catalog,
    path: Path | str = "",
) -> tuple[Policy | None, list[Finding]]:
    """The policy of a loaded front matter, and the findings of the rules on its fields.

    `data` is the whole file, for the hash. `path` only names the file in the findings, as it does
    for `load`. The findings come in no particular order: `validate_file` sorts them. All the rules
    run for the fields that are there, also when there is no policy. Without front matter data
    there is nothing to build from, and nothing to say.
    """
    if fm.data is None:
        return None, []
    fields = Fields(fm, str(path))
    findings, max_class = check_fields(fields, cfg)
    forbidden_findings, forbidden = check_forbidden(fields, catalog)
    tool_findings, tools = check_tools(fields, catalog, max_class, forbidden)
    findings += [
        *forbidden_findings,
        *tool_findings,
        *check_limits(fields, tools),
        *check_scope(fields, tools),
    ]
    # The rules report a wrong type too (E-FIELD-TYPE): then there is no value to build from.
    typed = fields.complete() and all(found.code != "E-FIELD-TYPE" for found in findings)
    return (_assemble(fields, data) if typed else None), findings


def _assemble(fields: Fields, data: bytes) -> Policy:
    """The policy of a front matter that is complete. The names are those of the field table."""
    get = fields.get
    limits = Limits(**{name: get(f"limits.{name}") for name in FIELDS["limits"]})
    scope = Scope(
        drive_folder_id=get("scope.drive_folder_id"),
        drive_folder_path=get("scope.drive_folder_path"),
        email_to=_texts(fields, "scope.email_to"),
    )
    return Policy(
        agent=get("agent"),
        version=get("version"),
        principal=get("principal"),
        max_class=cast(MaxClass, get("max_class")),
        tools=_texts(fields, "tools"),
        forbidden=_texts(fields, "forbidden"),
        untrusted_input=cast(UntrustedInput, get("untrusted_input")),
        limits=limits,
        scope=scope,
        shadow_min_runs=get("shadow.min_runs"),
        sha256="sha256:" + hashlib.sha256(data).hexdigest(),
    )


def _texts(fields: Fields, path: str) -> tuple[str, ...]:
    return tuple(entry.text for entry in fields.entries(path) or ())
