"""The limit and scope rules (validator-spec sections 3.3 and 3.5).

Limits: E-RANGE for the numbers that have a ceiling; E-LIMIT-SPEND for any spend above 0 (the
spend has no range of its own); E-LIMIT-CONFLICT when a limit is 0 and a tool needs at least 1
(`gmail.send` needs `emails_per_day`, an R1+ tool, class R1 or R2, needs `records_per_run`); and
W-LIMIT-UNUSED when a limit is above 0 and no tool uses it. One finding for each limit, and for a
conflict the tool is the first, in the order of the file, that needs the limit.

Scope: `drive_folder_id` must have the shape of a Drive ID (E-FIELD-TYPE) and `drive_folder_path`
must be the Sandbox drive or a folder in it, each name on one line and without a backtick
(E-SCOPE-SANDBOX, ruling R67). Each entry of `email_to` is judged alone: malformed, upper case or
wild is E-SCOPE-EMAIL; a domain of a public mail service is E-SCOPE-EMAIL-PUBLIC; anything else
that is not `aivenstudios.com` itself is E-SCOPE-EMAIL-EXTERNAL (a subdomain is another domain).
The list has 1 to 50 entries (E-RANGE).

A tool needs a scope field (`constants.SCOPE_TOOLS`), and the field is E-SCOPE-MISSING when it is
not in the file. It is reported on the line of `scope`, or on line 1 without a scope, once for each
field, with the first tool that needs it. A field that is in the file but has no value (a
placeholder, or a wrong type) is not missing: `load` has reported it. A field that no tool needs is
W-SCOPE-UNUSED.

Only the tools that passed their own rules count for the errors (ruling R33). The two warnings that
a limit or a scope field is unused are made only when the list of tools is settled (see tools.py:
rulings R49 and R53), because until then the tool that uses it may be the one that fails or the
placeholder. A value that fails E-RANGE gets no warning for its field (ruling R45). When there is no
tool list to judge, the rules that need one are skipped and the others are not.
"""

import re
from collections.abc import Callable

from aiven.policy.catalog import Action, matches
from aiven.policy.constants import (
    CEILINGS,
    DRIVE_FOLDER_ID_PATTERN,
    DRIVE_ROOT,
    EMAIL_LIMIT_TOOLS,
    LIST_SIZES,
    PHASE1_EMAIL_DOMAIN,
    PUBLIC_MAIL_DOMAINS,
    R1_PLUS,
    SCOPE_TOOLS,
)
from aiven.policy.fields import Fields, range_finding, size_finding
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import FIELDS
from aiven.policy.tools import Tools

SPEND = "spend_eur_per_run"

# Every pattern is used with fullmatch: `$` would accept a trailing newline.
_FOLDER_ID = re.compile(DRIVE_FOLDER_ID_PATTERN)
# A folder name has no `/`, no line break, no backtick, and no whitespace at either end. Parts are
# joined by " / ". A line break could only come from a block scalar, and the signer reads a path on
# one line. The path is written in a code span of "Enforced rules (generated)", and a backtick in
# it could close that span and leave the rest as prose in the signed text (ruling R67).
_FOLDER_NAME = r"[^/\s`](?:[^/\r\n`]*[^/\s`])?"
_FOLDER_PATH = re.compile(rf"{re.escape(DRIVE_ROOT)}(?: / {_FOLDER_NAME})*")
# An address is `local@domain` or `@domain`, in lower case.
_LOCAL_PART = re.compile(r"[a-z0-9._%+-]+")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")  # inner hyphens: punycode passes

# The limits that tools use, and which tools.
_USED_BY: dict[str, Callable[[Action], bool]] = {
    "emails_per_day": lambda action: action.id in EMAIL_LIMIT_TOOLS,
    "records_per_run": lambda action: action.cls in R1_PLUS,
}


def check_limits(fields: Fields, tools: Tools | None) -> list[Finding]:
    """The findings about `limits`. `tools` are what `check_tools` made of the tools (or None)."""
    findings: list[Finding] = []
    for limit in FIELDS["limits"]:
        path = f"limits.{limit}"
        if limit == SPEND:
            findings += _spend(fields, path)
        elif (found := range_finding(fields, path)) is not None:
            findings.append(found)  # out of range: no warning on top of it (ruling R45)
        elif limit in _USED_BY and tools is not None:
            findings += _use(fields, limit, tools)
    return findings


def _spend(fields: Fields, path: str) -> list[Finding]:
    spend = fields.checked(path)
    low, high = CEILINGS[path]
    if spend is None or low <= spend <= high:
        return []
    return [fields.report("E-LIMIT-SPEND", path)]


def _use(fields: Fields, limit: str, tools: Tools) -> list[Finding]:
    """E-LIMIT-CONFLICT, or W-LIMIT-UNUSED (a settled list), for one limit that is in range."""
    path = f"limits.{limit}"
    value = fields.checked(path)
    user = next((tool.id for tool in tools.actions if _USED_BY[limit](tool)), None)
    if value is None:
        return []
    if value == 0 and user is not None:
        return [fields.report("E-LIMIT-CONFLICT", path, {"limit": limit, "tool": user})]
    if value > 0 and user is None and tools.settled:
        return [fields.report("W-LIMIT-UNUSED", path, {"limit": limit, "value": str(value)})]
    return []


def check_scope(fields: Fields, tools: Tools | None) -> list[Finding]:
    """The findings about `scope`. `tools` are what `check_tools` made of the tools (or None)."""
    if fields.unreadable("scope"):
        return []  # a placeholder or a wrong type, reported: the fields in it are not known
    findings = [*_folder_id(fields), *_folder_path(fields), *_email_to(fields)]
    if tools is not None:
        findings += _needed(fields, tools)
    return findings


def _folder_id(fields: Fields) -> list[Finding]:
    path = "scope.drive_folder_id"
    value = fields.checked(path)
    if value is None or _FOLDER_ID.fullmatch(value):
        return []
    params = {"field": path, "expected": DRIVE_FOLDER_ID_PATTERN, "found": value}
    return [fields.report("E-FIELD-TYPE", path, params)]


def _folder_path(fields: Fields) -> list[Finding]:
    path = "scope.drive_folder_path"
    value = fields.checked(path)
    if value is None or _FOLDER_PATH.fullmatch(value):
        return []
    return [fields.report("E-SCOPE-SANDBOX", path)]


def _email_to(fields: Fields) -> list[Finding]:
    path = "scope.email_to"
    entries = fields.entries(path)
    if entries is None:
        return []
    findings = [found] if (found := size_finding(fields, path)) is not None else []
    for entry in entries:
        code = None if entry.placeholder else _email_problem(entry.text)
        if code is not None:
            findings.append(fields.report(code, entry.line, {"entry": entry.text}))
    return findings


def _email_problem(entry: str) -> str | None:
    """The code that an `email_to` entry gets, None if it is fine in Phase 1."""
    local, at, domain = entry.partition("@")
    labels = domain.split(".")
    if (
        not at
        or (local and not _LOCAL_PART.fullmatch(local))
        or len(labels) < 2
        or not all(_DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        return "E-SCOPE-EMAIL"
    if not local and domain in PUBLIC_MAIL_DOMAINS:
        return "E-SCOPE-EMAIL-PUBLIC"
    if domain != PHASE1_EMAIL_DOMAIN:
        return "E-SCOPE-EMAIL-EXTERNAL"
    return None


def _needed(fields: Fields, tools: Tools) -> list[Finding]:
    """E-SCOPE-MISSING, and W-SCOPE-UNUSED (a settled list): the scope the tools need or leave."""
    findings = []
    scope_line = fields.line("scope") if fields.written("scope") else 1
    for name, patterns in SCOPE_TOOLS.items():
        path = f"scope.{name}"
        user = next((a.id for a in tools.actions if any(matches(p, a.id) for p in patterns)), None)
        if user is not None:
            if not fields.written(path):
                params = {"field": name, "tool": user}
                findings.append(fields.report("E-SCOPE-MISSING", scope_line, params))
        elif tools.settled and _is_set(fields, path):
            findings.append(fields.report("W-SCOPE-UNUSED", path, {"field": name}))
    return findings


def _is_set(fields: Fields, path: str) -> bool:
    """Whether the field has a value that can be called unused: no placeholder, and in range."""
    if fields.checked(path) is None:
        return False
    return path not in LIST_SIZES or size_finding(fields, path) is None
