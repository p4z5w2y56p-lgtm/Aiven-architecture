"""The field rules (validator-spec section 3.3), and what all the rules read the front matter with.

`Fields` is the front matter as the rules see it, made from what `frontmatter.load` returns:
- `checked(path)` is the value of a field that the rules should look at. A field that holds a
  placeholder skips its other checks (section 3.1, ruling R7), and a field that has no value has
  been reported already (E-FIELD-MISSING, E-FIELD-TYPE, or E-PLACEHOLDER where a number belongs).
  In both cases it is None.
- `entries(path)` are the entries of a list, each once: the first time it is written. `load`
  reports a later repeat (E-LIST-DUPLICATE), and after that the entry is not there for any rule
  (ruling R26). A placeholder is not a repeat of another one, as in `load`.
- `report` makes a finding on the line of a field, or of a list entry.

`check_fields` has the rules of the fields that stand alone: `schema`, `agent`, `version`,
`principal`, `max_class`, `untrusted_input` and `shadow.min_runs`. The rules of the tools, the
limits and the scope are in tools.py and limits_scope.py, and use `range_finding` and
`size_finding` from here for E-RANGE.

One defect gets one code. An agent that fails E-AGENT-ID is not compared with the principal
(E-PRINCIPAL), nor, in `validate_file`, with the file name (E-FILENAME): ruling R28. A value that
fails E-RANGE gets none of the warnings of its field (ruling R45).

Findings carry text from the file in their params, and `Finding` cleans them. Nothing here puts
text of the file in an exception, a log or a repr: `Entry` has no repr.
"""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from aiven.policy.config import PlatformConfig
from aiven.policy.constants import (
    AGENT_ID_LENGTH,
    AGENT_ID_PATTERN,
    CEILINGS,
    LIST_SIZES,
    POLICY_CLASSES,
    RESERVED_AGENT_IDS,
    SCHEMA,
    SHADOW_DEFAULT,
    UNTRUSTED_INPUT_DEFAULT,
    UNTRUSTED_INPUT_MODES,
)
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import FIELDS, OPTIONAL, FrontMatter

_AGENT_ID = re.compile(AGENT_ID_PATTERN)


@dataclass(frozen=True, slots=True, repr=False)
class Entry:
    """One entry of a list field: its text, its file line, and whether it is a placeholder.

    It has no repr, because it holds text of the file.
    """

    text: str
    line: int
    placeholder: bool


class Fields:
    """The front matter as the rules read it. See the module docstring."""

    def __init__(self, front: FrontMatter, where: str = "") -> None:
        """`where` names the file in the findings, as the `path` of `load` does."""
        self.where = where
        self._data: dict[str, Any] = front.data if front.data is not None else {}
        self._lines = front.lines
        self._placeholders = front.placeholders
        self._entries: dict[str, list[Entry] | None] = {}

    def get(self, path: str) -> Any:
        """The value at a dotted path (`limits.runs_per_day`), or None if the data has none."""
        value: Any = self._data
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return value

    def checked(self, path: str) -> Any:
        """The value at `path` if its rules should look at it, else None (see the module)."""
        return None if path in self._placeholders else self.get(path)

    def written(self, path: str) -> bool:
        """Whether the field is in the file, even if it has no value in the data."""
        return path in self._lines

    def line(self, path: str) -> int:
        """The file line of a field that is in the file (the line of its key)."""
        return self._lines[path]

    def unreadable(self, path: str) -> bool:
        """Whether the field is in the file but has no value: it has been reported."""
        return self.written(path) and self.get(path) is None

    def entries(self, path: str) -> list[Entry] | None:
        """The entries of the list at `path`, each once. None if the list has no value."""
        if path not in self._entries:
            self._entries[path] = self._distinct(path)
        return self._entries[path]

    def _distinct(self, path: str) -> list[Entry] | None:
        items = self.get(path)
        if items is None:
            return None
        seen: set[str] = set()
        found = []
        for number, text in enumerate(items):
            entry_path = f"{path}.{number}"
            placeholder = entry_path in self._placeholders
            if text in seen and not placeholder:
                continue  # a repeat: `load` has reported it, and it is not there for any rule
            seen.add(text)
            found.append(Entry(text, self._lines[entry_path], placeholder))
        return found

    def complete(self) -> bool:
        """Whether the data holds every field that the file has, and every field that is needed.

        Then the front matter can be read as a `Policy`. A field that is in the file and not in the
        data has the wrong type, or is a placeholder where a number belongs (ruling R4).
        """
        return all(
            self.get(path) is not None
            for path, required in _paths(FIELDS)
            if required or self.written(path)
        )

    def report(
        self, code: str, where: str | int, params: Mapping[str, str] | None = None
    ) -> Finding:
        """A finding on the line of the field at path `where`, or on line `where`."""
        line = where if isinstance(where, int) else self.line(where)
        severity = "error" if code.startswith("E-") else "warning"
        return Finding(code, severity, self.where, line, params=dict(params or {}))


def _paths(
    table: dict[str, Any], prefix: str = "", required: bool = True
) -> Iterator[tuple[str, bool]]:
    """Every path of the field table, and whether the file must have it (as `load` decides)."""
    for name, kind in table.items():
        path = prefix + name
        needed = required and path not in OPTIONAL
        yield path, needed
        if isinstance(kind, dict):
            yield from _paths(kind, path + ".", needed)


def range_finding(fields: Fields, path: str) -> Finding | None:
    """E-RANGE if the number at `path` is outside the ceilings of that field."""
    value = fields.checked(path)
    if value is None:
        return None
    low, high = CEILINGS[path]
    if low <= value <= high:
        return None
    params = {"field": path, "value": str(value), "min": str(low), "max": str(high)}
    return fields.report("E-RANGE", path, params)


def size_finding(fields: Fields, path: str) -> Finding | None:
    """E-RANGE if the list at `path` has too few or too many entries.

    An entry that is wrong or a placeholder counts, and a repeat does not.
    """
    entries = fields.entries(path)
    if entries is None:
        return None
    low, high = LIST_SIZES[path]
    if low <= len(entries) <= high:
        return None
    params = {"field": path, "value": str(len(entries)), "min": str(low), "max": str(high)}
    return fields.report("E-RANGE", path, params)


def valid_agent_id(agent: str) -> bool:
    """Whether `agent` is an agent id: 3 to 24 characters of the pattern, and not a reserved id."""
    low, high = AGENT_ID_LENGTH
    return (
        low <= len(agent) <= high
        and _AGENT_ID.fullmatch(agent) is not None
        and agent not in RESERVED_AGENT_IDS
    )


def check_fields(fields: Fields, cfg: PlatformConfig) -> tuple[list[Finding], str | None]:
    """The findings of the fields that stand alone, and the `max_class` that can be relied on.

    That is the class when it is R0, R1 or R2; None when it is missing, a placeholder, or wrong.
    The tool rules compare the tools with it, and skip that when it is None.
    """
    max_class, max_class_findings = _max_class(fields)
    findings = [
        *_schema(fields),
        *_agent(fields),
        *_range(fields, "version"),
        *_principal(fields, cfg),
        *max_class_findings,
        *_untrusted_input(fields),
        *_shadow(fields),
    ]
    return findings, max_class


def _range(fields: Fields, path: str) -> list[Finding]:
    found = range_finding(fields, path)
    return [] if found is None else [found]


def _schema(fields: Fields) -> list[Finding]:
    found = fields.checked("schema")
    if found is None or found == SCHEMA:
        return []
    return [fields.report("E-SCHEMA", "schema", {"found": found})]


def _agent(fields: Fields) -> list[Finding]:
    agent = fields.checked("agent")
    if agent is None or valid_agent_id(agent):
        return []
    return [fields.report("E-AGENT-ID", "agent", {"value": agent})]


def _principal(fields: Fields, cfg: PlatformConfig) -> list[Finding]:
    """E-PRINCIPAL: not the service account of this agent in the agents project of the platform.

    Nothing to compare with when the agent is not a valid id (ruling R28: that is E-AGENT-ID, and
    not a second error) or still a placeholder.
    """
    agent, principal = fields.checked("agent"), fields.checked("principal")
    if principal is None or agent is None or not valid_agent_id(agent):
        return []
    expected = f"agent-{agent}@{cfg.agents_project}.iam.gserviceaccount.com"
    if principal == expected:
        return []
    params = {"agent": agent, "project": cfg.agents_project, "value": principal}
    return [fields.report("E-PRINCIPAL", "principal", params)]


def _max_class(fields: Fields) -> tuple[str | None, list[Finding]]:
    """The usable class and E-MAX-CLASS-R3, E-MAX-CLASS-R4 or E-FIELD-TYPE for any other value."""
    value = fields.checked("max_class")
    if value is None:
        return None, []
    if value in POLICY_CLASSES:
        return value, []
    if value in ("R3", "R4"):
        return None, [fields.report(f"E-MAX-CLASS-{value}", "max_class")]
    params = {
        "field": "max_class",
        "expected": " | ".join(POLICY_CLASSES),
        "found": value or '""',  # nothing between the words of the message would be unreadable
    }
    return None, [fields.report("E-FIELD-TYPE", "max_class", params)]


def _untrusted_input(fields: Fields) -> list[Finding]:
    value = fields.checked("untrusted_input")
    if value is None:
        return []
    if value not in UNTRUSTED_INPUT_MODES:
        return [fields.report("E-UNTRUSTED-INPUT", "untrusted_input")]
    if value != UNTRUSTED_INPUT_DEFAULT:
        return [fields.report("W-UNTRUSTED-TAINT", "untrusted_input")]
    return []


def _shadow(fields: Fields) -> list[Finding]:
    """E-RANGE, or W-SHADOW-LOW below the default; a value out of range gets no warning (R45)."""
    path = "shadow.min_runs"
    found = range_finding(fields, path)
    if found is not None:
        return [found]
    runs = fields.checked(path)
    if runs is not None and runs < SHADOW_DEFAULT:
        return [fields.report("W-SHADOW-LOW", path, {"value": str(runs)})]
    return []
