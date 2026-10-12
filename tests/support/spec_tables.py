"""Read tables and sentences out of docs/validator-spec.md.

The drift tests parse the spec itself and compare it with the code and data files, so a spec
edit without a code edit (or the reverse) fails CI.
"""

import re
from pathlib import Path

from tests.support import REPO_ROOT

SPEC_PATH = REPO_ROOT / "docs" / "validator-spec.md"

_HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*$")
_SEPARATOR_CELL = re.compile(r"^:?-+:?$")
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
_CODE_SPAN = re.compile(r"`([^`]+)`")


def _visible_lines(path: Path) -> list[str]:
    """The lines of a Markdown file, minus the ones inside fenced code blocks."""
    lines: list[str] = []
    in_fence = False
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        elif not in_fence:
            lines.append(line)
    return lines


def _cells(line: str) -> list[str]:
    row = line.strip()
    if not (row.startswith("|") and row.endswith("|")):
        raise ValueError(f"table row must start and end with a pipe: {line!r}")
    return [cell.strip().replace("\\|", "|") for cell in _UNESCAPED_PIPE.split(row[1:-1])]


def table_after(heading: str, path: Path = SPEC_PATH) -> list[list[str]]:
    """The cells of the first table under a heading: header row first, separator row dropped.

    `heading` is the heading text without its leading #s. It must match the start of exactly one
    heading, so a renamed or duplicated heading fails loudly instead of reading the wrong table.
    """
    lines = _visible_lines(path)
    starts = [
        number
        for number, line in enumerate(lines)
        if (match := _HEADING.match(line)) and match.group(1).startswith(heading)
    ]
    if len(starts) != 1:
        raise LookupError(
            f"expected exactly one heading starting with {heading!r}, found {len(starts)}"
        )
    rows: list[list[str]] = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("|"):
            rows.append(_cells(line))
        elif rows or _HEADING.match(line):
            break
    if len(rows) < 2:
        raise LookupError(f"no table under heading {heading!r}")
    header, separator, *body = rows
    if not all(_SEPARATOR_CELL.match(cell) for cell in separator):
        raise ValueError(f"the second row of the table under {heading!r} is not a separator")
    for row in body:
        if len(row) != len(header):
            raise ValueError(f"row has {len(row)} cells, the header has {len(header)}: {row}")
    return [header, *body]


def line_starting_with(prefix: str, path: Path = SPEC_PATH) -> str:
    """The one line (outside code fences) that starts with `prefix`."""
    found = [line for line in _visible_lines(path) if line.startswith(prefix)]
    if len(found) != 1:
        raise LookupError(f"expected exactly one line starting with {prefix!r}, found {len(found)}")
    return found[0]


def code_spans(text: str) -> list[str]:
    """The contents of the `backticked` spans in a piece of Markdown, in order."""
    return _CODE_SPAN.findall(text)
