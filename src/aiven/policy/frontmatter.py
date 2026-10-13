"""Front matter (validator-spec section 3.2): split it off the file, then load it strictly.

The YAML block at the top of a policy is what the gateway enforces, and the signer reads it as
text. So it is read with less YAML than YAML has: no anchor, alias, merge key, tag, directive,
complex key or second document, no backslash escape in a double-quoted string, no key twice in one
mapping, no character outside ASCII, and only the types of the field table (section 3.3). Where a
file used any of that, the signer would read one thing and some parser another. An escape does
that most plainly: a look-alike letter, an invisible character, a lone surrogate or a placeholder
can be written as an escape, and then the text reads as plain ASCII and decodes to something else.
No v1 field needs an escape, because every value is plain ASCII.

`split` cuts the decoded text of a file (`fileformat.decode_text`, which has dropped a byte-order
mark: E-ENCODING owns that) into the front matter and the body.

`load` reads the front matter from the parse events of ruamel.yaml (YAML 1.2, the pure Python
parser), and never builds YAML values:
- Anchors, aliases, explicit tags, directives and document starts show in the events. In a composed
  node graph an alias is a shared node and a tag looks like a resolved one.
- Nothing is constructed, so no tag can make Python build an object, and no alias can expand.
- A scalar stays the text that was written. Whether it is an integer or a string is decided here
  (`_INTEGER`, `_NOT_A_STRING`), so `5:00`, `0x12C`, `+5` and `on` are never read as numbers.
- The events come one at a time, and reading stops at `MAX_DEPTH`. A file of nothing but `[` would
  otherwise cost minutes: ruamel's scanner slows down with every level that is still open.

What `load` returns is a `FrontMatter`:
- `data`: the front matter as a dict of the fields of `FIELDS`, with Python values: str, int, list
  of str, and dicts for `limits`, `scope` and `shadow`. A field that is missing, unknown or of the
  wrong type is not in it, and neither is a list with a wrong entry (it would no longer match the
  numbers in `lines`). A repeated list entry stays. `data` is None when the YAML cannot be trusted
  (E-YAML, E-YAML-FEATURE, E-YAML-DUPLICATE-KEY: no value is kept when a key is there twice) and
  when the front matter is not a mapping. Then no field is checked, and the checks that need the
  fields are skipped (section 1). A field is never dropped silently: if it has a line and is not
  in `data`, a finding stands on its line (E-FIELD-TYPE, or E-PLACEHOLDER from the file checks) or
  on the line of a wrong entry of its list. So later checks may read "not in `data`" as "already
  reported".
- `lines`: the file line of every field and of every list entry that is in the file, by dotted path
  (`limits.max_runtime_s`, `tools.1`; entries count from 0). The line of a field is the line of its
  key. Empty when `data` is None. Later checks report at these lines.
- `placeholders`: the paths in `lines` whose value is written with a placeholder (`REPLACE_ME...`,
  `TODO`, `TBD`, `FIXME`). A field in it skips its other checks (section 3.1). It is judged on the
  value as it stands in the file, which is what E-PLACEHOLDER reads, and not on the value after
  YAML has decoded it: otherwise a placeholder written with an escape would skip every check and
  be reported by none.
- `findings`: E-FM-NON-ASCII, E-YAML, E-YAML-FEATURE, E-YAML-DUPLICATE-KEY, E-FIELD-MISSING,
  E-FIELD-UNKNOWN, E-FIELD-TYPE and E-LIST-DUPLICATE, in no particular order.

The front matter starts on file line 2. Lines are counted by LF only, as everywhere in the
validator, from the index of the character that a YAML mark points at. What ruamel raises for
input it rejects becomes E-YAML: its YAML errors, and the ValueError, OverflowError and
AssertionError that it raises for an escape that is no code point and for a `%YAML` version it does
not know. Any other exception, and any from this module, is a bug and goes up to the caller.

Findings carry text from the file in their params. `Finding` cleans them, so they are passed as
they are. Nothing else here puts text of the file in a message, a log or a repr.
"""

import re
from bisect import bisect_right
from contextlib import closing
from dataclasses import dataclass, field
from itertools import accumulate
from pathlib import Path
from typing import Any, Literal

from ruamel.yaml import YAML
from ruamel.yaml.error import MarkedYAMLError, YAMLError
from ruamel.yaml.events import (
    AliasEvent,
    CollectionEndEvent,
    CollectionStartEvent,
    DocumentStartEvent,
    ScalarEvent,
    SequenceStartEvent,
)
from ruamel.yaml.reader import ReaderError

from aiven.policy.chars import is_hidden
from aiven.policy.fileformat import has_placeholder
from aiven.policy.findings import Finding

DELIMITER = "---"

# The front matter starts on this line of the file, behind the opening delimiter.
FIRST_LINE = 2

# The most lists and mappings inside each other. The field table needs three (the front matter,
# `scope`, `scope.email_to`) and a list entry that is a list is wrong anyway, so nothing deeper can
# be right. A bigger limit would only let a file spend more time in the scanner.
MAX_DEPTH = 16

# The field table of section 3.3: a field is "string", "integer" or "list", or a dict of the fields
# inside a mapping. The order is that of the table, and missing fields are reported in it.
FIELDS: dict[str, Any] = {
    "schema": "string",
    "agent": "string",
    "version": "integer",
    "principal": "string",
    "max_class": "string",
    "tools": "list",
    "forbidden": "list",
    "untrusted_input": "string",
    "limits": {
        "emails_per_day": "integer",
        "records_per_run": "integer",
        "spend_eur_per_run": "integer",
        "max_runtime_s": "integer",
        "runs_per_day": "integer",
    },
    "scope": {
        "drive_folder_id": "string",
        "drive_folder_path": "string",
        "email_to": "list",
    },
    "shadow": {"min_runs": "integer"},
}

# Every field is required, except these and the fields inside them. Task 1.4 requires the scope
# fields that the tools need (E-SCOPE-MISSING).
OPTIONAL = frozenset({"scope"})

# Used with fullmatch: `$` would accept a trailing newline.
_INTEGER = re.compile(r"0|[1-9][0-9]*")

# Plain text that the YAML 1.2 core schema reads as null, bool, int or float, so not as a string.
_NOT_A_STRING = re.compile(
    "|".join(
        [
            r"~|null|Null|NULL",
            r"true|True|TRUE|false|False|FALSE",
            r"[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+",
            r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?",
            r"[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)",
        ]
    )
)

_NON_ASCII = re.compile(r"[^\x00-\x7f]")

# What a field check hands back when there is no usable value.
_UNUSABLE = object()


@dataclass(frozen=True)
class FrontMatter:
    """What `load` found: the data, where it stands, and the findings. See the module docstring.

    `data` and `lines` stay out of the repr, because they hold text of the file.
    """

    data: dict[str, Any] | None = field(repr=False)
    lines: dict[str, int] = field(repr=False)
    findings: list[Finding]
    placeholders: frozenset[str] = field(default=frozenset(), repr=False)


def split(text: str) -> tuple[str, str, int] | None:
    """The front matter, the body and the file line where the body starts. None: no front matter.

    Line 1 must be exactly `---`, and the front matter runs to the line before the next line that
    is exactly `---` (E-FM-MISSING if there is none). The front matter text has an LF behind every
    line, so `"---\\n" + front + "---\\n" + body` is the file again.
    """
    lines = text.split("\n")
    if lines[0] != DELIMITER:
        return None
    try:
        closing_row = lines.index(DELIMITER, 1)
    except ValueError:
        return None
    front = "".join(f"{line}\n" for line in lines[1:closing_row])
    body = "\n".join(lines[closing_row + 1 :])
    return front, body, closing_row + 2


def load(fm_text: str, path: Path | str = "") -> FrontMatter:
    """Read the front matter text (from `split`) strictly. `path` only names the file."""
    where = str(path)
    text = _Text(fm_text)
    findings = _non_ascii_findings(where, text)
    reader = _Reader(where, text)
    reader.read()
    findings.extend(reader.problems)
    if reader.problems:
        return FrontMatter(None, {}, findings)
    checker = _Checker(where)
    data = checker.check(reader.root)
    findings.extend(checker.findings)
    return FrontMatter(data, checker.lines, findings, frozenset(checker.placeholders))


def check_filename(path: Path, front: FrontMatter) -> list[Finding]:
    """E-FILENAME (section 3.1): the file is not called `<agent>.md`.

    It needs the agent id from the front matter, so it is checked here and not with the file.
    There is nothing to compare when there is no agent (no data, or it is missing or not a
    string), or when it is still a placeholder as written: that field skips its other checks.
    """
    agent = (front.data or {}).get("agent")
    if not isinstance(agent, str) or "agent" in front.placeholders or path.name == f"{agent}.md":
        return []
    return [Finding("E-FILENAME", "error", str(path), params={"name": path.name, "agent": agent})]


# --- the front matter as text


class _Text:
    """The front matter text, and a way from a character index to a position in the file."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.split("\n")
        self._starts = list(accumulate((len(line) + 1 for line in self.lines), initial=0))

    def row(self, index: int) -> int:
        """The row (0-based, in the front matter) of the character at `index`."""
        return bisect_right(self._starts, index) - 1

    def start(self, row: int) -> int:
        """The index of the first character of a row."""
        return self._starts[row]

    def line(self, index: int) -> int:
        """The file line (1-based) of the character at `index`."""
        return self.row(index) + FIRST_LINE

    def at(self, index: int) -> tuple[int, int]:
        """The file line and the column (both 1-based) of the character at `index`."""
        row = self.row(index)
        return row + FIRST_LINE, index - self._starts[row] + 1


# --- E-FM-NON-ASCII


def _non_ascii_findings(where: str, text: _Text) -> list[Finding]:
    """E-FM-NON-ASCII for each character outside ASCII, comments included.

    A hidden character is E-HIDDEN-CHAR already (one defect, one code), so it is left out.
    """
    findings = []
    for number, line in enumerate(text.lines, start=FIRST_LINE):
        for found in _NON_ASCII.finditer(line):
            if not is_hidden(found.group()):
                column = found.start() + 1
                params = {"col": str(column)}
                findings.append(Finding("E-FM-NON-ASCII", "error", where, number, column, params))
    return findings


# --- reading the YAML


@dataclass(slots=True, repr=False)
class _Node:
    """A value of the front matter. It has no repr: it holds text of the file."""

    kind: Literal["scalar", "list", "mapping"]
    line: int
    text: str = ""
    raw: str = ""  # a scalar as it stands in the file, quotes and escapes included
    plain: bool = False  # a scalar that was written without quotes or a block indicator
    items: list["_Node"] = field(default_factory=list)  # the entries of a list
    pairs: list[tuple["_Node", "_Node"]] = field(default_factory=list)  # (key, value) of a mapping


@dataclass(slots=True, repr=False)
class _Open:
    """A list or mapping that is still being read."""

    node: _Node
    key: _Node | None = None  # the key of a mapping that waits for its value
    seen: set[str] = field(default_factory=set)  # the keys of a mapping so far


class _Reader:
    """Builds the tree of the front matter from parse events and reports the forbidden YAML.

    `problems` holds E-YAML, E-YAML-FEATURE and E-YAML-DUPLICATE-KEY findings. The tree in `root`
    can only be used when there are none; with a feature or a repeated key it is not what the file
    says, and after a syntax error it is not complete.
    """

    def __init__(self, where: str, text: _Text) -> None:
        self.where = where
        self.text = text
        self.problems: list[Finding] = []
        self.root: _Node | None = None
        self._open: list[_Open] = []
        self._documents = 0
        self._last_index = 0  # where the last event that was taken starts

    def read(self) -> None:
        """Read all events, or as many as can be trusted. A YAML error is one more problem.

        The events are pulled one at a time and handled apart (`_feed`), so that only what ruamel
        raises is caught here, and an exception from this module itself goes up to the caller.
        Besides YAML errors, ruamel raises a ValueError or an OverflowError for an escape that is
        no code point, and an AssertionError for a `%YAML` version it does not know. They are
        E-YAML as well.
        """
        yaml = YAML(typ="safe", pure=True)  # pure: the same result with or without the C parser
        yaml.version = (1, 2)
        with closing(yaml.parse(self.text.source)) as events:
            while True:
                try:
                    event = next(events, None)
                except YAMLError as error:
                    self._syntax_problem(*_describe(error))
                    return
                except (ValueError, OverflowError):
                    self._rejected("invalid escape sequence")
                    return
                except AssertionError:
                    self._rejected("unsupported YAML version")
                    return
                if event is None or not self._feed(event):
                    return

    def _rejected(self, detail: str) -> None:
        """E-YAML for input that ruamel rejects without a position: at the last event it gave."""
        self._syntax_problem(detail, self._last_index)

    def _feed(self, event: Any) -> bool:
        """Take one event. False means stop: it is too deep, or ruamel would have refused it."""
        keep_going = True
        if isinstance(event, ScalarEvent):
            self._scalar(event)
        elif isinstance(event, AliasEvent):
            self._feature("alias", event.start_mark.index)
            self._add(_Node("scalar", self.text.line(event.start_mark.index)))
        elif isinstance(event, CollectionStartEvent):
            keep_going = self._start(event)
        elif isinstance(event, CollectionEndEvent):
            self._add(self._open.pop().node)
        elif isinstance(event, DocumentStartEvent):
            keep_going = self._document(event)
        self._last_index = event.start_mark.index
        return keep_going

    def _scalar(self, event: ScalarEvent) -> None:
        self._properties(event)
        index = event.start_mark.index
        raw = self.text.source[index : event.end_mark.index]
        node = _Node("scalar", self.text.line(index), event.value, raw, event.style is None)
        if event.style == '"' and "\\" in raw:
            self._feature("escape sequence", index)
        if self._expects_key():
            if node.plain and node.text == "<<":
                self._feature("merge key", index)
            seen = self._open[-1].seen
            if node.text in seen:
                self._problem("E-YAML-DUPLICATE-KEY", index, key=node.text)
            seen.add(node.text)
        self._add(node)

    def _start(self, event: CollectionStartEvent) -> bool:
        self._properties(event)
        index = event.start_mark.index
        if self._expects_key():
            self._feature("complex key", index)
        if len(self._open) >= MAX_DEPTH:
            self._syntax_problem(f"nesting is deeper than {MAX_DEPTH} levels", index)
            return False
        kind = "list" if isinstance(event, SequenceStartEvent) else "mapping"
        self._open.append(_Open(_Node(kind, self.text.line(index))))
        return True

    def _document(self, event: DocumentStartEvent) -> bool:
        """A document start. The file's own `---` opened the first document, so a marker in the
        front matter always starts another one, and so does anything after a `...`.

        False if the document says it is YAML of a version that ruamel does not know. Ruamel checks
        that with an assert, which `python -O` removes, so it is judged here too: otherwise the
        result would depend on how Python was started. It is then the same as when ruamel raises.
        """
        if event.version not in (None, (1, 1), (1, 2)):
            self._rejected("unsupported YAML version")
            return False
        self._documents += 1
        index = event.start_mark.index
        if event.explicit:
            for row in self._directive_rows(self.text.row(index)):
                self._feature("directive", self.text.start(row))
        if event.explicit or self._documents > 1:
            self._feature("second document", index)
        return True

    def _directive_rows(self, marker_row: int) -> list[int]:
        """The rows of the directives above the `---` marker in `marker_row`, in file order.

        A directive is a line that starts with `%`. Only blank lines and comments may stand
        between directives, and between the last one and the marker. The events do not show every
        directive (ruamel drops the ones it does not know), so the text is looked at.
        """
        rows = []
        for row in range(marker_row - 1, -1, -1):
            line = self.text.lines[row]
            if line.startswith("%"):
                rows.append(row)
            elif line.strip() and not line.lstrip().startswith("#"):
                break
        return rows[::-1]

    def _properties(self, event: Any) -> None:
        index = event.start_mark.index
        if event.anchor is not None:
            self._feature("anchor", index)
        if event.ctag is not None:
            self._feature("tag", index)

    def _expects_key(self) -> bool:
        """Whether the next node is a key: a mapping is open and it has no key waiting."""
        return bool(self._open) and (
            self._open[-1].node.kind == "mapping" and self._open[-1].key is None
        )

    def _add(self, node: _Node) -> None:
        """Put a finished node where it belongs: the root, a list, or a key or value."""
        if not self._open:
            self.root = node
            return
        top = self._open[-1]
        if top.node.kind == "list":
            top.node.items.append(node)
        elif top.key is None:
            top.key = node
        else:
            top.node.pairs.append((top.key, node))
            top.key = None

    def _feature(self, name: str, index: int) -> None:
        self._problem("E-YAML-FEATURE", index, feature=name)

    def _problem(self, code: str, index: int, **params: str) -> None:
        line, column = self.text.at(index)
        self.problems.append(Finding(code, "error", self.where, line, column, params))

    def _syntax_problem(self, detail: str, index: int = 0) -> None:
        line, column = self.text.at(index)
        params = {"col": str(column), "detail": detail}
        self.problems.append(Finding("E-YAML", "error", self.where, line, column, params))


def _describe(error: YAMLError) -> tuple[str, int]:
    """What ruamel says is wrong, and the index of the character where.

    Only its short problem text is used. `str(error)` would add the lines of the file around the
    problem, and a finding must not become a copy of the file.
    """
    if isinstance(error, MarkedYAMLError):
        mark = error.problem_mark or error.context_mark
        return error.problem or "syntax error", mark.index if mark else 0
    if isinstance(error, ReaderError):
        return error.reason, error.position
    return "syntax error", 0


# --- checking the fields


class _Checker:
    """Checks the tree against `FIELDS`, and collects the data, the lines and the findings."""

    def __init__(self, where: str) -> None:
        self.where = where
        self.findings: list[Finding] = []
        self.lines: dict[str, int] = {}
        self.placeholders: set[str] = set()

    def check(self, root: _Node | None) -> dict[str, Any] | None:
        if root is None:  # no document, only comments perhaps: a mapping without fields
            root = _Node("mapping", FIRST_LINE)
        if root.kind != "mapping":
            self._wrong_type("front matter", root.line, "mapping", root)
            return None
        return self._mapping(root, FIELDS, "", 1, required=True)

    def _mapping(
        self, node: _Node, fields: dict[str, Any], prefix: str, line: int, *, required: bool
    ) -> dict[str, Any]:
        """The fields of one mapping. A missing field is reported at `line`: that of its parent."""
        data: dict[str, Any] = {}
        for key, value in node.pairs:
            path = prefix + key.text
            kind = fields.get(key.text)
            if kind is None:
                self._report("E-FIELD-UNKNOWN", key.line, field=prefix + (key.text or "null"))
                continue
            self.lines[path] = key.line
            found = self._value(path, kind, key.line, value, required and path not in OPTIONAL)
            if found is not _UNUSABLE:
                data[key.text] = found
        present = {key.text for key, _ in node.pairs}
        for name in fields:
            if name not in present and required and prefix + name not in OPTIONAL:
                self._report("E-FIELD-MISSING", line, field=prefix + name)
        return data

    def _value(self, path: str, kind: Any, line: int, node: _Node, required: bool) -> Any:
        self._note_placeholder(path, node)
        if isinstance(kind, dict):
            if node.kind != "mapping":
                return self._wrong_type(path, line, "mapping", node)
            return self._mapping(node, kind, path + ".", line, required=required)
        if kind == "list":
            return self._list(path, line, node)
        if kind == "integer":
            return self._integer(path, line, node)
        return self._string(path, line, node)

    def _integer(self, path: str, line: int, node: _Node) -> Any:
        """Plain digits only: no quotes, sign, leading zero, `_`, `0x`, and not `5:00`."""
        if node.kind == "scalar" and node.plain and _INTEGER.fullmatch(node.text):
            try:
                return int(node.text)
            except ValueError:  # more digits than Python reads; no field takes so many
                pass
        return self._wrong_type(path, line, "integer", node)

    def _string(self, path: str, line: int, node: _Node) -> Any:
        if _is_string(node):
            return node.text
        return self._wrong_type(path, line, "string", node)

    def _list(self, path: str, line: int, node: _Node) -> Any:
        """A list of strings. Every entry gets a line, and an entry that repeats is reported."""
        if node.kind != "list":
            return self._wrong_type(path, line, "list", node)
        entries: list[str] = []
        seen: set[str] = set()
        usable = True
        for number, item in enumerate(node.items):
            entry = f"{path}.{number}"
            self.lines[entry] = item.line
            self._note_placeholder(entry, item)
            if not _is_string(item):
                self._wrong_type(entry, item.line, "string", item)
                usable = False
                continue
            if item.text in seen and entry not in self.placeholders:
                self._report("E-LIST-DUPLICATE", item.line, list=path, entry=item.text)
            seen.add(item.text)
            entries.append(item.text)
        return entries if usable else _UNUSABLE

    def _note_placeholder(self, path: str, node: _Node) -> None:
        """Remember a scalar that is written with a placeholder, judged on its text in the file.

        E-PLACEHOLDER reads the file as it is written, and so does this. A value that YAML decodes
        to a placeholder (`"T\\x4fDO"`) is not one for E-PLACEHOLDER, and so not for this.
        """
        if node.kind == "scalar" and has_placeholder(node.raw):
            self.placeholders.add(path)

    def _wrong_type(self, path: str, line: int, expected: str, node: _Node) -> Any:
        """E-FIELD-TYPE, unless E-PLACEHOLDER reports the value on `line`, the line of the field.

        A field that holds a placeholder skips its other checks (section 3.1). It must not drop
        out of `data` without a finding on its line though, because later checks read "not in
        `data`" as "already reported". E-PLACEHOLDER is sure to report a placeholder that stands
        in the part of the value on `line`. One on a later line is reported there, the field would
        have nothing on its own line, and so the type error stays.
        """
        first_line = node.raw.split("\n", 1)[0]
        if not (node.kind == "scalar" and node.line == line and has_placeholder(first_line)):
            self._report("E-FIELD-TYPE", line, field=path, expected=expected, found=_found(node))
        return _UNUSABLE

    def _report(self, code: str, line: int, **params: str) -> None:
        self.findings.append(Finding(code, "error", self.where, line, params=params))


def _is_string(node: _Node) -> bool:
    """Whether YAML 1.2 reads the node as a string: quoted text, or plain text that is no null,
    bool, int or float."""
    if node.kind != "scalar":
        return False
    return not node.plain or not (node.text == "" or _NOT_A_STRING.fullmatch(node.text))


def _found(node: _Node) -> str:
    """What E-FIELD-TYPE says was found: `list`, `mapping`, or the scalar text as it was written.

    Text that was not plain is shown in double quotes; no value at all is `null`.
    """
    if node.kind != "scalar":
        return node.kind
    if node.plain:
        return node.text or "null"
    return f'"{node.text}"'
