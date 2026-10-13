"""File format checks (validator-spec section 3.1).

`check_file` looks at the raw bytes and at a best-effort decoding of them (`decode_text`), so a
file that fails one check is still checked for the others. E-FILENAME needs the agent id from the
front matter, so it is checked together with the front matter and not here.
"""

import codecs
import re
from pathlib import Path

from aiven.policy.chars import is_hidden
from aiven.policy.constants import MAX_FILE_BYTES
from aiven.policy.content import ELLIPSIS, HIDDEN, is_sensitive
from aiven.policy.findings import Finding

# Whole words only and case-sensitive, so a random Drive ID that happens to hold "TBD" is no hit.
_PLACEHOLDER = re.compile(r"\b(?:REPLACE_ME\w*|TODO|TBD|FIXME)\b")

# The name of a placeholder: REPLACE_ME and any upper-case words after underscores. A finding shows
# this much of what `_PLACEHOLDER` found, and nothing that follows it in the same word.
_NAME = re.compile(r"REPLACE_ME(?:_[A-Z0-9]+)*")

# A word: the run of characters without whitespace that a placeholder stands in.
_WORD = re.compile(r"\S+")

# Printable ASCII has no hidden character. Looking only at the rest keeps the common case fast.
_NOT_PRINTABLE_ASCII = re.compile(r"[^\x20-\x7e]")


def has_placeholder(text: str) -> bool:
    """Whether `text` holds a placeholder: `REPLACE_ME...`, `TODO`, `TBD` or `FIXME`.

    This is the test of E-PLACEHOLDER. A field that holds a placeholder skips its other checks
    (section 3.1), so the checks of a field ask it too.
    """
    return _PLACEHOLDER.search(text) is not None


def decode_text(data: bytes) -> str:
    """The text that every check reads: one leading byte-order mark dropped, bad bytes replaced.

    E-ENCODING reports the byte-order mark and the invalid bytes; the other checks still need
    text to work on. Lines are separated by LF only, so a CR or a Unicode line separator stays
    inside its line.
    """
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8) :]
    return data.decode("utf-8", errors="replace")


def check_file(path: Path, data: bytes, text: str | None = None) -> list[Finding]:
    """Every finding of section 3.1 for `data`, the content of the file called `path`.

    `path` only names the file in the findings; nothing is read from disk. `text` is
    `decode_text(data)`: pass it when you have decoded the bytes already, and they are not decoded
    twice.

    E-ENCODING, E-LINE-ENDINGS, E-FINAL-NEWLINE and E-FILE-SIZE are reported once per file, and
    E-HIDDEN-CHAR and E-PLACEHOLDER once per occurrence. The findings come in no particular
    order: `validate_file` sorts them.
    """
    where = str(path)
    if text is None:
        text = decode_text(data)
    findings: list[Finding] = []

    encoding_line = _encoding_line(data)
    if encoding_line is not None:
        findings.append(Finding("E-ENCODING", "error", where, encoding_line))

    first_cr = text.find("\r")
    if first_cr != -1:
        findings.append(Finding("E-LINE-ENDINGS", "error", where, _line_at(text, first_cr)))

    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        findings.append(Finding("E-FINAL-NEWLINE", "error", where))

    if len(data) > MAX_FILE_BYTES:
        findings.append(Finding("E-FILE-SIZE", "error", where, params={"size": str(len(data))}))

    for number, line in enumerate(text.split("\n"), start=1):
        for found in _NOT_PRINTABLE_ASCII.finditer(line):
            char = found.group()
            # A CR is hidden by the definition, but E-LINE-ENDINGS owns it: one defect, one code.
            # A byte-order mark at the start never gets here: `decode_text` drops it, and
            # E-ENCODING reports it.
            if char != "\r" and is_hidden(char):
                column = found.start() + 1
                params = {"codepoint": f"U+{ord(char):04X}", "col": str(column)}
                findings.append(Finding("E-HIDDEN-CHAR", "error", where, number, column, params))
        findings.extend(_placeholder_findings(where, number, line))
    return findings


def _placeholder_findings(where: str, number: int, line: str) -> list[Finding]:
    """E-PLACEHOLDER for each placeholder in one line.

    A finding shows the name of the placeholder (`_name`) and nothing of the word around it, and
    not even the name when that word holds something sensitive: `REPLACE_ME_` and a key are one
    word, and a name that stops at a hyphen or a dot inside the key would show part of it. So the
    whole word goes through `is_sensitive`, once, however many placeholders it holds. If it is
    sensitive, the token is `[hidden]`.
    """
    if not has_placeholder(line):
        return []
    findings = []
    for word in _WORD.finditer(line):
        text = word.group()
        sensitive = None
        for found in _PLACEHOLDER.finditer(text):
            if sensitive is None:
                sensitive = is_sensitive(text)
            params = {"token": HIDDEN if sensitive else _name(found.group())}
            column = word.start() + found.start() + 1
            findings.append(Finding("E-PLACEHOLDER", "error", where, number, column, params))
    return findings


def _name(placeholder: str) -> str:
    """The name of a placeholder, with an ellipsis if the placeholder goes on after it.

    `TODO`, `TBD` and `FIXME` are their own names. Of a word that starts with `REPLACE_ME`, the
    name is the longest start that is `REPLACE_ME` and upper-case words after underscores.
    """
    if not placeholder.startswith("REPLACE_ME"):
        return placeholder
    name = _NAME.match(placeholder).group()
    return name if len(name) == len(placeholder) else name + ELLIPSIS


def _encoding_line(data: bytes) -> int | None:
    """The line of the first encoding problem: 1 for a byte-order mark, else the first bad byte."""
    if data.startswith(codecs.BOM_UTF8):
        return 1
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        return data.count(b"\n", 0, error.start) + 1
    return None


def _line_at(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1
