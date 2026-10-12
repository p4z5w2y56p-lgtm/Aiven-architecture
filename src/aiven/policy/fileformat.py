"""File format checks (validator-spec section 3.1).

`check_file` looks at the raw bytes and at a best-effort decoding of them (`decode_text`), so a
file that fails one check is still checked for the others. E-FILENAME needs the agent id from the
front matter, so it is checked together with the front matter and not here.
"""

import codecs
import re
import unicodedata
from pathlib import Path

from aiven.policy.constants import HIDDEN_CATEGORIES, HIDDEN_RANGES, MAX_FILE_BYTES
from aiven.policy.findings import Finding

# Whole words only and case-sensitive, so a random Drive ID that happens to hold "TBD" is no hit.
_PLACEHOLDER = re.compile(r"\b(?:REPLACE_ME\w*|TODO|TBD|FIXME)\b")

# Printable ASCII has no hidden character. Looking only at the rest keeps the common case fast.
_NOT_PRINTABLE_ASCII = re.compile(r"[^\x20-\x7e]")


def decode_text(data: bytes) -> str:
    """The text that every check reads: one leading byte-order mark dropped, bad bytes replaced.

    E-ENCODING reports the byte-order mark and the invalid bytes; the other checks still need
    text to work on. Lines are separated by LF only, so a CR or a Unicode line separator stays
    inside its line.
    """
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8) :]
    return data.decode("utf-8", errors="replace")


def check_file(path: Path, data: bytes) -> list[Finding]:
    """Every finding of section 3.1 for `data`, the content of the file called `path`.

    `path` only names the file in the findings; nothing is read from disk. E-ENCODING, E-LINE-ENDINGS, E-FINAL-NEWLINE and E-FILE-SIZE are reported once per file, and
    E-HIDDEN-CHAR and E-PLACEHOLDER once per occurrence. The findings come in no particular
    order: `validate_file` sorts them.
    """
    where = str(path)
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
            if _is_hidden(found.group()):
                column = found.start() + 1
                params = {"codepoint": f"U+{ord(found.group()):04X}", "col": str(column)}
                findings.append(Finding("E-HIDDEN-CHAR", "error", where, number, column, params))
        for found in _PLACEHOLDER.finditer(line):
            params = {"token": found.group()}
            findings.append(
                Finding("E-PLACEHOLDER", "error", where, number, found.start() + 1, params)
            )
    return findings


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


def _is_hidden(char: str) -> bool:
    """Whether `char` can hide text from the signer (the categories and ranges in constants).

    LF is the line separator, CR belongs to E-LINE-ENDINGS (one defect, one code), and the normal
    space is plainly visible. A byte-order mark at the start never gets here: `decode_text` drops
    it, and E-ENCODING reports it.
    """
    if char in "\n\r ":
        return False
    if unicodedata.category(char) in HIDDEN_CATEGORIES:
        return True
    code = ord(char)
    return any(low <= code <= high for low, high in HIDDEN_RANGES)
