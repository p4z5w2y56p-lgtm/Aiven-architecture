"""`aiven-check-config`: the platform values and the Terraform values hold IDs and addresses only.

At the M1 review Matthijs decided that `config/platform.yaml` holds IDs and addresses only, never a
credential, a key or a token, and that CI refuses secrets in it. The Terraform values
(`infra/terraform/terraform.tfvars`) are held to the same rule; both files are committed. This
command is that check (ruling R113). With no arguments it checks each of `DEFAULT_FILES` that
exists; with arguments, the files named. CI runs it on every push and pull request.

With `--staged` it checks each of `DEFAULT_FILES` that the Git index holds, as the index holds it:
what the next commit holds, whatever the working copy says. Terraform values are then checked
against the `variables.tf` of the index. The optional pre-commit hook `.githooks/pre-commit` runs
this, so a secret is refused before it is in the Git history; CI stays the gate that cannot be
skipped. Without Git, or outside a work tree, it is exit 2.

Every file:

- C-FILE-KIND: it is neither platform values (`.yaml`, `.yml`) nor Terraform values (`.tfvars`,
  `.tfvars.example`). C-READ: it cannot be read. C-SIZE: it is larger than 64 KiB, and is not read.
- C-SECRET: `aiven.policy.content.scan` flags a line, comments included: a credential, a bank
  detail or an ID number. That is `scan`, and not the guard's paranoid `is_sensitive`, which would
  flag a long project number.
- C-ENCODING: it is not plain ASCII text (printable ASCII, tabs, and LF or CR LF line ends). Its
  lines are still scanned, and nothing else is checked.
- C-SECRET-NAME: a key or a variable whose name suggests a secret (`secret_like`, ruling R114).

Platform values: the rules of `config.platform_problems`, which the validator loads by too:
C-SYNTAX (YAML that does not load, a duplicate key, not a mapping), C-UNKNOWN-KEY, C-MISSING and
C-SHAPE. Each string value is scanned again as YAML reads it, because an escape (`"\\x41KIA..."`)
hides a key from the line.

Terraform values: a strict subset of HCL. An assignment takes one line, a list may take several:
`name = "string"`, a number, `true` or `false`, or a list of strings, with blank lines and `#` and
`//` comments. Anything else is C-SYNTAX at its line, and the file is not read past it: a heredoc,
a map, a function, a reference, `${` or `%{`, a backslash, a negative number, a `/* */` comment. A
name that is set twice is C-SYNTAX too. The names are the variables that `variables.tf` in the same
folder declares at the start of a line, as `terraform fmt` writes them (C-UNKNOWN-KEY for any other
name); without that file no name can be checked (C-NO-VARIABLES). Each name has a shape
(`_TFVARS_SHAPES`, C-SHAPE).

Output: one line per problem on stdout, `error <CODE> <path>[:<line>]: <text>`, the problems of a
file in the order of their lines and the files in the order given. The text is fixed. It names a
key of the platform values or a declared variable, a kind of secret, a line; never a value, and
nothing else that is read from the file. So a secret that is refused does not land in a CI log a
second time. The path is written in ASCII, with escapes. One line on stderr says which files were
checked.

Exit codes: 0 no problem, 1 problems, 2 a crash (C-INTERNAL, which gives the name of the class of
the error only: its message can quote the file).

What it cannot see (validator-spec section 8): a secret of no known shape, under a name that does
not suggest one, as a value that fits its key (a drive ID is any 10 to 100 letters, digits, `_` and
`-`). And CI runs it after the commit: a secret that CI finds is in the Git history already, and
must be revoked, not only removed. Only the pre-commit hook, where it is installed, comes before.
"""

import argparse
import os
import posixpath
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import date
from decimal import Decimal
from functools import partial
from pathlib import Path
from typing import NamedTuple

from aiven.policy.addresses import is_address
from aiven.policy.config import (
    PROJECT_ID_RE,
    PROJECT_ID_TEXT,
    ConfigError,
    parse_platform_values,
    platform_problems,
)
from aiven.policy.constants import MAX_FILE_BYTES
from aiven.policy.content import escape_unprintable, scan
from aiven.policy.fields import valid_agent_id

DEFAULT_FILES = (
    "config/platform.yaml",
    "config/platform.example.yaml",
    "infra/terraform/terraform.tfvars",
    "infra/terraform/terraform.tfvars.example",
)

EXIT_OK, EXIT_PROBLEMS, EXIT_CRASH = 0, 1, 2
GIT_TIMEOUT_S = 60

_ONLY_IDS = "this file holds IDs and addresses only"
_SECRET_NAME = f"a name that suggests a secret; {_ONLY_IDS}"
_NOT_PLAIN = (
    "not a plain assignment: name = a string, a number, true, false or a list of strings, "
    "with nothing after it but a comment"
)


def _ascii(text: str) -> str:
    """`text` in printable ASCII: escapes for what is unprintable or hidden, and for the rest."""
    return escape_unprintable(text).encode("ascii", "backslashreplace").decode("ascii")


@dataclass(frozen=True)
class Problem:
    """One problem of a file. `line` is 1-based, None for the whole file; `text` is fixed text.

    Making a problem writes its path in printable ASCII (`_ascii`), so a file name cannot start
    another line of output, and cannot fail on an output that takes ASCII only.
    """

    code: str
    path: str
    line: int | None
    text: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _ascii(self.path))

    def __str__(self) -> str:
        where = self.path if self.line is None else f"{self.path}:{self.line}"
        return f"error {self.code} {where}: {self.text}"


# --- names that suggest a secret (ruling R114)

# Words that suggest a secret wherever they stand in a name (with its parts joined), and words that
# do only as a whole part of it: `auth` is in `trusted_authors`, and `key` in `keyword`.
_SECRET_ANYWHERE = (
    "secret",
    "token",
    "passw",
    "passphrase",
    "credential",
    "apikey",
    "accesskey",
    "privatekey",
    "bearer",
)
_SECRET_PARTS = frozenset(
    {
        "auth",
        "authn",
        "authz",
        "oauth",
        "oauth2",
        "pass",
        "pwd",
        "pin",
        "otp",
        "creds",
        "private",
        "key",
        "keys",
        "cert",
        "certs",
        "certificate",
        "certificates",
        "pem",
        "p12",
        "pfx",
        "jwt",
    }
)
_NAME_PARTS = re.compile(r"[\s_.-]+|(?<=[a-z0-9])(?=[A-Z])")


def secret_like(name: str) -> bool:
    """Whether a key's name suggests a secret (ruling R114).

    The name is cut into parts at `_`, `-`, `.`, white space, and where a capital follows a
    lower-case letter or a digit, and the parts are taken in lower case. It suggests a secret when
    the parts joined hold a word of `_SECRET_ANYWHERE`, or when a part is a word of `_SECRET_PARTS`
    or ends in `key` or `keys` (`apikey`, `sakey`, `sshkeys`).
    """
    parts = [part.lower() for part in _NAME_PARTS.split(name) if part]
    joined = "".join(parts)
    return any(word in joined for word in _SECRET_ANYWHERE) or any(
        part in _SECRET_PARTS or part.endswith(("key", "keys")) for part in parts
    )


def _secret_text(kind: str) -> str:
    return f"looks like it holds a secret ({kind}); {_ONLY_IDS}"


# --- platform values

_PLATFORM_CODES = {
    "not a mapping": "C-SYNTAX",
    "unknown key": "C-UNKNOWN-KEY",
    "missing key": "C-MISSING",
    "wrong value": "C-SHAPE",
}
_KEY_AT_START = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)[ \t]*:(?:[ \t]|$)")


def _key_lines(text: str) -> dict[str, int]:
    """The line of each key that starts a line as a plain word and a colon.

    A key that is quoted, or in a flow mapping, has no line here: its problems are about the whole
    file.
    """
    lines: dict[str, int] = {}
    for number, line in enumerate(text.split("\n"), start=1):
        if found := _KEY_AT_START.match(line.rstrip("\r")):
            lines.setdefault(found[1], number)
    return lines


def _check_platform(text: str, where: str, scanned: set[str]) -> list[Problem]:
    """The problems of platform values, when the line scan found the kinds in `scanned`."""
    try:
        doc = parse_platform_values(text)
    except ConfigError as error:
        return [Problem("C-SYNTAX", where, error.line, str(error))]
    lines = _key_lines(text)
    problems = []
    for problem in platform_problems(doc):
        if problem.kind == "unknown key" and isinstance(problem.key, str):
            if secret_like(problem.key):
                problems.append(
                    Problem("C-SECRET-NAME", where, lines.get(problem.key), _SECRET_NAME)
                )
                continue
        line = lines.get(problem.key) if isinstance(problem.key, str) else None
        problems.append(Problem(_PLATFORM_CODES[problem.kind], where, line, problem.text))
    if isinstance(doc, dict):
        # A value as YAML reads it: an escape can hide from the line scan what it stands for.
        for key, value in doc.items():
            line = lines.get(key) if isinstance(key, str) else None
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str):
                    problems += [
                        Problem("C-SECRET", where, line, _secret_text(hit.kind))
                        for hit in scan(item)
                        if hit.kind not in scanned
                    ]
    return problems


# --- Terraform values

# The tokens of the subset. A comment counts as blank: it ends the line, and is scanned all the
# same. A string has no backslash (so no escape), no `$` and no `%` (so no `${` and no `%{`). A
# number has no sign and no exponent, and no letter or digit or dot right after it.
_TOKEN = re.compile(
    r"""
      (?P<blank>[ \t]+|(?:\#|//)[^\n]*)
    | (?P<newline>\n)
    | (?P<name>[A-Za-z_][A-Za-z0-9_-]*)
    | (?P<string>"[^"\\$%\n]*")
    | (?P<number>[0-9]+(?:\.[0-9]+)?(?![A-Za-z0-9_.]))
    | (?P<punct>[=\[\],])
    """,
    re.VERBOSE,
)

_Value = str | Decimal | bool | tuple[str, ...]


class _Token(NamedTuple):
    kind: str  # name, string, number, = [ ] , newline, end, or bad: where nothing fits
    text: str
    line: int


def _tokens(text: str) -> list[_Token]:
    """The tokens of `text`, up to a "bad" one where no token fits, and then an "end"."""
    tokens: list[_Token] = []
    line, position = 1, 0
    while position < len(text):
        found = _TOKEN.match(text, position)
        if found is None:
            tokens.append(_Token("bad", "", line))
            break
        kind = found.lastgroup
        if kind == "newline":
            tokens.append(_Token(kind, "", line))
            line += 1
        elif kind == "punct":
            tokens.append(_Token(found[0], "", line))
        elif kind != "blank":
            tokens.append(_Token(str(kind), found[0], line))
        position = found.end()
    last = line - 1 if text.endswith("\n") else line
    tokens.append(_Token("end", "", max(last, 1)))
    return tokens


class _NotPlain(Exception):
    """The subset does not allow what stands at `line`."""

    def __init__(self, line: int) -> None:
        super().__init__(line)
        self.line = line


class _Assignment(NamedTuple):
    name: str
    value: _Value
    line: int


class _Parser:
    """Reads the tokens of Terraform values, and raises _NotPlain at the first one out of place."""

    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens, self.at = tokens, 0

    def peek(self) -> _Token:
        return self.tokens[self.at]

    def take(self, *kinds: str) -> _Token:
        token = self.peek()
        if token.kind not in kinds:
            raise _NotPlain(token.line)
        if token.kind != "end":
            self.at += 1
        return token

    def skip_newlines(self) -> None:
        while self.peek().kind == "newline":
            self.at += 1

    def assignment(self) -> _Assignment:
        name = self.take("name")
        self.take("=")
        value = self.value()
        self.take("newline", "end")
        return _Assignment(name.text, value, name.line)

    def value(self) -> _Value:
        token = self.take("string", "number", "name", "[")
        if token.kind == "string":
            return token.text[1:-1]
        if token.kind == "number":
            return Decimal(token.text)
        if token.kind == "name":
            if token.text not in ("true", "false"):
                raise _NotPlain(token.line)  # a function, or a reference
            return token.text == "true"
        items: list[str] = []
        self.skip_newlines()
        while self.peek().kind != "]":
            items.append(self.take("string").text[1:-1])
            self.skip_newlines()
            if self.take(",", "]").kind == "]":
                return tuple(items)
            self.skip_newlines()
        self.take("]")
        return tuple(items)


def _assignments(text: str) -> tuple[list[_Assignment], int | None]:
    """The assignments of Terraform values, up to the first thing that the subset does not allow,
    and the line of that thing (None when there is none). Windows line ends are allowed."""
    parser = _Parser(_tokens(text.replace("\r\n", "\n")))
    found: list[_Assignment] = []
    try:
        while True:
            parser.skip_newlines()
            if parser.peek().kind == "end":
                return found, None
            found.append(parser.assignment())
    except _NotPlain as stop:
        return found, stop.line


_ORG_ID = re.compile(r"[0-9]{1,20}")
_BILLING_ACCOUNT = re.compile(r"[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}")
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_PLAIN = re.compile(r"[!-~]+")  # printable ASCII without a space


def _string_of(pattern: re.Pattern[str]) -> Callable[[_Value], bool]:
    return lambda value: isinstance(value, str) and pattern.fullmatch(value) is not None


def _is_date(value: _Value) -> bool:
    if not (isinstance(value, str) and _ISO_DATE.fullmatch(value)):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _is_agent_list(value: _Value) -> bool:
    return (
        isinstance(value, tuple)
        and all(valid_agent_id(agent) for agent in value)
        and len(set(value)) == len(value)
    )


def _is_plain(value: _Value) -> bool:
    return isinstance(value, bool | Decimal) or (
        isinstance(value, str) and _PLAIN.fullmatch(value) is not None
    )


class _Shape(NamedTuple):
    names: Callable[[str], bool]  # which names have this shape
    accepts: Callable[[_Value], bool]
    says: str  # what a value of the shape is, for the message


# The shape of each Terraform value. The first row whose names match a name decides; the last row
# matches every name. A task that adds a variable with a shape of its own adds a row here.
_TFVARS_SHAPES: tuple[_Shape, ...] = (
    _Shape(lambda name: name == "org_id", _string_of(_ORG_ID), "a string of digits"),
    _Shape(
        lambda name: name == "billing_account",
        _string_of(_BILLING_ACCOUNT),
        "a billing account id (XXXXXX-XXXXXX-XXXXXX, of 0 to 9 and A to F)",
    ),
    _Shape(
        lambda name: name.endswith("_project"),
        _string_of(PROJECT_ID_RE),
        f"a project id ({PROJECT_ID_TEXT})",
    ),
    _Shape(
        lambda name: name == "alert_email",
        lambda value: isinstance(value, str) and is_address(value),
        "an email address (local@domain, in lower case)",
    ),
    _Shape(
        lambda name: name == "budget_currency", lambda value: value in ("EUR", "USD"), "EUR or USD"
    ),
    _Shape(
        lambda name: name.startswith("budget_") and name.endswith("_amount"),
        lambda value: isinstance(value, Decimal) and value > 0,
        "a number above 0",
    ),
    _Shape(
        lambda name: name.startswith("credit_") and name.endswith("_date"),
        _is_date,
        "a date, YYYY-MM-DD",
    ),
    _Shape(lambda name: name == "region", lambda value: value == "europe-west4", "europe-west4"),
    _Shape(
        lambda name: name == "agents",
        _is_agent_list,
        "a list of distinct agent ids (validator-spec 3.3)",
    ),
    _Shape(lambda name: True, _is_plain, "a string without spaces, a number, true or false"),
)


def _shape_problem(item: _Assignment) -> str | None:
    shape = next(shape for shape in _TFVARS_SHAPES if shape.names(item.name))
    return None if shape.accepts(item.value) else f"{item.name} must be {shape.says}"


_DECLARATION = re.compile(r'^variable[ \t]+"([A-Za-z_][A-Za-z0-9_-]*)"', re.MULTILINE)


def _declared(variables: Path) -> frozenset[str] | None:
    """The names of the variables that `variables` declares; None when there is no such file."""
    try:
        text = variables.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return frozenset(_DECLARATION.findall(text))


def _declared_in(variables: bytes | None) -> frozenset[str] | None:
    """The names of the variables that the bytes of a variables.tf declare; None without them."""
    if variables is None:
        return None
    return frozenset(_DECLARATION.findall(variables.decode("utf-8")))


def _check_tfvars(text: str, where: str, declared: frozenset[str] | None) -> list[Problem]:
    """The problems of Terraform values, against the names of the variables that are declared."""
    assignments, stopped_at = _assignments(text)
    problems = [] if stopped_at is None else [Problem("C-SYNTAX", where, stopped_at, _NOT_PLAIN)]
    if declared is None:
        text = "no variables.tf next to this file, so its names cannot be checked"
        problems.append(Problem("C-NO-VARIABLES", where, None, text))
    seen: set[str] = set()
    for item in assignments:
        if item.name in seen:
            problems.append(Problem("C-SYNTAX", where, item.line, "sets a name a second time"))
        elif secret_like(item.name):
            problems.append(Problem("C-SECRET-NAME", where, item.line, _SECRET_NAME))
        elif declared is None:
            pass  # C-NO-VARIABLES says it
        elif item.name not in declared:
            text = "a name that variables.tf does not declare"
            problems.append(Problem("C-UNKNOWN-KEY", where, item.line, text))
        elif (says := _shape_problem(item)) is not None:
            problems.append(Problem("C-SHAPE", where, item.line, says))
        seen.add(item.name)
    return problems


# --- a file, and the command


def read_tfvars(path: Path) -> dict[str, _Value]:
    """The values of a Terraform values file, for a tool that compares against them.

    The file is read only when the guard finds no problem in it; otherwise ValueError names the
    codes of the problems and their lines, never a value.
    """
    problems = check_file(path)
    if problems:
        found = ", ".join(f"{problem.code} line {problem.line}" for problem in problems)
        raise ValueError(f"{_ascii(str(path))} does not pass aiven-check-config: {found}")
    assignments, _ = _assignments(path.read_text(encoding="ascii"))
    return {item.name: item.value for item in assignments}


def _kind(name: str) -> str | None:
    if name.endswith((".yaml", ".yml")):
        return "platform"
    if name.endswith((".tfvars", ".tfvars.example")):
        return "tfvars"
    return None


# Plain ASCII text: printable ASCII, tabs, and line ends (LF, or CR LF). A control character can hide
# text from someone who reads the file in a terminal, and YAML reads a lone CR as a line end, which
# the scan and the line numbers here do not.
_NOT_PLAIN_TEXT = re.compile(rb"[^\t\n\r -~]|\r(?!\n)")


def check_file(path: Path) -> list[Problem]:
    """Every problem of one file, in the order of their lines (those of the whole file first)."""
    where = str(path)
    kind = _kind(path.name)
    if kind is None:
        text = (
            "is neither platform values (.yaml, .yml) "
            "nor Terraform values (.tfvars, .tfvars.example)"
        )
        return [Problem("C-FILE-KIND", where, None, text)]
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        return [Problem("C-READ", where, None, f"cannot be read ({type(error).__name__})")]
    declared = partial(_declared, path.parent / "variables.tf")
    return _check_data(data, where, kind == "platform", declared)


def _check_data(
    data: bytes, where: str, platform: bool, declared: Callable[[], frozenset[str] | None]
) -> list[Problem]:
    """Every problem of the bytes of a file (check_file). `declared` gives the names that the
    variables.tf next to Terraform values declares, None when there is none; it is only asked for
    Terraform values that get as far as their names."""
    if len(data) > MAX_FILE_BYTES:
        return [Problem("C-SIZE", where, None, "is larger than 64 KiB, and was not read")]
    text = data.decode("utf-8", errors="replace")
    hits = scan(text)
    problems = [Problem("C-SECRET", where, hit.line, _secret_text(hit.kind)) for hit in hits]
    if (odd := _NOT_PLAIN_TEXT.search(data)) is not None:
        line = data.count(b"\n", 0, odd.start()) + 1
        says = "is not plain ASCII text from this line on (printable ASCII, tabs and line ends)"
        problems.append(Problem("C-ENCODING", where, line, says))
    elif platform:
        problems += _check_platform(text, where, {hit.kind for hit in hits})
    else:
        problems += _check_tfvars(text, where, declared())
    return sorted(dict.fromkeys(problems), key=lambda problem: problem.line or 0)


# --- the staged files (the pre-commit hook)


def _git(*args: str) -> bytes:
    """What `git` prints with these arguments, in the current folder and the environment as it is.

    A hook gets its index from that environment: `git commit -a` and `git commit <file>` hand it
    an index of their own in GIT_INDEX_FILE.
    """
    command = ["git", *args]
    return subprocess.run(command, capture_output=True, check=True, timeout=GIT_TIMEOUT_S).stdout


def _index(names: Sequence[str]) -> dict[str, bytes]:
    """The bytes of each of `names` (paths from the top of the work tree) that the index holds.

    It works from any folder of the work tree: the paths are taken from the top (`:(top)`), and
    `:<path>` names the file in the index by its path from the top.
    """
    specs = [f":(top,literal){name}" for name in names]
    listed = _git("ls-files", "-z", "--cached", "--full-name", "--", *specs)
    held = dict.fromkeys(os.fsdecode(name) for name in listed.split(b"\0") if name)
    return {name: _git("cat-file", "blob", f":{name}") for name in held}


def _staged_checks() -> list[tuple[str, Callable[[], list[Problem]]]]:
    """A check of each default file that the index holds, as the index holds it: what the next
    commit holds. Terraform values are checked against the variables.tf of the index."""
    variables = {
        name: posixpath.join(posixpath.dirname(name), "variables.tf") for name in DEFAULT_FILES
    }
    blobs = _index([*DEFAULT_FILES, *variables.values()])
    return [
        (
            name,
            partial(
                _check_data,
                blobs[name],
                name,
                _kind(name) == "platform",
                partial(_declared_in, blobs.get(variables[name])),
            ),
        )
        for name in DEFAULT_FILES
        if name in blobs
    ]


def _report(checks: list[tuple[str, Callable[[], list[Problem]]]], checked: str) -> int:
    """Run each check, print the problems and one line on stderr, and give the exit code."""
    problems: list[Problem] = []
    crashed = False
    for where, check in checks:
        try:
            problems += [replace(problem, path=where) for problem in check()]
        except Exception as error:
            # The message of the error, and its traceback, can quote the file; its class cannot.
            crashed = True
            text = f"the check crashed ({type(error).__name__})"
            problems.append(Problem("C-INTERNAL", where, None, text))
    for problem in problems:
        print(problem)
    print(f"{checked}: " + ", ".join(_ascii(where) for where, _ in checks), file=sys.stderr)
    if crashed:
        return EXIT_CRASH
    return EXIT_PROBLEMS if problems else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and give the exit code: 0, 1 or 2 (see the module)."""
    parser = argparse.ArgumentParser(
        prog="aiven-check-config",
        description="Refuse anything but IDs and addresses in the platform and Terraform values.",
    )
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help=f"the files to check (default: each of {', '.join(DEFAULT_FILES)} that exists)",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="check the default files as the Git index holds them: what the next commit holds "
        "(the pre-commit hook in .githooks runs this)",
    )
    args = parser.parse_args(argv)
    if args.staged:
        if args.files:
            parser.error("--staged checks the default files as the index holds them: give no files")
        try:
            checks = _staged_checks()
        except (OSError, subprocess.SubprocessError) as error:
            says = "--staged needs Git, in a Git work tree"
            print(f"cannot read the Git index ({type(error).__name__}): {says}", file=sys.stderr)
            return EXIT_CRASH
        if not checks:
            print(
                f"nothing to check: the index holds none of {', '.join(DEFAULT_FILES)}",
                file=sys.stderr,
            )
            return EXIT_OK
        return _report(checks, "checked (staged)")
    paths = list(dict.fromkeys(args.files)) or [
        Path(name) for name in DEFAULT_FILES if os.path.lexists(name)
    ]
    if not paths:
        print(f"nothing to check: none of {', '.join(DEFAULT_FILES)} exists", file=sys.stderr)
        return EXIT_OK
    return _report([(str(path), partial(check_file, path)) for path in paths], "checked")
