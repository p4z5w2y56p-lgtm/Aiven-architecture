"""Content safety (validator-spec section 3.8): credentials, bank details and ID numbers.

`scan` looks for them line by line and reports the kind and the place, never the value: a finding
must not become a second copy of what it warns about. The validator turns the hits into E-SECRET,
E-BANK-DETAILS and E-ID-NUMBER (`KIND_CODES` says which), and the gateway reuses `scan` on what
agents write (M4, M6).

The patterns are heuristics for the usual accidents. A value that is split up, spelled out or put
in an image is not found (spec section 8), and an innocent number can be flagged by mistake.
Letters and digits mean ASCII ones throughout. Every pattern takes linear time, because the
gateway scans text that an agent may have been tricked into writing.

`safe_text` and `escape_unprintable` are the single place where text from a file may enter a
message. `Finding` runs every param and its path through them, so no check has to remember to.
"""

import re
import string
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from types import MappingProxyType

# A match as (start, end) in the line, end exclusive.
Span = tuple[int, int]
Finder = Callable[[str], Iterator[Span]]

_ALNUM = frozenset(string.ascii_letters + string.digits)
_DIGITS = frozenset(string.digits)


@dataclass(frozen=True)
class ContentHit:
    """Where something sensitive was found. It has no field for the value, on purpose."""

    kind: str
    line: int
    column: int


def _regex(pattern: str, flags: int = 0) -> Finder:
    compiled = re.compile(pattern, flags)

    def find(line: str) -> Iterator[Span]:
        return (found.span() for found in compiled.finditer(line))

    return find


# --- bank details and ID numbers: checksums


def _is_iban(candidate: str) -> bool:
    """Mod 97: the first four characters go to the end, A to Z read as 10 to 35, remainder 1.

    `int(char, 36)` reads a letter in either case, so lower case needs no separate step.
    """
    rearranged = candidate[4:] + candidate[:4]
    return int("".join(str(int(char, 36)) for char in rearranged)) % 97 == 1


def _is_card_number(digits: str) -> bool:
    """The Luhn check: double every second digit from the right, and the sum ends in 0."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char) * (2 if index % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def _is_bsn(digits: str) -> bool:
    """The eleven-test: 9*d1 + 8*d2 + ... + 2*d8 - d9 is a multiple of 11.

    Nine zeros pass it too, so they are refused here.
    """
    if digits == "0" * 9:
        return False
    weights = (9, 8, 7, 6, 5, 4, 3, 2, -1)
    return sum(w * int(d) for w, d in zip(weights, digits, strict=True)) % 11 == 0


# --- bank details and ID numbers: finding the candidates


def _first_valid_end(
    line: str,
    begin: int,
    body: frozenset[str],
    separators: str,
    lengths: range,
    is_valid: Callable[[str], bool],
) -> int | None:
    """Where the shortest valid candidate that starts at `begin` ends, or None.

    A candidate is made of `body` characters, with a single separator allowed between two of
    them. It has a number of body characters in `lengths`, and no letter or digit follows it. The
    walk covers at most `lengths[-1]` characters and their separators, so it takes constant time.
    """
    kept: list[str] = []
    position, size = begin, len(line)
    while position < size:
        char = line[position]
        if char in body:
            kept.append(char)
            position += 1
            followed_by_alnum = position < size and line[position] in _ALNUM
            if len(kept) in lengths and not followed_by_alnum and is_valid("".join(kept)):
                return position
            if len(kept) >= lengths[-1]:
                return None
        elif char in separators and position + 1 < size and line[position + 1] in body:
            position += 1
        else:
            return None
    return None


def _grouped_finder(
    start: str,
    body: frozenset[str],
    separators: str,
    lengths: range,
    is_valid: Callable[[str], bool],
) -> Finder:
    """A finder for values that may be written in groups: an IBAN, or a card number.

    `start` matches where a candidate may begin. A hit that starts inside an earlier hit overlaps
    it, and `_hits_in_line` drops it.
    """
    start_pattern = re.compile(start)

    def find(line: str) -> Iterator[Span]:
        for match in start_pattern.finditer(line):
            end = _first_valid_end(line, match.start(), body, separators, lengths, is_valid)
            if end is not None:
                yield match.start(), end

    return find


_BSN = re.compile(r"(?<![A-Za-z0-9])[0-9]{9}(?![A-Za-z0-9])")


def _bsn_finder(line: str) -> Iterator[Span]:
    for found in _BSN.finditer(line):
        if _is_bsn(found.group()):
            yield found.span()


# --- the kinds, most specific first

# A token starts where no letter or digit stands in front of it. Without this, any word that
# ends in the prefix is a token: `risk-adjusted-return-calculation` holds an `sk-` key.
_LEFT = r"(?<![A-Za-z0-9])"

# The password pattern: a keyword that does not directly follow a letter or digit (so not
# mytoken), but may follow an identifier prefix that ends in `_`, `-` or `.` (db_password,
# x-api-key, aws.secret). Then an optional closing quote, `:` or `=` (so not max_tokens), an
# optional opening quote and a value of at least four characters.
_PASSWORD = (
    _LEFT
    + r"(?:password|secret|token|api_key|api-key|apikey|client_secret|client-secret)"
    + r"""["']? *[:=] *["']?[^\s"']{4,}"""
)

# Each kind with the finding code it gets. When two hits overlap on a line, the kind that comes
# first in this list wins, so a known token keeps its own name even after `token:`, and an
# Anthropic key is not also an OpenAI key.
_KINDS: tuple[tuple[str, str, Finder], ...] = (
    # The PGP armor header ends in `KEY BLOCK` instead of `KEY`.
    ("private key", "E-SECRET", _regex(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")),
    ("service account key", "E-SECRET", _regex(r'"private_key"')),
    ("Google API key", "E-SECRET", _regex(_LEFT + r"AIza[0-9A-Za-z_-]{35}")),
    (
        "OAuth token",
        "E-SECRET",
        _regex(_LEFT + r"(?:ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{20,})"),
    ),
    (
        "GitHub token",
        "E-SECRET",
        _regex(_LEFT + r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    ),
    ("Slack token", "E-SECRET", _regex(_LEFT + r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Anthropic API key", "E-SECRET", _regex(_LEFT + r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", "E-SECRET", _regex(_LEFT + r"sk-[A-Za-z0-9_-]{20,}")),
    ("AWS access key", "E-SECRET", _regex(_LEFT + r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    # The first segment of a JWT is short, so it is capped. Without the cap, `eyJ_` repeated inside
    # one long run is retried from every `eyJ`, each time to the end of the run, and the scan
    # takes quadratic time.
    (
        "JWT",
        "E-SECRET",
        _regex(_LEFT + r"eyJ[A-Za-z0-9_-]{5,300}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    ),
    ("password or secret value", "E-SECRET", _regex(_PASSWORD, re.IGNORECASE)),
    # An IBAN starts at the start of a word with two letters and two digits, and has 15 to 34
    # letters and digits, with single spaces allowed between them.
    (
        "IBAN",
        "E-BANK-DETAILS",
        _grouped_finder(
            r"(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}", _ALNUM, " ", range(15, 35), _is_iban
        ),
    ),
    # A card number has 13 to 19 digits, with single spaces or dashes allowed between them.
    (
        "card number",
        "E-BANK-DETAILS",
        _grouped_finder(r"(?<![A-Za-z0-9])[0-9]", _DIGITS, " -", range(13, 20), _is_card_number),
    ),
    ("BSN", "E-ID-NUMBER", _bsn_finder),
)

# The finding code of each kind, in the same order. Read only: the gateway shares it.
KIND_CODES = MappingProxyType({kind: code for kind, code, _ in _KINDS})


def scan(text: str) -> list[ContentHit]:
    """Every credential, bank detail and ID number in `text`, by line and column.

    Lines are separated by LF only, and a column counts characters. Hits never overlap: where two
    would, only the one that comes first in `KIND_CODES` is kept. The hits come in text order.
    """
    hits: list[ContentHit] = []
    for number, line in enumerate(text.split("\n"), start=1):
        hits.extend(ContentHit(kind, number, column) for column, kind in _hits_in_line(line))
    return hits


def _hits_in_line(line: str) -> list[tuple[int, str]]:
    """(column, kind) for each kept hit in a line, left to right."""
    covered = bytearray(len(line))  # 1 where a hit that was kept already stands
    hits: list[tuple[int, str]] = []
    for kind, _, find in _KINDS:
        for start, end in find(line):
            if covered.find(1, start, end) == -1:
                covered[start:end] = b"\x01" * (end - start)
                hits.append((start + 1, kind))
    return sorted(hits)


# --- the single entry for file text into a message

# What a finding shows of a value, at most; and what it shows in place of a sensitive one.
_SHOWN = 200
_HIDDEN = "[hidden]"
_CUT = "\N{HORIZONTAL ELLIPSIS}"


def _escape(char: str) -> str:
    code = ord(char)
    if code <= 0xFFFF:
        return "\\u" + format(code, "04x")
    return "\\U" + format(code, "08x")


def escape_unprintable(text: str) -> str:
    """`text` with every character that is not printable written out as an escape.

    The escape is a backslash and `u` with four hex digits, or a backslash and `U` with eight
    above U+FFFF. So a newline, a bidi control or a terminal escape in text from a file cannot
    start another line of output, reorder it or hide anything from the reader.
    """
    if text.isprintable():
        return text
    return "".join(char if char.isprintable() else _escape(char) for char in text)


def safe_text(value: str) -> str:
    """`value`, text from a file, as a finding may show it.

    A value in which `scan` finds anything is replaced by `[hidden]`, whatever else it holds, so a
    finding never repeats a credential, a bank detail or an ID number that the scan recognises.
    Anything else is escaped with `escape_unprintable` and cut to 200 characters, ending in an
    ellipsis.

    The guard sees what `scan` sees. A credential glued onto the letters or digits in front of it,
    or disguised in some other way (spec section 8), is not recognised and would be shown.
    """
    if scan(value):
        return _HIDDEN
    shown = escape_unprintable(value)
    if len(shown) > _SHOWN:
        shown = shown[: _SHOWN - 1] + _CUT
    return shown
