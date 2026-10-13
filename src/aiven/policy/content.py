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
`safe_text` is more suspicious than `scan`: it also hides a value in which a kind matches with no
word boundary at all, because hiding a value costs nothing and showing one costs a leak.
"""

import re
import string
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from types import MappingProxyType
from typing import NamedTuple

from aiven.policy.chars import is_hidden

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

# A token, an IBAN, a card number or a BSN starts where no letter or digit stands in front of it.
# Without this, any word that ends in a prefix is a token: `risk-adjusted-return-calculation`
# holds an `sk-` key.
_LEFT = r"(?<![A-Za-z0-9])"


def _first_valid_end(
    line: str,
    begin: int,
    body: frozenset[str],
    separators: str,
    lengths: range,
    is_valid: Callable[[str], bool],
    *,
    needs_end_boundary: bool,
) -> int | None:
    """Where the shortest valid candidate that starts at `begin` ends, or None.

    A candidate is made of `body` characters, with a single separator allowed between two of
    them. It has a number of body characters in `lengths`, and no letter or digit follows it,
    unless `needs_end_boundary` is false. The walk covers at most `lengths[-1]` characters and
    their separators, so it takes constant time.
    """
    kept: list[str] = []
    position, size = begin, len(line)
    while position < size:
        char = line[position]
        if char in body:
            kept.append(char)
            position += 1
            followed_by_alnum = position < size and line[position] in _ALNUM
            if (
                len(kept) in lengths
                and not (needs_end_boundary and followed_by_alnum)
                and is_valid("".join(kept))
            ):
                return position
            if len(kept) >= lengths[-1]:
                return None
        elif char in separators and position + 1 < size and line[position + 1] in body:
            position += 1
        else:
            return None
    return None


class _Grouped(NamedTuple):
    """What it takes to find a value that may be written in groups: an IBAN, or a card number."""

    start: str  # a pattern for the first characters of a candidate
    body: frozenset[str]  # the characters a candidate is made of
    separators: str  # what may stand once between two of them
    lengths: range  # how many of them a candidate has
    is_valid: Callable[[str], bool]


# An IBAN starts with two letters and two digits, and has 15 to 34 letters and digits, with
# single spaces allowed between them.
_IBAN = _Grouped(r"[A-Za-z]{2}[0-9]{2}", _ALNUM, " ", range(15, 35), _is_iban)
# A card number has 13 to 19 digits, with single spaces or dashes allowed between them.
_CARD_NUMBER = _Grouped(r"[0-9]", _DIGITS, " -", range(13, 20), _is_card_number)


def _grouped_finder(kind: _Grouped, *, anywhere: bool = False) -> Finder:
    """A finder for values that may be written in groups: an IBAN, or a card number.

    A candidate starts where no letter or digit stands in front of it, and no letter or digit
    follows its end. With `anywhere` it needs neither: it may start and end inside a word. That is
    for the guard (see `safe_text`). A hit that starts inside an earlier hit overlaps it, and
    `_hits_in_line` drops it.
    """
    start_pattern = re.compile(f"(?={kind.start})" if anywhere else _LEFT + kind.start)

    def find(line: str) -> Iterator[Span]:
        for match in start_pattern.finditer(line):
            end = _first_valid_end(
                line,
                match.start(),
                kind.body,
                kind.separators,
                kind.lengths,
                kind.is_valid,
                needs_end_boundary=not anywhere,
            )
            if end is not None:
                yield match.start(), end

    return find


_BSN_DIGITS = r"[0-9]{9}"
_BSN = re.compile(_LEFT + _BSN_DIGITS + r"(?![A-Za-z0-9])")
_BSN_ANYWHERE = re.compile(f"(?=({_BSN_DIGITS}))")  # a window of nine, in a longer run too


def _bsn_finder(line: str) -> Iterator[Span]:
    for found in _BSN.finditer(line):
        if _is_bsn(found.group()):
            yield found.span()


def _bsn_finder_anywhere(line: str) -> Iterator[Span]:
    """Nine digits that pass the eleven-test, wherever they stand: for the guard."""
    for found in _BSN_ANYWHERE.finditer(line):
        if _is_bsn(found.group(1)):
            yield found.span(1)


# --- the kinds, most specific first

# The bodies of the token patterns. `scan` puts `_LEFT` in front of most of them; the guard
# (see `safe_text`) uses them as they are, so a token in the middle of a word is found too.

# The PGP armor header ends in `KEY BLOCK` instead of `KEY`.
_PRIVATE_KEY = r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
_SERVICE_ACCOUNT_KEY = r'"private_key"'
_GOOGLE_API_KEY = r"AIza[0-9A-Za-z_-]{35}"
_OAUTH_TOKEN = r"(?:ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{20,})"
_GITHUB_TOKEN = r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"
_SLACK_TOKEN = r"xox[abposr]-[A-Za-z0-9-]{10,}"
_ANTHROPIC_API_KEY = r"sk-ant-[A-Za-z0-9_-]{20,}"
_OPENAI_API_KEY = r"sk-[A-Za-z0-9_-]{20,}"
_AWS_ACCESS_KEY = r"(?:AKIA|ASIA)[0-9A-Z]{16}"
# The first segment of a JWT is short, so it is capped. Without the cap, `eyJ_` repeated inside
# one long run is retried from every `eyJ`, each time to the end of the run, and the scan
# takes quadratic time.
_JWT = r"eyJ[A-Za-z0-9_-]{5,300}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"

# The password pattern: a keyword, then an optional closing quote, `:` or `=` (so not
# max_tokens), an optional opening quote and a value of at least four characters. `scan` asks
# that the keyword does not directly follow a letter or digit (so not mytoken), but it may follow
# an identifier prefix that ends in `_`, `-` or `.` (db_password, x-api-key, aws.secret).
_ASSIGNMENT = (
    r"(?:password|secret|token|api_key|api-key|apikey|client_secret|client-secret)"
    r"""["']? *[:=] *["']?[^\s"']{4,}"""
)

# Each kind with the finding code it gets. When two hits overlap on a line, the kind that comes
# first in this list wins, so a known token keeps its own name even after `token:`, and an
# Anthropic key is not also an OpenAI key.
_KINDS: tuple[tuple[str, str, Finder], ...] = (
    ("private key", "E-SECRET", _regex(_PRIVATE_KEY)),
    ("service account key", "E-SECRET", _regex(_SERVICE_ACCOUNT_KEY)),
    ("Google API key", "E-SECRET", _regex(_LEFT + _GOOGLE_API_KEY)),
    ("OAuth token", "E-SECRET", _regex(_LEFT + _OAUTH_TOKEN)),
    ("GitHub token", "E-SECRET", _regex(_LEFT + _GITHUB_TOKEN)),
    ("Slack token", "E-SECRET", _regex(_LEFT + _SLACK_TOKEN)),
    ("Anthropic API key", "E-SECRET", _regex(_LEFT + _ANTHROPIC_API_KEY)),
    ("OpenAI API key", "E-SECRET", _regex(_LEFT + _OPENAI_API_KEY)),
    ("AWS access key", "E-SECRET", _regex(_LEFT + _AWS_ACCESS_KEY)),
    ("JWT", "E-SECRET", _regex(_LEFT + _JWT)),
    ("password or secret value", "E-SECRET", _regex(_LEFT + _ASSIGNMENT, re.IGNORECASE)),
    ("IBAN", "E-BANK-DETAILS", _grouped_finder(_IBAN)),
    ("card number", "E-BANK-DETAILS", _grouped_finder(_CARD_NUMBER)),
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


def _must_be_escaped(char: str) -> bool:
    return not char.isprintable() or is_hidden(char)


def escape_unprintable(text: str) -> str:
    """`text` with every character that must not be shown as it is written out as an escape.

    That is each character that is not printable, and each one in the hidden set of the spec
    (section 3.1), which Python counts as printable in part: the fillers, the variation selectors
    and the like. The escape is a backslash and `u` with four hex digits, or a backslash and `U`
    with eight above U+FFFF. So a newline, a bidi control, a terminal escape or an invisible
    letter in text from a file cannot start another line of output, reorder it or hide anything
    from the reader.
    """
    if text.isascii() and text.isprintable():
        return text  # printable ASCII holds no hidden character
    return "".join(_escape(char) if _must_be_escaped(char) else char for char in text)


# What the guard looks for. `scan` asks for a word boundary in front of a token, an IBAN, a card
# number or a BSN, and behind the last three. That keeps the content check quiet on prose and on
# base64, but it also lets a credential glued to the word in front of it go by: `REPLACE_ME` and
# a key, written without an underscore, are one word. The guard asks again with no boundary at
# all. It uses the same patterns and the same checksums, so a random identifier is not hidden
# just for looking like one.
_ANYWHERE: tuple[Finder, ...] = (
    _regex(
        "|".join(
            (
                _PRIVATE_KEY,
                _SERVICE_ACCOUNT_KEY,
                _GOOGLE_API_KEY,
                _OAUTH_TOKEN,
                _GITHUB_TOKEN,
                _SLACK_TOKEN,
                _ANTHROPIC_API_KEY,
                _OPENAI_API_KEY,
                _AWS_ACCESS_KEY,
                _JWT,
            )
        )
    ),
    _regex(_ASSIGNMENT, re.IGNORECASE),
    _bsn_finder_anywhere,
    _grouped_finder(_IBAN, anywhere=True),
    _grouped_finder(_CARD_NUMBER, anywhere=True),
)


def _holds_sensitive_text(value: str) -> bool:
    """Whether any kind of `scan` matches anywhere in `value`, with no boundary conditions.

    A token or the JWT may start or end inside a word, and the keyword of a password assignment may
    follow any character. An IBAN may start wherever two letters and two digits do, and end after
    any of 15 to 34 letters and digits. A card number is any 13 to 19 digits of a run, with the
    same single separators; a BSN is any nine digits of a run. The checksums are those of `scan`.

    The time is in proportion to the length of `value`: a candidate is at most 34 characters long,
    plus its separators, and the first segment of a JWT is capped. Every line of `value` is
    searched at once, which makes no difference: no pattern matches across a newline.
    """
    return any(next(find(value), None) is not None for find in _ANYWHERE)


def safe_text(value: str) -> str:
    """`value`, text from a file, as a finding may show it.

    A value that holds a credential, a bank detail or an ID number is replaced by `[hidden]`,
    whatever else it holds, so a finding never repeats one. A value holds one when `scan` finds
    anything in it, and also when any kind matches with no word boundary at all (see
    `_holds_sensitive_text`): a credential glued to the letters or digits in front of it or behind
    it is hidden too, and so is a run of digits in which a window passes a checksum. That hides a
    few harmless values as well, a long hex digest or number most often; hiding costs nothing.
    Anything else is escaped with `escape_unprintable` and cut to 200 characters, ending in an
    ellipsis.

    A value that is split up, spelled out or otherwise disguised (spec section 8) is not
    recognised and would be shown.
    """
    if scan(value) or _holds_sensitive_text(value):
        return _HIDDEN
    shown = escape_unprintable(value)
    if len(shown) > _SHOWN:
        shown = shown[: _SHOWN - 1] + _CUT
    return shown
