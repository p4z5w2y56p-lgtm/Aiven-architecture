"""The body checks (validator-spec section 3.7): the Markdown that the signer reads.

The signer signs the body, and the gateway enforces the front matter. These checks make sure that
the body says what the front matter does, that nothing in it is hidden from the reader, and that it
has the shape the signer expects: a title, five sections in order, and a reason for each tool.

`check_body` works on the tokens of the body (markdown.py), and on its lines where the spec asks for
text. Each finding stands on a line of the file: the rows of the body plus `first_line`.

What needs the policy: E-BODY-TITLE, E-BODY-TOOL-UNEXPLAINED, E-BODY-TOOL-EXTRA and E-BODY-DRIFT.
Without one (no `p`) only the checks of the shape and of what the reader sees run. `title` and
`drift` switch two of them off, for the reasons of the callers (validate.py): an agent that is not a
valid id is E-AGENT-ID and not also a wrong title (ruling R28), and drift is judged only when the
front matter has no error, because a render from an invalid front matter is noise (ruling R29).
Drift is judged only when the sections are right as well: where a section ends is not known when
E-BODY-SECTIONS has fired, and one defect gets one code (ruling R58).

E-BODY-SECTIONS is one finding for the `##` headings, and one for each other heading that is out of
place (a second title, a heading of level 3 to 6 outside the first three sections). The finding for
the `##` headings stands on the first one that is not a section of the five names. If there is none
and a section is missing, it stands on the first line of the body, and else on the first heading
that is not where the five sections have it. A heading is a heading wherever it stands, in a quote
or a list too, but a section is a `##` at the top level of the document (ruling R64): one in a
quote or a list is never one of the five, and it is the one that is reported. The renderer
(`rewrite`) goes by the same headings, so the check and the renderer cannot differ about a section.

E-BODY-HTML and E-BODY-LINK also cover text that the reader never sees, because a parser keeps
it from them: a link reference definition shows nothing, and markdown-it drops what is nested 20
levels deep (a quote is one level, a list and its item are two, so 10 lists inside each other do
it). From a list that deep it drops all that follows in the document. A line of the body that no
block of the parser holds is such text. The definitions are links, and the rest is reported as
HTML: "a policy may not contain text the reader cannot see".

A URL is found in the lines of the body and not in its tokens, so one in a code span or a code block
counts as well (ruling R46): a policy must be complete on its own.

The row of an inline token is counted from the start of its paragraph, over the breaks and the
tags that go over lines. A code span or a link title that goes over lines hides its line breaks from
the parser, so a token behind one is reported a line early.

Findings carry text of the file in their params, and `Finding` cleans them. Nothing else here puts
text of the file in a message, a log or a repr.
"""

import re
from collections.abc import Generator, Iterator
from itertools import zip_longest
from pathlib import Path

from markdown_it.rules_block.table import escapedSplit
from markdown_it.token import Token

from aiven.policy.catalog import Catalog
from aiven.policy.chars import is_hidden
from aiven.policy.constants import FREE_SECTIONS, GENERATED_SECTIONS, MIN_SECTION_CHARS, SECTIONS
from aiven.policy.findings import Finding
from aiven.policy.markdown import Heading, find, headings, parse, sections
from aiven.policy.model import Policy
from aiven.policy.render import render_generated
from aiven.policy.tools import tool_problem

# The blocks of the parser that hold lines of text. Lines that none of them holds are not shown.
_LEAVES = frozenset(
    {"paragraph_open", "heading_open", "fence", "code_block", "html_block", "hr", "table_open"}
)
_BREAKS = ("softbreak", "hardbreak")

# Printable ASCII has no hidden character, so only the rest is looked at.
_NOT_PLAIN = re.compile(r"[^\x20-\x7e]")

# What may stand in front of the text of a line: the marks of quotes and lists.
_MARKS = r"(?:[ \t>]|[-+*](?=[ \t]|$)|[0-9]{1,9}[.)](?=[ \t]|$))*"
_ONLY_MARKS = re.compile(_MARKS)
_DEFINITION = re.compile(_MARKS + r"\[")

# `scheme://`, `www.` and `://www.` (which is one URL). A scheme is a letter and then letters,
# digits, `+`, `.` and `-`; searching for the scheme in front of every `://` and not the other way
# round keeps a long word from costing time that grows with the square of its length.
_URL = re.compile(r"://(?:www\.)?|www\.", re.IGNORECASE)
_SCHEME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.-")
_LETTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def check_body(
    body: str,
    first_line: int,
    p: Policy | None,
    catalog: Catalog,
    path: Path | str = "",
    *,
    title: bool = True,
    drift: bool = True,
) -> list[Finding]:
    """The findings of the body, which starts on file line `first_line`, in no particular order.

    `p` is the policy of the front matter, None if there is none. `path` only names the file in
    the findings, as it does for `build_policy`. See the module docstring for `title` and `drift`.
    """
    report = _Report(str(path), first_line)
    lines = body.split("\n")
    tokens = parse(body)
    found = headings(tokens)
    wrong_sections = _sections(report, lines, found)
    findings = [
        *wrong_sections,
        *_empty(report, tokens, found),
        *_markup(report, tokens, lines),
    ]
    if p is not None:
        if title:
            findings += _title(report, lines, p.agent)
        findings += _tools(report, tokens, found, p, catalog)
        if drift and not wrong_sections:  # where a section ends is not known otherwise (ruling R58)
            findings += _drift(report, lines, found, p, catalog)
    return findings


class _Report:
    """Makes the findings of one body: it knows the file, and the line where the body starts."""

    def __init__(self, path: str, first_line: int) -> None:
        self.path = path
        self.first_line = first_line

    def at(self, code: str, row: int, **params: str) -> Finding:
        return Finding(code, "error", self.path, self.first_line + row, params=params)


# --- E-BODY-TITLE and E-BODY-SECTIONS


def _first_text_row(lines: list[str]) -> int | None:
    return next((row for row, line in enumerate(lines) if line.strip()), None)


def _title(report: _Report, lines: list[str], agent: str) -> list[Finding]:
    """The first line that is not empty must be exactly `# <agent>`."""
    row = _first_text_row(lines)
    if row is not None and lines[row] == f"# {agent}":
        return []
    return [report.at("E-BODY-TITLE", row or 0, agent=agent)]


def _sections(report: _Report, lines: list[str], found: list[Heading]) -> list[Finding]:
    twos = [heading for heading in found if heading.level == 2]
    tops = sections(found)
    title_row = _first_text_row(lines)
    rows = [row] if (row := _misplaced(twos)) is not None else []
    rows += [h.row for h in found if h.level == 1 and h.row != title_row]
    rows += [h.row for h in found if h.level >= 3 and not _in_free_sections(h, tops)]
    names = ", ".join(heading.name for heading in twos)
    return [report.at("E-BODY-SECTIONS", row, found=names) for row in rows]


def _misplaced(twos: list[Heading]) -> int | None:
    """The row to report for the `##` headings. None if they are the five sections in order.

    A `##` that is not at the top level of the document (in a quote or a list) is no section,
    whatever its name, and it is the one that is reported (ruling R64).
    """
    tops = [heading for heading in twos if heading.top]
    names = [heading.name for heading in tops]
    unknown = next((h for h in twos if not h.top or h.name not in SECTIONS), None)
    if unknown is not None:
        return unknown.row
    if names == list(SECTIONS):
        return None
    if any(name not in names for name in SECTIONS):
        return 0  # a section is missing, and there is no heading to point at
    wrong = (h for i, h in enumerate(tops) if i >= len(SECTIONS) or h.name != SECTIONS[i])
    return next(wrong).row


def _in_free_sections(heading: Heading, tops: list[Heading]) -> bool:
    """Whether the heading stands in the first three sections: behind the first section heading,
    and in front of the fourth."""
    return bool(tops) and tops[0].row < heading.row and (len(tops) < 4 or heading.row < tops[3].row)


# --- E-BODY-EMPTY


def _section(tokens: list[Token], found: list[Heading], heading: Heading) -> list[Token]:
    """The tokens behind the heading of a section, up to the heading of the next one."""
    later = (other.index for other in sections(found) if other.index > heading.index)
    return tokens[heading.index + 3 : next(later, len(tokens))]  # the heading has three tokens


def _shown(text: str) -> str:
    """The text without the characters that the reader cannot see, written or made by references."""
    return _NOT_PLAIN.sub(lambda found: "" if is_hidden(found.group()) else found.group(), text)


def _plain(tokens: list[Token]) -> str:
    """The text of inline tokens that shows: text, code spans and soft breaks (as a space).

    Nothing else counts, and a character that the reader cannot see is not a character of text:
    twenty zero width spaces are not a sentence, and not a reason.
    """
    parts = []
    for token in tokens:
        if token.type in ("text", "code_inline"):
            parts.append(_shown(token.content))
        elif token.type == "softbreak":
            parts.append(" ")
    return "".join(parts)


def _empty(report: _Report, tokens: list[Token], found: list[Heading]) -> list[Finding]:
    """A free-text section with fewer than 20 characters of text (whitespace runs as one space)."""
    findings = []
    for name in FREE_SECTIONS:
        heading = find(found, name, top=True)
        if heading is None:
            continue
        inlines = [t for t in _section(tokens, found, heading) if t.type == "inline"]
        text = " ".join(" ".join(_plain(inline.children or []) for inline in inlines).split())
        if len(text) < MIN_SECTION_CHARS:
            findings.append(report.at("E-BODY-EMPTY", heading.row, section=name))
    return findings


# --- E-BODY-TOOL-UNEXPLAINED and E-BODY-TOOL-EXTRA


def _bullets(section: list[Token]) -> Iterator[tuple[int, str, bool]]:
    """(row, name, explains) of each list item whose paragraph starts with a code span.

    The item explains the tool of that name when the text behind the code span starts with a colon
    and has a reason after it. A list item of any depth counts, an ordered one too. A section can
    end inside an item, at a heading in it, and then the item has no paragraph to look at.
    """
    for index, token in enumerate(section):
        if token.type != "list_item_open" or not token.map:
            continue
        first = section[index + 1 : index + 3]
        if len(first) < 2 or first[0].type != "paragraph_open":
            continue
        children = first[1].children or []
        if children and children[0].type == "code_inline":
            rest = _plain(children[1:])
            yield token.map[0], children[0].content, rest.startswith(":") and bool(rest[1:].strip())


def _tools(
    report: _Report, tokens: list[Token], found: list[Heading], p: Policy, catalog: Catalog
) -> list[Finding]:
    """Why each tool has a bullet for each tool, and for no other.

    A tool entry that failed its own rules (or is a placeholder) is not a tool (ruling R33): the
    rules say what is wrong with it, and the body is not also called incomplete. Without the
    section there is nothing to judge, and E-BODY-SECTIONS says that it is not there.
    """
    why = find(found, "Why each tool", top=True)
    if why is None:
        return []
    bullets = list(_bullets(_section(tokens, found, why)))
    explained = {name for _, name, explains in bullets if explains}
    findings = [
        report.at("E-BODY-TOOL-UNEXPLAINED", why.row, tool=tool)
        for tool in p.tools
        if tool_problem(tool, catalog) is None and tool not in explained
    ]
    findings += [
        report.at("E-BODY-TOOL-EXTRA", row, tool=name)
        for row, name, _ in bullets
        if name not in p.tools
    ]
    return findings


# --- E-BODY-HTML and E-BODY-LINK


def _markup(report: _Report, tokens: list[Token], lines: list[str]) -> list[Finding]:
    findings = [
        report.at("E-BODY-HTML", token.map[0])
        for token in tokens
        if token.type == "html_block" and token.map
    ]
    written = set()  # the rows where a URL was found as it is written
    for row, line in enumerate(lines):
        urls = [report.at("E-BODY-LINK", row) for _ in _urls(line)]
        findings += urls
        if urls:
            written.add(row)
    for token in tokens:
        if token.type == "inline" and token.map:
            findings += _inline(report, token, written)
    return findings + _extra_cells(report, tokens, lines) + _hidden(report, tokens, lines)


def _inline(report: _Report, inline: Token, written: set[int]) -> list[Finding]:
    """The tags, links and images of a paragraph, and what its text is when it is rendered.

    The text that the reader gets is not the text that is written (a reference or an escape is
    decoded). So a character that a reference made and that is hidden is HTML (what is written is
    E-HIDDEN-CHAR's), and a URL in the rendered text is a link, also when markup or a code span
    cuts it in pieces. A row where a URL was found as it is written (`written`) has had its finding:
    the rendered text adds one more finding for a row, at most, and none to such a row.
    """
    findings = []
    shown: dict[int, list[str]] = {}
    for token, row in _walk(inline.children or [], inline.map[0]):
        if token.type == "html_inline":
            findings.append(report.at("E-BODY-HTML", row))
        elif token.type in ("link_open", "image"):
            findings.append(report.at("E-BODY-LINK", row))
        elif token.type == "text" and any(map(is_hidden, token.meta.get("entities", ""))):
            findings.append(report.at("E-BODY-HTML", row))
        if token.type in ("text", "code_inline"):
            shown.setdefault(row, []).append(_shown(token.content))
    for row, parts in shown.items():
        if row not in written and any(True for _ in _urls("".join(parts))):
            findings.append(report.at("E-BODY-LINK", row))
            written.add(row)
    return findings


def _walk(children: list[Token], row: int) -> Generator[tuple[Token, int], None, int]:
    """The tokens of a paragraph (and of the alt text of an image) with their rows.

    The row moves down at a break, and over the lines of a tag. It returns the row it ends on.
    """
    for child in children:
        yield child, row
        if child.type == "image":
            row = yield from _walk(child.children or [], row)
        elif child.type in _BREAKS:
            row += 1
        elif child.type == "html_inline":
            row += child.content.count("\n")
    return row


def _extra_cells(report: _Report, tokens: list[Token], lines: list[str]) -> list[Finding]:
    """A row of a table with text in a cell behind the last cell of the header.

    The header has the cells of the table. A row with more has its other cells dropped, and the
    parser makes no token for them: text, tags, a link or an image there is never shown. The row
    is split as the parser splits it (`escapedSplit`, the outer pipes off), and a row with fewer
    cells, or with empty ones behind the header, has nothing to hide.
    """
    findings = []
    columns, nested, head = 0, False, False
    for token in tokens:
        if token.type == "table_open":
            columns, nested = 0, token.level > 0
        elif token.type in ("thead_open", "thead_close"):
            head = token.type == "thead_open"
        elif token.type == "th_open":
            columns += 1
        elif token.type == "tr_open" and not head and token.map:
            if any(cell.strip() for cell in _cells(lines[token.map[0]], nested)[columns:]):
                findings.append(report.at("E-BODY-HTML", token.map[0]))
    return findings


def _cells(line: str, nested: bool) -> list[str]:
    """The cells of a row of a table, as the table rule of the parser gets them from the line.

    In a quote or a list the rule is given the line without the marks in front of it.
    """
    text = line[_ONLY_MARKS.match(line).end() :] if nested else line
    cells = escapedSplit(text.strip())
    if cells and cells[0] == "":
        cells.pop(0)
    if cells and cells[-1] == "":
        cells.pop()
    return cells


def _hidden(report: _Report, tokens: list[Token], lines: list[str]) -> list[Finding]:
    """The lines of text that no block of the parser holds: a link reference definition (a link
    that shows nothing) and what is nested too deep to be parsed. A line of marks alone is empty."""
    held = {
        row
        for token in tokens
        if token.type in _LEAVES and token.map
        for row in range(token.map[0], token.map[1])
    }
    findings = []
    previous: tuple[int, str] | None = None
    for row, line in enumerate(lines):
        if row in held or not line.strip() or _ONLY_MARKS.fullmatch(line):
            continue
        # A definition goes on over lines (its destination, its title), and those are links too.
        goes_on = previous == (row - 1, "E-BODY-LINK")
        code = "E-BODY-LINK" if goes_on or _DEFINITION.match(line) else "E-BODY-HTML"
        findings.append(report.at(code, row))
        previous = (row, code)
    return findings


def _urls(line: str) -> Iterator[int]:
    """Where each `scheme://` and each `www.` starts in a line (`://www.` is one URL)."""
    for found in _URL.finditer(line):
        if found.group() != "://" or _has_scheme(line, found.start()):
            yield found.start()


def _has_scheme(line: str, end: int) -> bool:
    """Whether a scheme ends at `end`: scheme characters in front of it, and a letter among them."""
    start = end
    while start > 0 and line[start - 1] in _SCHEME_CHARS:
        start -= 1
    return any(char in _LETTERS for char in line[start:end])


# --- E-BODY-DRIFT


def _drift(
    report: _Report, lines: list[str], found: list[Heading], p: Policy, catalog: Catalog
) -> list[Finding]:
    """A generated section that is not what `render_generated` makes of the policy, byte for byte.

    A section is its lines from the heading of the section up to the heading of the next one, as
    the renderer has it (`rewrite` goes by the same headings, the `##` at the top level of the
    document). The last one runs to the end of the file, without the newlines there
    (E-FINAL-NEWLINE's, ruling R15). The check relies on the five sections being right, each there
    once and in its place, and `check_body` runs it only then (ruling R58). A policy that cannot be
    rendered (a tool that is not one) has errors that say so, and no drift.
    """
    try:
        rendered = render_generated(p, catalog)
    except ValueError:
        return []
    tops = sections(found)
    findings = []
    for name, text in zip(GENERATED_SECTIONS, rendered, strict=True):
        index = next((i for i, heading in enumerate(tops) if heading.name == name), None)
        if index is None:
            continue
        start = tops[index].row
        last = index + 1 == len(tops)
        have = lines[start:] if last else lines[start : tops[index + 1].row]
        want = text.split("\n")[:-1]  # every line ends with an LF
        if last:
            have, want = _without_blank_ends(have), _without_blank_ends(want)
        differ = _first_difference(have, want)
        if differ is not None:
            row = min(start + differ, len(lines) - 1)  # a file that ends early: its last line
            line = str(report.first_line + row)
            findings.append(report.at("E-BODY-DRIFT", row, section=name, diff_line=line))
    return findings


def _without_blank_ends(lines: list[str]) -> list[str]:
    end = len(lines)
    while end and lines[end - 1] == "":
        end -= 1
    return lines[:end]


def _first_difference(have: list[str], want: list[str]) -> int | None:
    for index, (found, wanted) in enumerate(zip_longest(have, want)):
        if found != wanted:
            return index
    return None
