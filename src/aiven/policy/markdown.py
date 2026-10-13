"""The body as CommonMark with tables (validator-spec section 3.7), and its headings.

The body is parsed by markdown-it-py with the CommonMark preset and tables on. Linkify stays off,
and nothing is rendered: only the tokens are used, so no HTML is ever made from a policy. A heading
inside a code block or a fence has no token, so it is no heading. ATX and setext headings both are.

The rows of a token (`Token.map`) are 0-based within the body. markdown-it takes a CR for a line
end, as CommonMark does, and the validator counts LF only (a CR is E-LINE-ENDINGS, and it would
move every row below it). So a CR is changed into another character first, and a row is a line of
the file. Nothing is lost by it: the file is invalid anyway.

A `text` token is the text as the reader gets it: a character reference (`&#8203;`) and an escape
(`\\:`) are decoded. The checks of the raw lines (E-HIDDEN-CHAR reads the bytes) cannot see what a
reference makes of them, so the checks of the body look at this text as well. They need to know
which of its characters were written and which a reference made, and markdown-it's own `text_join`
forgets that. So it is switched off, and `_join_text` does the same job and notes it:
`meta["entities"]` of a `text` token is the text that the references in it gave.

`Heading` holds text of the file, so it has no repr.
"""

from dataclasses import dataclass
from functools import cache

from markdown_it import MarkdownIt
from markdown_it.token import Token


@dataclass(frozen=True, slots=True, repr=False)
class Heading:
    """A heading of the body.

    `row` is where it starts, `index` is the position of its `heading_open` token, and `top` says
    that it stands at the top level of the document, and not inside a quote or a list.
    """

    level: int
    name: str
    row: int
    index: int
    top: bool


@cache
def _parser() -> MarkdownIt:
    return MarkdownIt("commonmark").enable("table").disable("text_join")


def parse(body: str) -> list[Token]:
    """The tokens of the body. The inline tokens are the `children` of an `inline` token."""
    tokens = _parser().parse(body.replace("\r", "\ufffd"))
    for token in tokens:
        if token.type == "inline":
            _join_text(token)
    return tokens


def _join_text(parent: Token) -> None:
    """Join each run of text and references into one `text` token, as markdown-it's `text_join`
    does, and note the text that the references gave. The alt text of an image is joined too."""
    joined: list[Token] = []
    run: list[Token] = []
    for child in parent.children or []:
        if child.type in ("text", "text_special"):
            run.append(child)
            continue
        _end_run(run, joined)
        run = []
        if child.type == "image":
            _join_text(child)
        joined.append(child)
    _end_run(run, joined)
    parent.children = joined


def _end_run(run: list[Token], joined: list[Token]) -> None:
    if run:
        first = run[0]
        first.meta = {"entities": "".join(t.content for t in run if t.info == "entity")}
        first.content = "".join(token.content for token in run)
        first.type = "text"
        joined.append(first)


def headings(tokens: list[Token]) -> list[Heading]:
    """Every heading, in the order of the document, nested ones included.

    The name is the text as it was written, so `## **Purpose**` is not `Purpose`.
    """
    return [
        Heading(
            int(token.tag[1:]), tokens[index + 1].content, token.map[0], index, token.level == 0
        )
        for index, token in enumerate(tokens)
        if token.type == "heading_open" and token.map
    ]


def find(found: list[Heading], name: str, *, top: bool = False) -> Heading | None:
    """The first `##` heading with this name. With `top`, one at the top level of the document."""
    for heading in found:
        if heading.level == 2 and heading.name == name and (heading.top or not top):
            return heading
    return None
