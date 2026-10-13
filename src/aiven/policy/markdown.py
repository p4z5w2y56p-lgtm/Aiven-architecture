"""The body as CommonMark with tables (validator-spec section 3.7), and its headings.

The body is parsed by markdown-it-py with the CommonMark preset and tables on. Linkify stays off,
and nothing is rendered: only the tokens are used, so no HTML is ever made from a policy. A heading
inside a code block or a fence has no token, so it is no heading. ATX and setext headings both are.

The rows of a token (`Token.map`) are 0-based within the body. markdown-it takes a CR for a line
end, as CommonMark does, and the validator counts LF only (a CR is E-LINE-ENDINGS, and it would
move every row below it). So a CR is changed into another character first, and a row is a line of
the file. Nothing is lost by it: the file is invalid anyway.

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
    return MarkdownIt("commonmark").enable("table")


def parse(body: str) -> list[Token]:
    """The tokens of the body. The inline tokens are the `children` of an `inline` token."""
    return _parser().parse(body.replace("\r", "\ufffd"))


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
