"""The body checks for what the reader should see and nothing else: HTML (E-BODY-HTML), links and
URLs (E-BODY-LINK), and text that the parser keeps from the reader.

A policy must be complete on its own and have no text that the reader cannot see (validator-spec
3.7, rulings R46 and R48). So a token that is HTML or a link is a finding, a URL is one wherever it
stands (a code span and a code block included), and so is a line that the parser drops: a link
reference definition, and what is nested too deep to be parsed. The inputs here are hostile ones as
well: the checks must be quick and must not raise.
"""

import random
import time

import pytest

from aiven.policy.findings import Finding, format_line, message
from tests.support import gen
from tests.support.bodies import (
    BODY,
    FIRST_LINE,
    POLICY,
    added_after,
    at,
    codes,
    edited,
    only,
    places,
    run,
)

PURPOSE = "Once a day, this agent reads"
END = "no email goes to clients."
STOP = "Stop: the agent kill switch"


def purpose_with(text: str) -> str:
    """The base body with `text` added to the end of the Purpose paragraph."""
    return edited(END, f"{END} {text}")


def after_purpose(text: str) -> str:
    """The base body with the lines of `text` behind the Purpose paragraph, after a blank line."""
    return added_after(END, "\n" + text)


# --- E-BODY-HTML


@pytest.mark.parametrize(
    "html",
    [
        "<b>",
        "</b>",
        "<br>",
        "<br/>",
        "<!-- x -->",
        "<?php x ?>",
        "<!DOCTYPE x>",
        "<![CDATA[x]]>",
        '<a href="x">',
    ],
)
def test_html_inside_a_paragraph_is_reported_on_its_line(html):
    body = purpose_with(f"text {html} text")
    assert places(run(body)) == [("E-BODY-HTML", at(PURPOSE, body))]


@pytest.mark.parametrize(
    "block",
    [
        "<div>",
        "<div>\ntext\n</div>",
        "<!-- hidden -->",
        "<!--\nhidden\nover lines\n-->",
        "<script>x</script>",
        "<p>",
    ],
)
def test_html_that_starts_a_block_is_one_finding_on_its_first_line(block):
    body = after_purpose(block)
    assert places(run(body)) == [("E-BODY-HTML", at(END, body) + 2)]


def test_every_token_is_a_finding_of_its_own():
    body = purpose_with("<b>bold</b> and <i>italic</i> <!-- c -->")
    assert [f.line for f in only(run(body), "E-BODY-HTML")] == [at(PURPOSE, body)] * 5


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("- ", ""),
        ("> ", ""),
        ("### ", ""),
        ("| a | ", " |\n|---|---|\n| c | d |"),
        ("[link text ", "](x)"),
    ],
    ids=["a list", "a quote", "a heading", "a table cell", "link text"],
)
def test_html_is_found_in_every_kind_of_block_and_inline(before, after):
    body = after_purpose(f"{before}text <b>x</b> text{after}")
    assert len(only(run(body), "E-BODY-HTML")) == 2


def test_html_in_the_alt_text_of_an_image_is_found_too():
    body = purpose_with("![alt <b> text](x)")
    assert codes(run(body)) == ["E-BODY-HTML", "E-BODY-LINK"]


@pytest.mark.parametrize(
    "text",
    [
        "&lt;b&gt; and &lt;!-- x --&gt;",
        "`<b>` and `<!-- x -->`",
        "a < b and 1 <2 and x<>y and <3 and < b>",
        "<<b",
        "\\<b>",
        "<b",
        "<>",
        "<!- x -->",
    ],
)
def test_text_that_looks_like_html_but_is_not_is_not_reported(text):
    assert only(run(purpose_with(text)), "E-BODY-HTML") == []


@pytest.mark.parametrize(
    "block", ["```\n<!-- x -->\n<b>\n```", "~~~html\n<div>\n~~~", "    <b>x</b>"]
)
def test_html_in_a_code_block_is_text_and_not_reported(block):
    assert only(run(after_purpose(block)), "E-BODY-HTML") == []


def test_html_in_a_generated_section_is_reported_too():
    body = edited(STOP, f"<b>{STOP}")
    line = at(STOP, body)
    assert places(run(body)) == [("E-BODY-DRIFT", line), ("E-BODY-HTML", line)]


def test_the_line_of_a_token_in_a_paragraph_of_several_lines_is_its_own():
    text = "no email\ngoes to <i>clients</i>,\nand then\\\nthis <b>too</b>.\n\nA new <u>one</u>."
    body = edited(END, text)
    start = at("no email", body)
    assert [f.line for f in only(run(body), "E-BODY-HTML")] == (
        [start + 1] * 2 + [start + 3] * 2 + [start + 5] * 2
    )


def test_the_lines_of_the_alt_text_of_an_image_are_counted_too():
    body = edited(END, "![alt\ntext](x) and <b>")
    assert [f.line for f in only(run(body), "E-BODY-HTML")] == [at("text](x)", body)]


def test_a_tag_that_goes_over_lines_counts_the_lines_it_has():
    body = edited(END, '<a\nhref="x">t</a>\nlast <b>')
    assert [f.line for f in only(run(body), "E-BODY-HTML")] == [
        at("<a", body),
        at('href="x"', body),
        at("last <b>", body),
    ]


# --- E-BODY-LINK


@pytest.mark.parametrize(
    "link",
    ["[a](b)", "[a](<b c>)", "[a](b 'title')", "![a](b)", "![](b)", "<a@example.test>", "[a]()"],
)
def test_a_link_or_an_image_is_one_finding_on_its_line(link):
    body = purpose_with(f"See {link} here.")
    assert places(run(body)) == [("E-BODY-LINK", at(PURPOSE, body))]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test",
        "http://x",
        "ftp://x",
        "a+b-c.d://x",
        "a1://x",
        "HTTPS://X",
        "x://",
        "www.example.test",
        "WWW.EXAMPLE.TEST",
        "Www.example.test",
        "https://www.example.test",
        "see:https://x",
        "(https://x)",
        "a-://x",
        "a+://x",
        "a.://x",
    ],
)
def test_a_url_is_one_finding_on_its_line(url):
    body = purpose_with(f"See {url} here.")
    assert places(run(body)) == [("E-BODY-LINK", at(PURPOSE, body))]


@pytest.mark.parametrize(
    "text",
    [
        "1://x",
        "://x",
        "-://x",
        "+.://x",
        "http:/x",
        "http//x",
        "www",
        "ww.example.test",
        "mailto:a@b.test",
    ],
)
def test_text_that_is_not_a_scheme_and_not_www_is_not_a_url(text):
    assert only(run(purpose_with(f"See {text} here.")), "E-BODY-LINK") == []


@pytest.mark.parametrize(
    "place",
    ["`https://x`", "```\nwww.example.test\n```", "    https://x", "~~~\nftp://x\n~~~"],
    ids=["a code span", "a fence", "indented code", "a tilde fence"],
)
def test_a_url_in_a_code_span_or_a_code_block_counts(place):
    assert only(run(after_purpose(place)), "E-BODY-LINK") != []


def test_every_url_is_a_finding_and_a_url_with_www_in_it_is_still_one():
    body = purpose_with("https://a.test and www.b.test and http://www.c.test")
    assert [f.line for f in only(run(body), "E-BODY-LINK")] == [at(PURPOSE, body)] * 3
    body = added_after(PURPOSE, "\nline https://a.test\nnext line www.b.test")
    assert [f.line for f in only(run(body), "E-BODY-LINK")] == [
        at("line https", body),
        at("next line", body),
    ]


def test_a_url_at_the_start_of_a_line_is_found_also_with_a_scheme_of_one_letter():
    for url in ("https://example.test", "x://y"):
        body = after_purpose(url)
        assert places(run(body)) == [("E-BODY-LINK", at(url, body))]


def test_a_url_in_a_link_is_the_link_and_the_url():
    for link in ("[a](https://example.test)", "<https://example.test>"):
        body = purpose_with(link)
        assert [f.line for f in only(run(body), "E-BODY-LINK")] == [at(PURPOSE, body)] * 2


def test_a_url_in_a_generated_section_is_reported_too():
    body = edited(STOP, f"{STOP} https://x")
    assert ("E-BODY-LINK", at(STOP, body)) in places(run(body))


def test_a_link_by_reference_is_the_link_and_the_definition_that_is_not_shown():
    body = after_purpose('See [the page][r] and [r].\n\n[r]: /somewhere "title"')
    see, definition = at("See [the page]", body), at("[r]: /somewhere", body)
    assert places(run(body)) == [("E-BODY-LINK", see)] * 2 + [("E-BODY-LINK", definition)]


def test_a_long_run_of_scheme_characters_is_not_a_quadratic_search():
    body = purpose_with("a" * 200_000 + " " + "a." * 100_000 + " " + "a://" * 50_000)
    started = time.perf_counter()
    found = only(run(body), "E-BODY-LINK")
    assert time.perf_counter() - started < 5
    assert len(found) == 50_000


# --- text that the reader cannot see: what the parser does not keep


@pytest.mark.parametrize(
    "definition",
    ["[r]: /somewhere", '[r]: /somewhere "a title"', '[r]: <hidden text> "more"', "  [r]: /x"],
)
def test_a_link_reference_definition_is_a_link_that_is_not_shown(definition):
    body = after_purpose(definition)
    assert places(run(body)) == [("E-BODY-LINK", at(END, body) + 2)]


def test_a_definition_over_two_lines_is_hidden_on_both_of_them():
    body = after_purpose("[r]:\n/x")
    assert [f.line for f in only(run(body), "E-BODY-LINK")] == [
        at("[r]:", body),
        at("[r]:", body) + 1,
    ]


def test_every_definition_is_reported_also_when_the_label_is_defined_twice():
    # Only the first definition of a label is kept by the parser; the others are not shown either.
    body = after_purpose('[r]: /one\n[r]: /two "secret text"\n\n[s]: /three')
    assert [f.line for f in only(run(body), "E-BODY-LINK")] == [
        at("[r]: /one", body),
        at("[r]: /two", body),
        at("[s]: /three", body),
    ]


@pytest.mark.parametrize("prefix", ["- ", "> ", "1. ", "> - "])
def test_a_definition_in_a_list_or_a_quote_is_found(prefix):
    body = after_purpose(f"{prefix}[r]: /x")
    assert places(run(body)) == [("E-BODY-LINK", at("[r]: /x", body))]


def test_text_nested_in_20_quotes_is_dropped_by_the_parser_and_is_reported():
    deep = "> " * 20 + "<!-- hidden -->"
    body = after_purpose(deep)
    assert places(run(body)) == [("E-BODY-HTML", at(deep, body))]
    assert run(after_purpose("> " * 19 + "text")) == []


@pytest.mark.parametrize("mark", ["- ", "1. "], ids=["bullets", "numbers"])
def test_text_nested_in_10_lists_is_dropped_with_the_rest_of_the_document_and_all_is_reported(mark):
    # A list and its item are two levels. The parser drops, from the 20th level on, all that follows
    # in the document, the generated sections too: every line of it is reported.
    deep = mark * 10 + "<!-- hidden -->"
    body = after_purpose(deep)
    hidden = [f.line for f in only(run(body), "E-BODY-HTML")]
    last = FIRST_LINE + body.count("\n")
    assert hidden[0] == at(deep, body)
    assert hidden[-1] == last - 1  # the last line of the file is empty
    assert len(hidden) > 40
    assert run(after_purpose(mark * 9 + "text")) == []


def test_every_line_that_is_dropped_is_reported_and_one_that_is_kept_is_not():
    deep = "> " * 25
    body = after_purpose(f"{deep}hidden1\n{deep}hidden2\n\n> kept")
    assert [f.line for f in only(run(body), "E-BODY-HTML")] == [
        at("hidden1", body),
        at("hidden2", body),
    ]


@pytest.mark.parametrize(
    "marks", ["-", "- ", "*", "+", "1.", "2)", ">", "> >", "- -", "> -", "  -", "-\t"]
)
def test_a_line_of_nothing_but_list_and_quote_marks_has_no_text_to_hide(marks):
    assert run(after_purpose(marks)) == []


def test_everything_that_markdown_has_is_kept_and_none_of_it_is_dropped():
    sink = "\n".join(
        [
            "- one",
            "  - nested",
            "    - deeper",
            "",
            "1. first",
            "2. second",
            "",
            "> quote",
            "> continued",
            ">",
            "> - in a quote",
            "",
            "| a | b |",
            "|---|:-:|",
            "| 1 | 2 |",
            "",
            "Setext",
            "======",
            "",
            "Setext two",
            "----------",
            "",
            "***",
            "",
            "```python",
            "code",
            "",
            "more code",
            "```",
            "",
            "~~~",
            "tilde",
            "~~~",
            "",
            "    indented code",
            "",
            "text with \\* escapes, &amp; entities, *emphasis* and **strong**",
            "hard\\",
            "break and  ",
            "another",
            "",
            "- a loose item",
            "",
            "  with a second paragraph",
        ]
    )
    found = run(after_purpose(sink))
    assert only(found, "E-BODY-HTML") == [] and only(found, "E-BODY-LINK") == []


# --- the rows are lines of the file


def test_a_cr_in_a_line_does_not_move_the_lines_below_it():
    body = edited(END, "no email\rgoes to clients.\r\n\r<b>hidden</b>")
    row = next(row for row, line in enumerate(body.split("\n")) if "<b>" in line)
    assert {f.line for f in only(run(body), "E-BODY-HTML")} == {FIRST_LINE + row}


def test_the_findings_of_a_body_with_a_credential_in_it_do_not_hold_the_value():
    key = gen.secret_values()["AWS access key"][0]
    body = added_after("- `gmail.send`: sends", f"- `{key}`: a tool with a name that is a key")
    found = run(body)
    assert [f.code for f in found] == ["E-BODY-TOOL-EXTRA"]
    for finding in found:
        assert key not in format_line(finding) and key not in message(finding, "nl")


# --- hostile bodies


HOSTILE = {
    "open brackets": "[" * 40_000,
    "open brackets and text": "[a" * 20_000,
    "open images": "![" * 20_000,
    "stars": "*" * 100_000,
    "underscores": "_a" * 50_000,
    "backticks": "`" * 100_000,
    "backticks apart": "` " * 50_000,
    "angle brackets": "<" * 100_000,
    "open tags": "<a " * 40_000,
    "quotes": "> " * 50_000,
    "quote lines": "> a\n" * 20_000,
    "bullets": "- " * 50_000,
    "bullet lines": "- a\n" * 20_000,
    "pipes": "|" * 100_000,
    "table": "| a | b |\n" * 10_000,
    "hashes": "#" * 100_000,
    "heading lines": "## a\n" * 20_000,
    "a word": "a" * 100_000,
    "a long scheme": "a" * 100_000 + "://",
    "many schemes": "a://" * 25_000,
    "dots": "a." * 50_000,
    "www": "www." * 25_000,
    "colons": ":/" * 50_000,
    "empty lines": "\n" * 100_000,
    "definitions": "[a]: /x\n" * 15_000,
    "entities": "&amp;" * 20_000,
    "escapes": "\\*" * 50_000,
    "tildes": "~~~\n" * 25_000,
    "setext": "a\n---\n" * 15_000,
}


@pytest.mark.parametrize("hostile", HOSTILE.values(), ids=HOSTILE)
def test_a_hostile_body_is_judged_in_a_few_seconds_and_without_error(hostile):
    started = time.perf_counter()
    found = run(edited(END, f"{END}\n\n{hostile}"))
    assert time.perf_counter() - started < 5
    assert all(isinstance(f, Finding) for f in found)


# A random body: lines of the base body and of markdown, in any order.
PIECES = [
    *BODY.split("\n"),
    *["# T", "## Purpose", "## Why each tool", "### Sub", "#### Deep", "Setext", "=====", "-----"],
    *["---", "- `gmail.send`: ok", "- `x`: y", "1. `gmail.draft`: z", "> quote", "> > > deep"],
    *["- ", ">", "", "<b>", "</b>", "<!-- c -->", "<div>", "[a](b)", "![i](j)", "[r]: /d"],
    *["https://x", "www.y", "`c`", "```", "~~~", "    code", "| a | b |", "|---|---|", "\\"],
    *["&amp;", "\t", "\r", "\N{NO-BREAK SPACE}", "\N{REPLACEMENT CHARACTER}"],
]


MARKS = ["", "", "", "", "- ", "> ", "1. ", "  ", "- - ", "> > ", "    "]


def test_a_random_body_never_raises_and_every_finding_can_be_printed_on_a_line_of_the_file():
    rng = random.Random(20261014)
    for number in range(500):
        lines = [rng.choice(MARKS) + rng.choice(PIECES) for _ in range(rng.randint(0, 60))]
        body = "\n".join(lines)
        last = FIRST_LINE + body.count("\n")
        for policy in (POLICY, None):
            for finding in run(body, policy=policy):
                assert FIRST_LINE <= finding.line <= last, (number, finding.code)
                assert "\n" not in format_line(finding), number
                assert message(finding, "en") and message(finding, "nl"), number
