"""The body as markdown-it sees it (validator-spec 3.7): the tokens, and the headings in them."""

from aiven.policy.markdown import find, headings, parse


def seen(body: str) -> list[tuple[int, str, int, bool]]:
    return [(h.level, h.name, h.row, h.top) for h in headings(parse(body))]


def kinds(body: str) -> set[str]:
    """The type of every token of the body, the inline ones included."""
    return {child.type for token in parse(body) for child in [token, *(token.children or [])]}


def test_atx_and_setext_headings_both_count_with_their_level_and_their_first_row():
    body = "# T\n\n## A ##\n\n##   B   \n\nSetext\n------\n\nTitle\n=====\n"
    assert seen(body) == [
        (1, "T", 0, True),
        (2, "A", 2, True),
        (2, "B", 4, True),
        (2, "Setext", 6, True),
        (1, "Title", 9, True),
    ]


def test_a_heading_in_a_fence_or_in_indented_code_is_no_heading():
    body = "```\n## In a fence\n```\n\n    ## Indented\n\n~~~\n# tilde\n~~~\n"
    assert headings(parse(body)) == []


def test_a_heading_in_a_quote_or_a_list_counts_but_is_not_at_the_top():
    assert seen("> ## In a quote\n\n- ### In a list\n") == [
        (2, "In a quote", 0, False),
        (3, "In a list", 2, False),
    ]


def test_seven_hashes_and_a_hash_without_a_space_are_text():
    assert headings(parse("####### seven\n\n##none\n")) == []


def test_the_name_is_the_text_as_it_was_written():
    body = "## **Purpose**\n\n## `Purpose`\n\n## Purpose &amp; more\n"
    assert [h.name for h in headings(parse(body))] == [
        "**Purpose**",
        "`Purpose`",
        "Purpose &amp; more",
    ]


def test_find_gives_the_first_heading_of_level_two_with_the_name():
    found = headings(parse("# Name\n\n> ## Name\n\n## Name\n\n## Name\n"))
    assert find(found, "Name").row == 2
    assert find(found, "Name", top=True).row == 4
    assert find(found, "Other") is None
    assert find(headings(parse("# Name\n")), "Name") is None  # level 1 is not a section


def test_a_cr_is_no_line_end_so_that_a_row_is_a_line_of_the_file():
    # By LF the lines are "a\rb\r", "c", "" and "## H". Taken as line ends, the CRs would make H
    # row 4 (and a lone CR in the middle of a line would shift every row below it).
    assert seen("a\rb\r\nc\n\n## H\n") == [(2, "H", 3, True)]


def test_tables_are_parsed():
    body = "| a | b |\n|---|---|\n| 1 | 2 |\n"
    assert {"table_open", "tr_open", "td_open"} <= kinds(body)


def test_html_is_a_token_and_a_bare_url_is_not_a_link():
    assert {"html_block", "html_inline"} <= kinds("<div>\nx\n</div>\n\ntext <b>bold</b>\n")
    assert "link_open" not in kinds("https://example.test and www.example.test\n")
    assert "link_open" in kinds("<https://example.test> and [a](b)\n")
