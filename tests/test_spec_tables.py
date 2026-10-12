"""The spec-table helper: the drift tests are only as good as this parser."""

from pathlib import Path

import pytest

from tests.support.spec_tables import code_spans, line_starting_with, table_after

SPEC = """\
# Title

## 1. First

| A | B |
|---|---|
| `x` | one |
| y | two \\| three |

Text after the table.

## 2. Second

```text
## 9. Not a heading, it sits in a code fence
| fake | table |
```

No table here.

## 3. Third

Intro.

| H1 | H2 | H3 |
|:---|---:|:--:|
| a | b | c |
| d | | f |

## 4. Twice

## 4. Twice again
"""


@pytest.fixture
def spec(tmp_path: Path) -> Path:
    path = tmp_path / "spec.md"
    path.write_text(SPEC, encoding="utf-8")
    return path


def test_table_after_returns_header_then_rows_without_separator(spec):
    assert table_after("1. First", spec) == [["A", "B"], ["`x`", "one"], ["y", "two | three"]]


def test_table_after_accepts_alignment_markers_and_empty_cells(spec):
    assert table_after("3. Third", spec) == [["H1", "H2", "H3"], ["a", "b", "c"], ["d", "", "f"]]


def test_heading_must_match_exactly_one_heading(spec):
    with pytest.raises(LookupError, match="exactly one heading"):
        table_after("4. Twice", spec)
    with pytest.raises(LookupError, match="exactly one heading"):
        table_after("7. Nowhere", spec)


def test_headings_and_tables_inside_code_fences_are_ignored(spec):
    with pytest.raises(LookupError, match="exactly one heading"):
        table_after("9. Not a heading", spec)
    with pytest.raises(LookupError, match="no table"):
        table_after("2. Second", spec)


def test_line_starting_with_and_code_spans(spec):
    assert line_starting_with("Text after", spec) == "Text after the table."
    with pytest.raises(LookupError):
        line_starting_with("No such line", spec)
    assert code_spans("use `a.b`, `c.*` and `d`") == ["a.b", "c.*", "d"]
