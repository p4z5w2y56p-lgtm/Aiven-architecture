"""Helpers for the body and renderer tests: the policy of a file, its body, and its sections.

The two generated sections are the last two of a policy file. `generated_of` cuts them out of a text
by their headings, which is what the renderer promises to reproduce: for a valid file,
`"".join(render_generated(...))` is the text from the first generated heading to the end.

`run` calls `check_body` on a body of the base, and `edited`, `added_after` and `at` change that body
and find lines in it by their content, so a test does not depend on a line number of the template.
Lines are the lines of the file: the body starts on `FIRST_LINE`, the line after the closing `---`.
"""

from pathlib import Path

from aiven.policy.body import check_body

from aiven.policy.fileformat import decode_text
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import load, split
from aiven.policy.model import Policy, build_policy
from aiven.policy.render import rewrite
from tests.support.policies import BASE_PATH, valid_base
from tests.support.rules import CATALOG, CFG

ENFORCED = "## Enforced rules (generated)"
SIGNOFF = "## Sign-off (generated)"
SECTION_NAMES = [
    "Purpose",
    "Why each tool",
    "Data and risks",
    "Enforced rules (generated)",
    "Sign-off (generated)",
]


def policy_of(data: bytes, path: Path = BASE_PATH) -> Policy:
    """The policy of the front matter of `data`, which must have one."""
    parts = split(decode_text(data))
    assert parts is not None, "the file has no front matter"
    policy, _ = build_policy(load(parts[0], path), data, CFG, CATALOG, path)
    assert policy is not None, "the front matter gives no policy"
    return policy


def generated_of(text: str) -> tuple[str, str]:
    """The text of the two generated sections of a file, each from its heading to the next."""
    start = text.index(ENFORCED)
    middle = text.index(SIGNOFF, start)
    return text[start:middle], text[middle:]


def rerendered(data: bytes) -> bytes:
    """`data` with its generated sections rendered again from its own front matter."""
    return rewrite(data, policy_of(data), CATALOG)


BASE = valid_base()
_, BODY, FIRST_LINE = split(decode_text(BASE))  # the body of the base, and where it starts
POLICY = policy_of(BASE)


def run(
    body: str = BODY, *, policy: Policy | None = POLICY, first_line: int = FIRST_LINE, **flags: bool
) -> list[Finding]:
    """The findings of `check_body` for a body, which is that of the base unless one is given."""
    return check_body(body, first_line, policy, CATALOG, BASE_PATH, **flags)


def codes(findings: list[Finding]) -> list[str]:
    return sorted(found.code for found in findings)


def places(findings: list[Finding]) -> list[tuple[str, int | None]]:
    """(code, line) of the findings, sorted."""
    return sorted((found.code, found.line) for found in findings)


def only(findings: list[Finding], code: str) -> list[Finding]:
    return [found for found in findings if found.code == code]


def edited(old: str, new: str, body: str = BODY) -> str:
    """The body with the one place where `old` stands replaced by `new`."""
    assert body.count(old) == 1, f"{old!r} must occur once, found {body.count(old)}"
    return body.replace(old, new)


def at(needle: str, body: str = BODY) -> int:
    """The file line of the one line of the body that holds `needle`."""
    rows = [row for row, line in enumerate(body.split("\n")) if needle in line]
    assert len(rows) == 1, f"{needle!r} must stand in one line, found {len(rows)}"
    return FIRST_LINE + rows[0]


def added_after(needle: str, text: str, body: str = BODY) -> str:
    """The body with the lines of `text` added behind the one line that holds `needle`."""
    lines = body.split("\n")
    row = at(needle, body) - FIRST_LINE
    return "\n".join([*lines[: row + 1], *text.split("\n"), *lines[row + 1 :]])
