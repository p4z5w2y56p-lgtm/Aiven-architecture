"""Helpers for the body and renderer tests: the policy of a file, and its generated sections.

The two generated sections are the last two of a policy file. `generated_of` cuts them out of a text
by their headings, which is what the renderer promises to reproduce: for a valid file,
`"".join(render_generated(...))` is the text from the first generated heading to the end.
"""

from pathlib import Path

from aiven.policy.fileformat import decode_text
from aiven.policy.frontmatter import load, split
from aiven.policy.model import Policy, build_policy
from aiven.policy.render import rewrite
from tests.support.policies import BASE_PATH
from tests.support.rules import CATALOG, CFG

ENFORCED = "## Enforced rules (generated)"
SIGNOFF = "## Sign-off (generated)"


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
