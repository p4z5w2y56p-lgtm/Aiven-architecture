"""Versions of the valid base policy, for the tests of widening and of the policy set (Task 1.6).

A version is the valid base with changes made to its front matter. A change is a function of the
front matter data, such as `setting` and `with_tools` (rules.py) and `without` (frontmatter.py)
make. `variant_file` writes the front matter again with `edited`, so its comments are gone, and
keeps the body of the base. The generated sections are not rendered again: these tests read the
policy that the file gives, and some of them set a field to a value that the renderer refuses.

`variant` reads that file with the real pipeline (`policy_of`), so its `sha256` is that of the new
bytes: two versions with the same changes are the same file, and two with other changes are not.
`another` is a policy of another agent, with the principal that agent has on the test platform.
"""

from collections.abc import Callable
from typing import Any

from aiven.policy.model import Policy
from tests.support.bodies import BODY, policy_of
from tests.support.frontmatter import edited
from tests.support.policies import AGENTS_PROJECT
from tests.support.rules import setting

Change = Callable[[dict[str, Any]], object]


def variant_file(*changes: Change) -> bytes:
    """The bytes of the valid base with the changes made to its front matter, in this order."""

    def change_all(data: dict[str, Any]) -> None:
        for change in changes:
            change(data)

    return f"---\n{edited(change_all)}---\n{BODY}".encode()


def variant(*changes: Change) -> Policy:
    """The policy of `variant_file(*changes)`. Without changes it has the fields of the base."""
    return policy_of(variant_file(*changes))


def principal_of(agent: str) -> str:
    """The principal that a valid policy of `agent` has on the test platform."""
    return f"agent-{agent}@{AGENTS_PROJECT}.iam.gserviceaccount.com"


def another(agent: str, *changes: Change) -> Policy:
    """A policy of another agent, with the principal of that agent and the changes."""
    return variant(setting("agent", agent), setting("principal", principal_of(agent)), *changes)
