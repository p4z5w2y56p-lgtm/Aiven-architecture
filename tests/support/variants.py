"""Versions of the base policy, for the tests of widening and of the policy set (Task 1.6).

A version is the base with changes made to its front matter. A change is a function of the front
matter data, such as `setting` and `with_tools` (rules.py) and `without` (frontmatter.py) make.
`variant_file` writes the front matter again with `edited`, so its comments are gone, and keeps
the body of the base. `variant` reads that file with the real pipeline (`policy_of`), so its
`sha256` is that of the new bytes: two versions with the same changes are the same file, and two
with other changes are not. `another` is a policy of another agent, with the principal that agent
has on the test platform.

A version is not a whole valid file as it stands. The generated sections still show the base, so
`validate_file` reports E-BODY-DRIFT for a version whose front matter shows other values. These
tests read the policy that the file gives, and some of them set a field to a value that the
renderer refuses, so by default the sections are left alone. (A set of versions is "valid" when
`check_set` has no finding for it, and that is all that the word means in these tests.)

With `render=True` the generated sections are rendered again from the new front matter
(`rerendered`). That makes a whole valid file of a change that only touches values which the
sections show: the version, a limit, the scope, the mode, the runs of shadow mode. Then
`validate_file` has the warnings of the base and nothing more, and the file can go through the
whole CLI. It is not for every change: a tool also needs its bullet in Why each tool, a principal
that is not the agent's own is E-PRINCIPAL, and the renderer refuses a mode that is neither
`strict` nor `taint`.
"""

from collections.abc import Callable
from typing import Any

from aiven.policy.model import Policy
from tests.support.bodies import BODY, policy_of, rerendered
from tests.support.frontmatter import edited
from tests.support.policies import AGENTS_PROJECT
from tests.support.rules import setting

Change = Callable[[dict[str, Any]], object]


def variant_file(*changes: Change, render: bool = False) -> bytes:
    """The bytes of the base with the changes made to its front matter, in this order.

    With `render` the generated sections are rendered again (see the module docstring); that
    raises ValueError for a value that the renderer refuses.
    """

    def change_all(data: dict[str, Any]) -> None:
        for change in changes:
            change(data)

    data = f"---\n{edited(change_all)}---\n{BODY}".encode()
    return rerendered(data) if render else data


def variant(*changes: Change, render: bool = False) -> Policy:
    """The policy of `variant_file(*changes)`. Without changes it has the fields of the base."""
    return policy_of(variant_file(*changes, render=render))


def principal_of(agent: str) -> str:
    """The principal that a valid policy of `agent` has on the test platform."""
    return f"agent-{agent}@{AGENTS_PROJECT}.iam.gserviceaccount.com"


def another(agent: str, *changes: Change) -> Policy:
    """A policy of another agent, with the principal of that agent and the changes."""
    return variant(setting("agent", agent), setting("principal", principal_of(agent)), *changes)
