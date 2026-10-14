"""What a wrapper does for the gateway (plan Tasks 3.4 and 3.7; drive-wrapper sections 2 to 6).

A wrapper (Drive in M4, Email in M6) turns typed actions into Google API calls. The pipeline asks
it four things:

- `classify(action, args, policy)`: the Classification of the call (decide.py): the action after
  reclassification (an update that trashes is `drive.delete`), the catalog class and the class
  after escalation, scope, records and recipients. It validates the arguments against the action's
  schema and content-scans what an R1 or R2 call would write, and refuses with BAD_ARGS or
  CONTENT_BLOCKED (`WrapperRefusal`) before anything is stored or shown.
- `target(action, args, policy)`: the state of the target now (its revision, say), for a queued
  call, so that `:apply` can tell that it changed (STALE_TARGET).
- `agent_text(action, args)`: the arguments that are text the agent wrote, for the preview.
- `execute(action, args, policy, run, call_id, snapshot=..., expect_target=...)`: does the call.
  With `snapshot`, it writes the snapshot to control first (drive-wrapper section 4) and refuses
  with SNAPSHOT_FAILED when it cannot. With `expect_target`, it refuses with STALE_TARGET when the
  target is no longer in that state. A refusal (`WrapperRefusal`) means nothing was written. A
  `WrapperFailure` means the outcome is unknown (a write that timed out after reaching Google):
  the call is marked failed and alerted, and never retried (review focus 2).

The pipeline decides whether the wrapper is used at all: the catalog must call it built, and
`wrappers/<name>.enabled_for` in control must hold the agent.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

from aiven.gateway.decide import Classification
from aiven.gateway.types import RunState
from aiven.policy.model import Policy


class WrapperRefusal(Exception):
    """The wrapper refuses the call with a reason code of section 4; nothing was written."""

    def __init__(self, reason: str, *, alert: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.alert = alert


class WrapperFailure(Exception):
    """The call may have reached Google and its outcome is unknown. The message names no content."""


@dataclass(frozen=True)
class Executed:
    """What an executed call gives: its result, its snapshot's path, and the files that taint."""

    result: dict[str, Any] | None = field(repr=False)
    snapshot: str | None = None
    taint_sources: tuple[str, ...] = ()


class Wrapper(Protocol):
    """A wrapper as the pipeline uses it. See the module docstring."""

    name: str

    def classify(self, action: str, args: dict[str, Any], policy: Policy) -> Classification: ...

    def target(self, action: str, args: dict[str, Any], policy: Policy) -> dict[str, Any]: ...

    def agent_text(self, action: str, args: dict[str, Any]) -> dict[str, str]: ...

    def execute(
        self,
        action: str,
        args: dict[str, Any],
        policy: Policy,
        run: RunState,
        call_id: str,
        *,
        snapshot: bool,
        expect_target: dict[str, Any] | None,
    ) -> Executed: ...
