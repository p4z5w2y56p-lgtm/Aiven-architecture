"""Shadow mode (plan Task 3.8; gateway-design sections 5 and 6, tests SH-3 and SH-4).

An agent is in shadow mode until its capability is signed off: then its R1 and R2 calls are
proposals, counted and logged but never executed (decide.py). The sign-off (`signoffs/{agent}` in
control, written by the control UI after the shadow review) covers a capability, not a version: a
policy is signed off when its tools are among the signed-off tools and its `max_class` is not
above the signed-off class. A tool added, or a class raised, puts the agent back in shadow mode; a
tool removed does not (SH-3).
"""

from aiven.gateway.control import Signoff
from aiven.gateway.preview import Preview
from aiven.gateway.store import Store
from aiven.gateway.types import RunState, rank
from aiven.policy.model import Policy


def in_shadow(p: Policy, signoff: Signoff | None) -> bool:
    """Whether runs of `p` are shadow runs."""
    if signoff is None:
        return True
    covered = set(p.tools) <= set(signoff.tools)
    return not (covered and rank(p.max_class) <= rank(signoff.max_class))


def record_proposal(store: Store, run: RunState, call_id: str, preview: Preview) -> None:
    """Keep the proposal of a shadow call, for the shadow review."""
    store.put_proposal(
        call_id,
        run.run_id,
        run.agent,
        {"en": preview.en, "nl": preview.nl, "sha256": preview.sha256},
    )


def count_shadow_run(store: Store, p: Policy) -> int:
    """Count one more shadow run of `p`'s agent, with the capability it covered."""
    return store.inc_shadow_runs(p.agent, p.tools, p.max_class)
