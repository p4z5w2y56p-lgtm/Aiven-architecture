"""Runs, limits and idempotency (plan Task 3.6; gateway-design sections 4 and 5).

- `amsterdam_day(now)`: the calendar day in Europe/Amsterdam at the moment of the request
  (validator-spec 6, review focus 3). Every day counter uses it.
- `start_run`: reserves a run of the day (`runs_per_day`, LIMIT_RUNS) and makes the run, open until
  its deadline (`max_runtime_s`). The kill switches, the verified policy and the `run_start` audit
  entry are the pipeline's (pipeline.py), around it.
- `end_run`: closes the run with the agent's usage and its reason, and gives the summary of section
  4: calls by outcome, records used, taint, and the cost estimate (pricing.py). A stopped run keeps
  its stop reason.
- `idempotent`: the stored answer of a `request_id`, so an action never executes twice (G-3).

IDs are made here, from a clock and randomness, never from what an agent sends.
"""

import secrets
import time
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Literal, get_args
from zoneinfo import ZoneInfo

from aiven.gateway.pricing import Pricing, Usage
from aiven.gateway.store import Store
from aiven.gateway.types import Refusal, RunState, RunSummary, StoredCall
from aiven.policy.constants import TIMEZONE
from aiven.policy.model import Policy

EndReason = Literal["done", "model_refusal", "max_turns", "error"]
END_REASONS: tuple[str, ...] = get_args(EndReason)

_AMSTERDAM = ZoneInfo(TIMEZONE)


def amsterdam_day(now: datetime) -> str:
    """The date in Europe/Amsterdam at `now`, as YYYY-MM-DD. `now` must carry its zone."""
    if now.tzinfo is None:
        raise ValueError("a time without its zone cannot be placed in a day")
    return now.astimezone(_AMSTERDAM).date().isoformat()


def new_id(prefix: str) -> str:
    """`prefix`, then 12 hex digits of milliseconds and 14 of randomness: sortable and unique."""
    return f"{prefix}{int(time.time() * 1000):012x}{secrets.token_hex(7)}"


def start_run(
    store: Store, p: Policy, catalog_sha256: str, *, shadow: bool, now: datetime
) -> RunState | Refusal:
    """A new open run of `p`'s agent, or LIMIT_RUNS when the day has no run left (G-2)."""
    if not store.reserve_run(p.agent, amsterdam_day(now), p.limits.runs_per_day):
        return Refusal("LIMIT_RUNS")
    run = RunState(
        run_id=new_id("r_"),
        agent=p.agent,
        policy_sha256=p.sha256,
        catalog_sha256=catalog_sha256,
        started_at=now,
        deadline=now + timedelta(seconds=p.limits.max_runtime_s),
        status="open",
        stop_reason=None,
        shadow=shadow,
        tainted=False,
        taint_sources=(),
        records_used=0,
        refusals=0,
    )
    store.create_run(run)
    return run


def end_run(
    store: Store,
    run_id: str,
    usage: list[Usage],
    end_reason: str,
    now: datetime,
    pricing: Pricing | None,
) -> tuple[RunSummary, RunState]:
    """End the run, and give its summary and its final state.

    A run that is still open ends ("ended"); a stopped one stays stopped, with its reason. The
    cost is None without a price list, or when a model has no price (CR-1).
    """
    if end_reason not in END_REASONS:
        raise ValueError(f"end_reason is one of {', '.join(END_REASONS)}")
    run = store.get_run(run_id)
    if run is None:
        raise KeyError("no such run")
    if run.status == "open":
        store.update_run(run_id, status="ended")
        run = replace(run, status="ended")
    cost = None if pricing is None else pricing.estimate(usage)
    summary = RunSummary(
        run_id=run_id,
        calls_by_outcome=store.calls_by_outcome(run_id),
        records_used=run.records_used,
        tainted=run.tainted,
        cost_estimate_eur=cost,
    )
    return summary, run


def idempotent(store: Store, run_id: str, request_id: str) -> StoredCall | None:
    """The stored answer to `request_id` in this run, or None if it was never asked (G-3)."""
    return store.get_call(run_id, request_id)
