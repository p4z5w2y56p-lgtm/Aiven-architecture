"""Taint state of a run (plan Task 3.7; drive-wrapper section 5).

A wrapper says which files of a read are untrusted (its `taint_sources`); `mark_tainted` puts them
on the run, once each. A tainted run stays tainted: under `strict`, its R1 calls queue for a
confirm (decide.py), and its previews list the sources (preview.py).
"""

from aiven.gateway.store import Store


def mark_tainted(store: Store, run_id: str, sources: tuple[str, ...]) -> None:
    """Taint the run with `sources`; nothing happens without a source."""
    if sources:
        store.taint_run(run_id, tuple(sources))
