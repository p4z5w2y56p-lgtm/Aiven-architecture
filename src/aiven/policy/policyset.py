"""The checks across policies (validator-spec section 3.9, and the W-WIDENS of section 3.6).

There are two functions, because a caller can have the one without the other (ruling R91):

- `check_duplicates(items)` is about a set of policies, together. `items` are the files, each once,
  as (path, policy) pairs. It needs nothing else, so it runs over the whole set that the caller
  has loaded: every file that gave a policy on a command line, every policy that the gateway
  loaded.
- `check_history(path, policy, previous)` is about one file, against the signed policy that came
  before it for the same agent. It runs per file, and `previous` comes from durable state that the
  caller keeps outside the file: in CI from Git history (`--previous-ref`), at the gateway from what
  it stored for the agent.

`previous=None` means a new agent, and a new agent must be version 1. That is a statement about the
history, so a caller that does not know the history of a file does not call `check_history` for that
file at all: it then has no version order and no widening, and is no new agent either. A caller that
passed `None` for it would be told, wrongly, that every version above 1 starts in the wrong place.

Every finding is about a whole file, because a `Policy` carries no line map (ruling R55). The
findings of `check_duplicates` come in the order of `items`, and the findings of one file by code:

- E-AGENT-DUPLICATE: the file declares an agent that another file declares too. `files` names every
  file of that group, the file itself included.
- E-PRINCIPAL-DUPLICATE: the file has a principal that another file has too. `other` names those
  other files. Two files of one agent usually share the principal as well, and then both codes are
  reported.

The findings of `check_history` are, in this order:

- E-VERSION-ORDER: the version is not the previous version + 1, or not 1 for an agent that has no
  previous version. `value` is the version found and `next` the version that is needed. This is the
  rule of CI; the rule at load is another one (section 3.10).
- W-WIDENS: the file gives the agent more room than the previous version (see `widening`). When
  shadow mode starts again, `restart_runs` is the `min_runs` of this file.

The names are file names (`Path.name`), sorted and joined with `, `.

A file whose hash is the one of the previous version is unchanged. It is that version, so it has
neither E-VERSION-ORDER nor W-WIDENS. `check_duplicates` does not look at hashes, so such a file is
still compared with the other files. A file that differs in any byte is changed, also when its
fields are the same: the signature is over the bytes. The hash decides, and the version is only
judged for the files that changed.
"""

from collections import defaultdict
from pathlib import Path

from aiven.policy.findings import Finding
from aiven.policy.model import Policy
from aiven.policy.widening import widening


def check_duplicates(items: list[tuple[Path, Policy]]) -> list[Finding]:
    """E-AGENT-DUPLICATE and E-PRINCIPAL-DUPLICATE for the files of `items`, taken together."""
    names = [path.name for path, _ in items]
    agents = _groups([policy.agent for _, policy in items])
    principals = _groups([policy.principal for _, policy in items])
    findings: list[Finding] = []
    for number, (path, policy) in enumerate(items):
        where = str(path)
        if len(agents[policy.agent]) > 1:
            params = {"agent": policy.agent, "files": _joined(names, agents[policy.agent])}
            findings.append(Finding("E-AGENT-DUPLICATE", "error", where, params=params))
        others = [other for other in principals[policy.principal] if other != number]
        if others:
            params = {"principal": policy.principal, "other": _joined(names, others)}
            findings.append(Finding("E-PRINCIPAL-DUPLICATE", "error", where, params=params))
    return findings


def check_history(path: Path, policy: Policy, previous: Policy | None) -> list[Finding]:
    """E-VERSION-ORDER and W-WIDENS of one file, against the previous signed policy of its agent.

    `previous` is that policy, which must be of the same agent as `policy`, or None for a new agent:
    then the file must be version 1. Call it only for a file whose history is known (see the module).
    """
    if previous is not None and previous.sha256 == policy.sha256:
        return []
    where = str(path)
    findings = []
    needed = 1 if previous is None else previous.version + 1
    if policy.version != needed:
        params = {"value": str(policy.version), "next": str(needed)}
        findings.append(Finding("E-VERSION-ORDER", "error", where, params=params))
    if previous is not None:
        changes, restart = widening(previous, policy)
        if changes:
            params = {"changes": "; ".join(changes)}
            if restart:
                params["restart_runs"] = str(policy.shadow_min_runs)
            findings.append(Finding("W-WIDENS", "warning", where, params=params))
    return findings


def _groups(keys: list[str]) -> dict[str, list[int]]:
    """For each key, the places in the list where it stands."""
    groups: dict[str, list[int]] = defaultdict(list)
    for number, key in enumerate(keys):
        groups[key].append(number)
    return groups


def _joined(names: list[str], places: list[int]) -> str:
    """The file names at these places, sorted. Two files can have one name, in two folders."""
    return ", ".join(sorted(names[place] for place in places))
