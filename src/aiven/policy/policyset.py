"""The checks across all policies (validator-spec section 3.9, and the W-WIDENS of section 3.6).

`check_set(items, previous)` looks at the files of a set together. `items` are the files, each
once, as (path, policy) pairs. `previous` maps an agent id to the previous signed policy of that
agent: in CI it comes from Git history. Every finding is about a whole file, because a `Policy`
carries no line map (ruling R55). The findings come in the order of `items`, and the findings of
one file by code:

- E-AGENT-DUPLICATE: the file declares an agent that another file declares too. `files` names every
  file of that group, the file itself included.
- E-PRINCIPAL-DUPLICATE: the file has a principal that another file has too. `other` names those
  other files. Two files of one agent usually share the principal as well, and then both codes are
  reported.
- E-VERSION-ORDER: the version is not the previous version + 1, or not 1 for an agent that has no
  previous version. `value` is the version found and `next` the version that is needed. This is the
  rule of CI; the rule at load is another one (section 3.10).
- W-WIDENS: the file gives the agent more room than the previous version (see `widening`). When
  shadow mode starts again, `restart_runs` is the `min_runs` of this file.

The names are file names (`Path.name`), sorted and joined with `, `.

A file whose hash is the one of the previous version is unchanged. It is that version, so it has
neither E-VERSION-ORDER nor W-WIDENS. It is still compared with the other files. A file that
differs in any byte is changed, also when its fields are the same: the signature is over the bytes.
The hash decides, and the version is only judged for the files that changed.
"""

from collections import defaultdict
from pathlib import Path

from aiven.policy.findings import Finding
from aiven.policy.model import Policy
from aiven.policy.widening import widening


def check_set(items: list[tuple[Path, Policy]], previous: dict[str, Policy]) -> list[Finding]:
    """The findings about the files of a set, together and against their previous versions."""
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
        findings += _against_previous(where, policy, previous.get(policy.agent))
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


def _against_previous(where: str, policy: Policy, before: Policy | None) -> list[Finding]:
    """E-VERSION-ORDER and W-WIDENS of a file, against the previous signed policy of its agent."""
    if before is not None and before.sha256 == policy.sha256:
        return []
    findings = []
    needed = 1 if before is None else before.version + 1
    if policy.version != needed:
        params = {"value": str(policy.version), "next": str(needed)}
        findings.append(Finding("E-VERSION-ORDER", "error", where, params=params))
    if before is not None:
        changes, restart = widening(before, policy)
        if changes:
            params = {"changes": "; ".join(changes)}
            if restart:
                params["restart_runs"] = str(policy.shadow_min_runs)
            findings.append(Finding("W-WIDENS", "warning", where, params=params))
    return findings
